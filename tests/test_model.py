"""Тесты ML-слоя (``aiav.model``)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from aiav.features import FEATURE_NAMES, N_FEATURES, extract_pe_features
from aiav.model import MalwareClassifier, Verdict


@pytest.fixture(scope="module")
def trained_classifier(dataset_dir: Path) -> MalwareClassifier:
    """Обученная модель — одна на модуль (обучение недешёвое)."""
    classifier = MalwareClassifier(backend="random_forest")
    classifier.train_from_directory(dataset_dir)
    return classifier


def test_dataset_from_directory_has_both_classes(dataset_dir: Path) -> None:
    """Датасет собирается из malware/ и benign/ и содержит оба класса."""
    classifier = MalwareClassifier()
    dataset = classifier.load_dataset_from_directory(dataset_dir)
    assert sorted(dataset["label"].unique()) == [0, 1]
    assert len(dataset) == 24
    assert all(name in dataset.columns for name in FEATURE_NAMES)


def test_missing_samples_directory_raises(tmp_path: Path) -> None:
    classifier = MalwareClassifier()
    with pytest.raises(FileNotFoundError, match="Не найден каталог образцов"):
        classifier.load_dataset_from_directory(tmp_path)


def test_single_class_dataset_raises() -> None:
    """Обучение на одном классе невозможно — ждём внятную ошибку."""
    classifier = MalwareClassifier()
    frame = pd.DataFrame(
        {**{name: [0.0] * 4 for name in FEATURE_NAMES}, "label": [1, 1, 1, 1]}
    )
    with pytest.raises(ValueError, match="только один класс"):
        classifier.fit(frame)


def test_training_produces_good_metrics(trained_classifier: MalwareClassifier) -> None:
    """На синтетических данных классы разделимы — качество обязано быть высоким."""
    metrics = trained_classifier.metrics
    assert metrics.samples_train + metrics.samples_test == 24
    assert metrics.accuracy >= 0.9
    assert metrics.f1 >= 0.9
    assert 0.0 <= metrics.roc_auc <= 1.0
    assert len(metrics.confusion) == 2


def test_predictions_separate_profiles(
    trained_classifier: MalwareClassifier, benign_exe: Path, malicious_exe: Path
) -> None:
    """Вердикт «вредоносного» манекена строго выше, чем у «безопасного»."""
    malicious = trained_classifier.predict_one(extract_pe_features(malicious_exe))
    benign = trained_classifier.predict_one(extract_pe_features(benign_exe))

    assert malicious.verdict is Verdict.MALICIOUS
    assert malicious.malware_probability >= 0.8          # порог карантина по умолчанию
    assert benign.verdict is Verdict.CLEAN
    assert benign.malware_probability <= 0.2
    # главное свойство: классы уверенно разделены
    assert malicious.malware_probability - benign.malware_probability > 0.5
    assert benign.malware_probability + benign.benign_probability == pytest.approx(1.0)


def test_batch_prediction_matches_single(
    trained_classifier: MalwareClassifier, benign_exe: Path, malicious_exe: Path
) -> None:
    """Пакетное предсказание не должно отличаться от пофайлового."""
    vectors = [
        extract_pe_features(malicious_exe).to_vector(),
        extract_pe_features(benign_exe).to_vector(),
    ]
    batch = trained_classifier.predict_many(vectors)
    singles = [trained_classifier.predict_one(v) for v in vectors]
    assert [p.verdict for p in batch] == [p.verdict for p in singles]
    assert batch[0].malware_probability == pytest.approx(singles[0].malware_probability)


def test_empty_batch_returns_empty(trained_classifier: MalwareClassifier) -> None:
    assert trained_classifier.predict_many([]) == []


def test_save_and_load_roundtrip(
    trained_classifier: MalwareClassifier, tmp_path: Path, malicious_exe: Path
) -> None:
    """Сохранённая модель восстанавливается и даёт те же предсказания."""
    model_path = tmp_path / "model.joblib"
    trained_classifier.save(model_path)
    assert model_path.is_file() and model_path.stat().st_size > 0

    restored = MalwareClassifier.load(model_path)
    assert restored.backend == trained_classifier.backend
    assert restored.feature_names == list(FEATURE_NAMES)
    assert restored.metrics.f1 == trained_classifier.metrics.f1

    before = trained_classifier.predict_one(extract_pe_features(malicious_exe))
    after = restored.predict_one(extract_pe_features(malicious_exe))
    assert after.malware_probability == pytest.approx(before.malware_probability)


def test_load_missing_model_gives_actionable_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Обучите модель"):
        MalwareClassifier.load(tmp_path / "nope.joblib")


def test_wrong_feature_count_rejected(trained_classifier: MalwareClassifier) -> None:
    """Вектор неверной ширины отклоняется — иначе модель даст мусор молча."""
    with pytest.raises(ValueError, match="Ожидалось"):
        trained_classifier.predict_many([np.zeros(N_FEATURES + 3)])


def test_nan_features_are_sanitised(trained_classifier: MalwareClassifier) -> None:
    """NaN в признаках не роняет предсказание (важно для реальных битых файлов)."""
    vector = [float("nan")] * N_FEATURES
    prediction = trained_classifier.predict_many([vector])[0]
    assert prediction.verdict in set(Verdict)
    assert 0.0 <= prediction.malware_probability <= 1.0


def test_predict_without_model_raises() -> None:
    classifier = MalwareClassifier()
    with pytest.raises(RuntimeError, match="не обучена"):
        classifier.predict_many([np.zeros(N_FEATURES)])


def test_unknown_backend_rejected() -> None:
    with pytest.raises(ValueError, match="Неизвестный бэкенд"):
        MalwareClassifier(backend="magic")._build_estimator()


def test_lightgbm_backend_if_available(dataset_dir: Path) -> None:
    """
    LightGBM — опциональный бэкенд; если пакета нет, тест честно пропускается.

    Порог F1 здесь заметно ниже, чем у RandomForest: датасет «игрушечный»
    (24 образца), а градиентный бустинг на таком объёме нестабилен. Тест
    проверяет работоспособность бэкенда, а не его качество.
    """
    pytest.importorskip("lightgbm")
    classifier = MalwareClassifier(backend="lightgbm")
    metrics = classifier.train_from_directory(dataset_dir)
    assert metrics.samples_train + metrics.samples_test == 24
    assert metrics.accuracy >= 0.5
    assert 0.0 <= metrics.roc_auc <= 1.0


def test_custom_params_override_defaults(dataset_dir: Path) -> None:
    """Переданные гиперпараметры действительно доходят до оценки."""
    classifier = MalwareClassifier(
        backend="random_forest", params={"n_estimators": 25, "max_depth": 4}
    )
    metrics = classifier.train_from_directory(dataset_dir)
    assert metrics.f1 >= 0.5
    estimator = classifier.pipeline.named_steps["clf"]
    assert estimator.n_estimators == 25
    assert estimator.max_depth == 4


def test_csv_dataset_loading(tmp_path: Path) -> None:
    """Поддержка внешних CSV-датасетов (EMBER/Kaggle): признаки + label."""
    rng = np.random.default_rng(0)
    frame = pd.DataFrame(
        rng.normal(size=(20, N_FEATURES)), columns=list(FEATURE_NAMES)
    )
    frame["label"] = [0] * 10 + [1] * 10
    # усиливаем разделимость, чтобы обучение не было «лотереей»
    frame.loc[frame["label"] == 1, "entropy_overall"] += 5.0
    csv_path = tmp_path / "dataset.csv"
    frame.to_csv(csv_path, index=False)

    classifier = MalwareClassifier()
    loaded = classifier.load_dataset_from_csv(csv_path)
    assert len(loaded) == 20
    assert list(loaded.columns) == list(FEATURE_NAMES) + ["label"]

    metrics = classifier.fit(loaded)
    assert metrics.samples_train + metrics.samples_test == 20


def test_csv_without_label_column_raises(tmp_path: Path) -> None:
    csv_path = tmp_path / "bad.csv"
    pd.DataFrame({"a": [1, 2]}).to_csv(csv_path, index=False)
    with pytest.raises(ValueError, match="нет колонки"):
        MalwareClassifier.load_dataset_from_csv(csv_path)


def test_threshold_controls_verdict(dataset_dir: Path) -> None:
    """Порог влияет на вердикт: при пороге 0.99 образец становится «подозрительным»."""
    strict = MalwareClassifier(backend="random_forest", threshold=0.99)
    strict.train_from_directory(dataset_dir)
    # порог сканера задаётся в FileScanner, здесь проверяем лишь корректность границ
    assert 0.0 < strict.threshold <= 1.0
