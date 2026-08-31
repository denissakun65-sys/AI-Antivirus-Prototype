"""
ML-слой прототипа: обучение, сохранение и применение классификатора вредоносности.

Возможности
-----------
* Загрузка датасета из **каталога с PE-файлами** (``malware/`` + ``benign/``)
  или из готового **CSV** (формат EMBER/Kaggle — колонки-признаки + ``label``).
* Обучение конвейера ``StandardScaler -> RandomForest`` (или LightGBM).
* Оценка качества: accuracy, precision, recall, F1, ROC-AUC + confusion matrix.
* Сохранение модели в один ``.joblib``-бандл вместе со схемой признаков,
  порогом и метаданными. При загрузке схема сверяется — это защищает от
  тихой деградации качества, если набор признаков изменили после обучения.

Класс намеренно не привязан к конкретной модели: бэкенд выбирается строкой
(``"random_forest"`` | ``"lightgbm"``), поэтому можно сравнивать алгоритмы
без изменения остального кода.
"""

from __future__ import annotations

import json
import platform
import time
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from aiav import __version__
from aiav.config import DEFAULT_BACKEND, RANDOM_STATE, TEST_SIZE
from aiav.features import (
    FEATURE_NAMES,
    N_FEATURES,
    PEFeatureError,
    extract_pe_features,
    iter_pe_files,
)
from aiav.logging_setup import get_logger

logger = get_logger(__name__)

#: Версия формата бандла модели. Инкрементируется при несовместимых изменениях.
MODEL_FORMAT_VERSION = 1

LABEL_COLUMN = "label"
#: Служебные колонки датасета, которые не являются признаками.
NON_FEATURE_COLUMNS = frozenset({"path", "sha256", "size", LABEL_COLUMN})


class Verdict(str, Enum):
    """Вердикт сканера для одного файла."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"  # модель недоступна / файл не разобрался


@dataclass(slots=True)
class Prediction:
    """Результат предсказания по одному образцу."""

    verdict: Verdict
    malware_probability: float
    benign_probability: float

    @property
    def confidence(self) -> float:
        """Уверенность модели — максимальная из двух вероятностей."""
        return max(self.malware_probability, self.benign_probability)


@dataclass(slots=True)
class Metrics:
    """Метрики качества на отложенной выборке."""

    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    roc_auc: float = 0.0
    cv_f1_mean: float = 0.0
    cv_f1_std: float = 0.0
    confusion: list[list[int]] = field(default_factory=list)
    samples_train: int = 0
    samples_test: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def summary(self) -> str:
        return (
            f"accuracy={self.accuracy:.4f} precision={self.precision:.4f} "
            f"recall={self.recall:.4f} f1={self.f1:.4f} roc_auc={self.roc_auc:.4f} "
            f"(cv_f1={self.cv_f1_mean:.4f}±{self.cv_f1_std:.4f})"
        )


@dataclass(slots=True)
class ModelBundle:
    """Всё, что нужно, чтобы воспроизвести и проверить модель."""

    pipeline: Any
    feature_names: list[str]
    backend: str
    metrics: Metrics
    threshold: float
    trained_at: str
    sklearn_version: str
    package_version: str
    python_version: str
    samples: int
    class_balance: dict[str, int]

    def save(self, path: str | Path) -> Path:
        """Сохраняет бандл в ``.joblib`` (атомарно: сначала во временный файл)."""
        target = Path(path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_suffix(target.suffix + ".tmp")
        payload = {
            "format_version": MODEL_FORMAT_VERSION,
            "pipeline": self.pipeline,
            "feature_names": self.feature_names,
            "backend": self.backend,
            "metrics": asdict(self.metrics),
            "threshold": self.threshold,
            "trained_at": self.trained_at,
            "sklearn_version": self.sklearn_version,
            "package_version": self.package_version,
            "python_version": self.python_version,
            "samples": self.samples,
            "class_balance": self.class_balance,
        }
        try:
            joblib.dump(payload, tmp, compress=3)
            tmp.replace(target)  # атомарная подмена на POSIX и Windows
        except Exception:
            tmp.unlink(missing_ok=True)  # не оставляем мусор при ошибке
            raise
        logger.info("Модель сохранена: %s (%.1f КБ)", target, target.stat().st_size / 1024)
        return target

    @classmethod
    def load(cls, path: str | Path, *, strict_features: bool = True) -> ModelBundle:
        """
        Загружает бандл и проверяет совместимость схемы признаков.

        :param strict_features: при ``True`` несоответствие :data:`FEATURE_NAMES`
            приводит к исключению (иначе — только к предупреждению в лог).
        """
        source = Path(path).expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(
                f"Файл модели не найден: {source}. Обучите модель: python main.py train"
            )
        try:
            payload = joblib.load(source)
        except Exception as exc:
            raise ValueError(f"Не удалось прочитать модель {source}: {exc}") from exc

        version = payload.get("format_version", 0)
        if version != MODEL_FORMAT_VERSION:
            raise ValueError(
                f"Несовместимый формат модели: файл v{version}, "
                f"ожидается v{MODEL_FORMAT_VERSION}. Переобучите модель."
            )

        feature_names = list(payload["feature_names"])
        if feature_names != list(FEATURE_NAMES):
            message = (
                "Схема признаков модели не совпадает с текущей FEATURE_NAMES "
                f"(модель: {len(feature_names)}, код: {N_FEATURES})."
            )
            if strict_features:
                raise ValueError(f"{message} Переобучите модель.")
            logger.warning(message)

        metrics_raw = payload.get("metrics", {})
        return cls(
            pipeline=payload["pipeline"],
            feature_names=feature_names,
            backend=payload.get("backend", "random_forest"),
            metrics=Metrics(**metrics_raw) if metrics_raw else Metrics(),
            threshold=float(payload.get("threshold", 0.8)),
            trained_at=payload.get("trained_at", "unknown"),
            sklearn_version=payload.get("sklearn_version", "unknown"),
            package_version=payload.get("package_version", "unknown"),
            python_version=payload.get("python_version", "unknown"),
            samples=int(payload.get("samples", 0)),
            class_balance=payload.get("class_balance", {}),
        )


# --------------------------------------------------------------------------- #
# Классификатор
# --------------------------------------------------------------------------- #


class MalwareClassifier:
    """
    Обёртка над scikit-learn конвейером классификации «malware / benign».

    Пример::

        clf = MalwareClassifier(backend="random_forest")
        metrics = clf.train_from_directory("data/samples")
        clf.save("models/malware_classifier.joblib")

        clf = MalwareClassifier.load("models/malware_classifier.joblib")
        features = extract_pe_features("sample.exe")
        print(clf.predict_one(features))
    """

    #: Гиперпараметры по умолчанию. Подбирались так, чтобы обучение было
    #: устойчивым и на больших, и на «игрушечных» датасетах (десятки образцов).
    DEFAULT_PARAMS: dict[str, dict[str, object]] = {
        "random_forest": {
            "n_estimators": 300,
            "max_depth": 18,
            "min_samples_split": 4,
            "min_samples_leaf": 2,
            "class_weight": "balanced_subsample",
        },
        "lightgbm": {
            "n_estimators": 200,
            "learning_rate": 0.1,
            "num_leaves": 15,
            "min_child_samples": 2,
            "subsample": 0.9,
            "subsample_freq": 1,
            "colsample_bytree": 0.9,
            "is_unbalance": True,
            "verbose": -1,
        },
    }

    def __init__(
        self,
        backend: str = DEFAULT_BACKEND,
        threshold: float = 0.80,
        random_state: int = RANDOM_STATE,
        n_jobs: int = -1,
        params: dict[str, object] | None = None,
    ) -> None:
        """
        :param backend: ``"random_forest"`` или ``"lightgbm"``.
        :param threshold: порог вероятности для вердикта MALICIOUS.
        :param random_state: для воспроизводимости результатов.
        :param n_jobs: параллелизм обучения (``-1`` — все ядра).
        :param params: переопределение гиперпараметров бэкенда.
        """
        self.backend = backend.lower().strip()
        self.threshold = float(threshold)
        self.random_state = int(random_state)
        self.n_jobs = int(n_jobs)
        self.params: dict[str, object] = dict(params or {})
        self.pipeline: Pipeline | None = None
        self.metrics = Metrics()
        self.trained_at: str = ""
        self.feature_names: list[str] = list(FEATURE_NAMES)
        self.class_balance: dict[str, int] = {}
        logger.debug("MalwareClassifier создан (backend=%s)", self.backend)

    # ------------------------- фабрика моделей ------------------------- #

    def _build_estimator(self) -> Any:
        """
        Создаёт классификатор выбранного бэкенда.

        Базовые гиперпараметры берутся из :data:`DEFAULT_PARAMS`, поверх них
        накладываются значения из ``self.params`` — так можно тюнинговать
        модель, не трогая код.
        """
        canonical = {"rf": "random_forest", "randomforest": "random_forest",
                     "lgbm": "lightgbm", "gbm": "lightgbm"}.get(self.backend, self.backend)
        if canonical not in self.DEFAULT_PARAMS:
            raise ValueError(
                f"Неизвестный бэкенд: {self.backend!r}. Доступны: random_forest, lightgbm."
            )

        options = {**self.DEFAULT_PARAMS[canonical], **self.params}
        options.setdefault("n_jobs", self.n_jobs)
        options.setdefault("random_state", self.random_state)

        if canonical == "random_forest":
            return RandomForestClassifier(**options)

        try:
            from lightgbm import LGBMClassifier
        except ImportError as exc:
            raise ImportError(
                "Бэкенд 'lightgbm' требует пакет lightgbm: pip install lightgbm"
            ) from exc
        return LGBMClassifier(**options)

    def _new_pipeline(self) -> Pipeline:
        """Конвейер: масштабирование признаков -> классификатор."""
        return Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                ("clf", self._build_estimator()),
            ]
        )

    # --------------------------- загрузка данных ------------------------- #

    def load_dataset_from_directory(
        self,
        root: str | Path,
        *,
        malware_dir: str = "malware",
        benign_dir: str = "benign",
        limit_per_class: int | None = None,
    ) -> pd.DataFrame:
        """
        Строит датасет из каталога с образцами::

            root/
              malware/  *.exe  -> label = 1
              benign/   *.exe  -> label = 0

        :param limit_per_class: ограничение числа образцов на класс (для быстрых
            прогонов; ``None`` — использовать всё).
        """
        base = Path(root).expanduser().resolve()
        frames: list[pd.DataFrame] = []

        for sub_dir, label in ((malware_dir, 1), (benign_dir, 0)):
            folder = base / sub_dir
            if not folder.is_dir():
                raise FileNotFoundError(
                    f"Не найден каталог образцов: {folder}. "
                    f"Ожидаемая структура: {base}/{{{malware_dir},{benign_dir}}}"
                )
            rows = self._extract_rows(folder, label=label, limit=limit_per_class)
            if rows:
                frames.append(pd.DataFrame(rows))

        if not frames:
            raise ValueError(f"В {base} не нашлось ни одного пригодного PE-образца")

        dataset = pd.concat(frames, ignore_index=True)
        counts = dataset[LABEL_COLUMN].value_counts().to_dict()
        logger.info(
            "Датасет собран: %d строк | классы: %s",
            len(dataset),
            {int(k): int(v) for k, v in counts.items()},
        )
        return dataset

    @staticmethod
    def _extract_rows(
        folder: Path, label: int, limit: int | None = None
    ) -> list[dict[str, Any]]:
        """Извлекает признаки из всех PE-файлов каталога (битые пропускает)."""
        rows: list[dict[str, Any]] = []
        candidates = list(iter_pe_files(folder))
        if limit:
            candidates = candidates[:limit]
        logger.info("Обрабатываю %d файл(ов) из %s", len(candidates), folder)

        for path in candidates:
            try:
                features = extract_pe_features(path)
                rows.append(features.to_dataset_row(label=label))
            except PEFeatureError as exc:
                logger.warning("Пропущен %s: %s", path.name, exc)
            except Exception as exc:  # noqa: BLE001 — обучение не должно падать на 1 файле
                logger.error("Непредвиденная ошибка на %s: %s", path.name, exc)
        return rows

    @staticmethod
    def load_dataset_from_csv(
        path: str | Path,
        label_column: str = LABEL_COLUMN,
        feature_columns: Sequence[str] | None = None,
    ) -> pd.DataFrame:
        """
        Загружает готовый CSV-датасет (EMBER, Kaggle и т.п.).

        Признаки определяются автоматически: все числовые колонки, имена которых
        есть в :data:`FEATURE_NAMES` (или все колонки из ``feature_columns``).
        """
        csv_path = Path(path).expanduser().resolve()
        if not csv_path.is_file():
            raise FileNotFoundError(f"CSV не найден: {csv_path}")

        dataset = pd.read_csv(csv_path)
        if label_column not in dataset.columns:
            raise ValueError(
                f"В {csv_path.name} нет колонки '{label_column}'. "
                f"Колонки: {list(dataset.columns)[:10]}…"
            )

        if feature_columns:
            missing = [c for c in feature_columns if c not in dataset.columns]
            if missing:
                raise ValueError(f"В датасете отсутствуют признаки: {missing}")
            columns: list[str] = list(feature_columns)
        else:
            columns = [c for c in FEATURE_NAMES if c in dataset.columns]
            if not columns:
                raise ValueError(
                    "В CSV не найдено ни одной колонки из FEATURE_NAMES. "
                    "Передайте feature_columns явно."
                )
            if len(columns) != N_FEATURES:
                logger.warning(
                    "В CSV найдено %d из %d ожидаемых признаков — недостающие "
                    "будут заполнены нулями (качество может снизиться).",
                    len(columns), N_FEATURES,
                )

        dataset = dataset.rename(columns={label_column: LABEL_COLUMN})
        dataset[LABEL_COLUMN] = pd.to_numeric(dataset[LABEL_COLUMN], errors="coerce")
        dataset = dataset.dropna(subset=[LABEL_COLUMN])
        dataset[LABEL_COLUMN] = dataset[LABEL_COLUMN].astype(int)

        for column in columns:
            dataset[column] = pd.to_numeric(dataset[column], errors="coerce").fillna(0.0)
        for column in FEATURE_NAMES:  # дополняем отсутствующие признаки нулями
            if column not in dataset.columns:
                dataset[column] = 0.0

        logger.info("CSV-датасет загружен: %s (%d строк)", csv_path.name, len(dataset))
        return dataset[list(FEATURE_NAMES) + [LABEL_COLUMN]]

    # ----------------------------- обучение ----------------------------- #

    def fit(self, dataset: pd.DataFrame, *, test_size: float = TEST_SIZE) -> Metrics:
        """
        Обучает конвейер и оценивает его на отложенной выборке.

        :param dataset: DataFrame с колонками признаков и ``label``.
        :param test_size: доля отложенной выборки.
        :raises ValueError: если данных недостаточно или только один класс.
        """
        if dataset is None or dataset.empty:
            raise ValueError("Датасет пуст — обучать не на чем")

        x = dataset[list(FEATURE_NAMES)].to_numpy(dtype=np.float64)
        y = dataset[LABEL_COLUMN].to_numpy(dtype=int)

        unique, counts = np.unique(y, return_counts=True)
        if len(unique) < 2:
            raise ValueError(
                f"В датасете только один класс {unique.tolist()} — "
                "нужны образцы обоих классов (0=benign, 1=malware)"
            )
        self.class_balance = {int(cls): int(cnt) for cls, cnt in zip(unique, counts, strict=True)}
        logger.info("Баланс классов: %s", self.class_balance)

        # Stratified split сохраняет пропорции классов в обеих выборках.
        stratify = y if min(counts) >= 2 else None
        x_train, x_test, y_train, y_test = train_test_split(
            x, y, test_size=test_size, random_state=self.random_state, stratify=stratify
        )

        logger.info("Обучение (%s): train=%d test=%d", self.backend, len(x_train), len(x_test))
        started = time.perf_counter()
        self.pipeline = self._new_pipeline()
        self.pipeline.fit(x_train, y_train)
        elapsed = time.perf_counter() - started
        logger.info("Обучение завершено за %.2f c", elapsed)

        self.metrics = self._evaluate(x_train, x_test, y_train, y_test)
        self.trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        logger.info("Метрики: %s", self.metrics.summary())
        return self.metrics

    def _evaluate(
        self,
        x_train: np.ndarray,
        x_test: np.ndarray,
        y_train: np.ndarray,
        y_test: np.ndarray,
    ) -> Metrics:
        """Считает метрики на тестовой выборке + кросс-валидацию по F1."""
        y_pred = self.pipeline.predict(x_test)
        metrics = Metrics(
            accuracy=float(accuracy_score(y_test, y_pred)),
            precision=float(precision_score(y_test, y_pred, zero_division=0)),
            recall=float(recall_score(y_test, y_pred, zero_division=0)),
            f1=float(f1_score(y_test, y_pred, zero_division=0)),
            samples_train=int(len(x_train)),
            samples_test=int(len(x_test)),
            confusion=confusion_matrix(y_test, y_pred, labels=[0, 1]).tolist(),
        )

        try:  # ROC-AUC требует обе вероятности — доступен не для всех бэкендов
            proba = self.pipeline.predict_proba(x_test)[:, 1]
            if len(np.unique(y_test)) > 1:
                metrics.roc_auc = float(roc_auc_score(y_test, proba))
        except Exception as exc:  # noqa: BLE001
            logger.warning("ROC-AUC не вычислен: %s", exc)

        try:  # 3-fold CV: оценка устойчивости, а не «удачного» сплита
            n_splits = int(min(3, min(np.bincount(y_train)[np.bincount(y_train) > 0])))
            if n_splits >= 2:
                cv = cross_val_score(
                    self._new_pipeline(), x_train, y_train, cv=StratifiedKFold(
                        n_splits=n_splits, shuffle=True, random_state=self.random_state
                    ), scoring="f1", n_jobs=1,
                )
                metrics.cv_f1_mean = float(np.mean(cv))
                metrics.cv_f1_std = float(np.std(cv))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Кросс-валидация пропущена: %s", exc)

        logger.debug(
            "Отчёт классификации:\n%s",
            classification_report(y_test, y_pred, target_names=["benign", "malware"],
                                  zero_division=0),
        )
        return metrics

    def train_from_directory(
        self, root: str | Path, *, limit_per_class: int | None = None,
        test_size: float = TEST_SIZE,
    ) -> Metrics:
        """Удобная обёртка: собрать датасет из каталога и обучиться."""
        dataset = self.load_dataset_from_directory(root, limit_per_class=limit_per_class)
        return self.fit(dataset, test_size=test_size)

    # ---------------------------- инференс ----------------------------- #

    def _check_ready(self) -> None:
        if self.pipeline is None:
            raise RuntimeError(
                "Модель не обучена и не загружена. Вызовите fit() или "
                "MalwareClassifier.load(...)."
            )

    def _to_matrix(self, samples: Sequence[Iterable[float]]) -> np.ndarray:
        """Приводит вход к матрице нужной формы и ширины (признаков)."""
        matrix = np.asarray(samples, dtype=np.float64)
        if matrix.ndim == 1:
            matrix = matrix.reshape(1, -1)
        expected = len(self.feature_names)
        if matrix.shape[1] != expected:
            raise ValueError(
                f"Ожидалось {expected} признаков, получено {matrix.shape[1]}. "
                "Скорее всего, модель обучена на другой схеме признаков."
            )
        # NaN/inf ломают StandardScaler — заменяем на 0 и предупреждаем.
        if not np.isfinite(matrix).all():
            logger.warning("В признаках найдены NaN/Inf — заменены на 0.0")
            matrix = np.nan_to_num(matrix, nan=0.0, posinf=0.0, neginf=0.0)
        return matrix

    def predict_proba_matrix(self, samples: Sequence[Iterable[float]]) -> np.ndarray:
        """Вероятности [P(benign), P(malware)] для набора векторов признаков."""
        self._check_ready()
        return self.pipeline.predict_proba(self._to_matrix(samples))

    def predict_many(self, feature_rows: Sequence[Sequence[float]]) -> list[Prediction]:
        """
        Пакетное предсказание (один вызов модели — заметно быстрее пофайлового).

        :param feature_rows: список векторов в порядке :data:`FEATURE_NAMES`.
        """
        if not feature_rows:
            return []
        self._check_ready()
        proba = self.predict_proba_matrix(feature_rows)
        return [self._build_prediction(row) for row in proba]

    def predict_one(self, features) -> Prediction:
        """
        Предсказание для одного :class:`~aiav.features.PEFeatures`
        (или любого объекта с методом ``to_vector()``).
        """
        vector = features.to_vector() if hasattr(features, "to_vector") else features
        return self.predict_many([vector])[0]

    def _build_prediction(self, proba_row: Sequence[float]) -> Prediction:
        """Преобразует вероятности в вердикт с учётом порога."""
        benign_p = float(proba_row[0]) if len(proba_row) > 0 else 0.0
        malware_p = float(proba_row[1]) if len(proba_row) > 1 else 0.0

        if malware_p >= self.threshold:
            verdict = Verdict.MALICIOUS
        elif malware_p >= self.threshold * 0.625:  # «серая зона» -> подозрительный
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN
        return Prediction(
            verdict=verdict,
            malware_probability=round(malware_p, 6),
            benign_probability=round(benign_p, 6),
        )

    # ------------------------ сохранение / загрузка ---------------------- #

    def save(self, path: str | Path) -> Path:
        """Сохраняет обученную модель в ``.joblib``-бандл."""
        self._check_ready()
        if self.pipeline is None:  # для mypy/IDE
            raise RuntimeError("Модель не обучена")

        bundle = ModelBundle(
            pipeline=self.pipeline,
            feature_names=list(self.feature_names),
            backend=self.backend,
            metrics=self.metrics,
            threshold=self.threshold,
            trained_at=self.trained_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            sklearn_version=_safe_import("sklearn", "__version__"),
            package_version=__version__,
            python_version=platform.python_version(),
            samples=int(self.metrics.samples_train + self.metrics.samples_test),
            class_balance={str(k): int(v) for k, v in self.class_balance.items()},
        )
        return bundle.save(path)

    @classmethod
    def load(cls, path: str | Path, *, strict_features: bool = True) -> MalwareClassifier:
        """
        Восстанавливает классификатор из файла.

        :raises FileNotFoundError: файла нет.
        :raises ValueError: несовместимый формат или схема признаков.
        """
        bundle = ModelBundle.load(path, strict_features=strict_features)
        instance = cls(backend=bundle.backend, threshold=bundle.threshold)
        instance.pipeline = bundle.pipeline
        instance.metrics = bundle.metrics
        instance.trained_at = bundle.trained_at
        instance.feature_names = bundle.feature_names
        logger.info(
            "Модель загружена: %s (backend=%s, trained_at=%s, samples=%d, f1=%.4f)",
            Path(path).name, bundle.backend, bundle.trained_at,
            bundle.samples, bundle.metrics.f1,
        )
        return instance

    def describe(self) -> str:
        """Человекочитаемая сводка о модели — удобно для ``main.py model-info``."""
        return json.dumps(
            {
                "backend": self.backend,
                "trained_at": self.trained_at,
                "threshold": self.threshold,
                "features": len(self.feature_names),
                "metrics": self.metrics.as_dict(),
                "sklearn": _safe_import("sklearn", "__version__"),
            },
            ensure_ascii=False,
            indent=2,
        )


def _safe_import(module_name: str, attribute: str, default: str = "unknown") -> str:
    """Достаёт атрибут модуля, не роняя процесс при импорте."""
    try:
        import importlib

        return str(getattr(importlib.import_module(module_name), attribute, default))
    except Exception:  # noqa: BLE001
        return default


__all__ = [
    "MalwareClassifier",
    "ModelBundle",
    "Metrics",
    "Prediction",
    "Verdict",
    "MODEL_FORMAT_VERSION",
    "LABEL_COLUMN",
]
