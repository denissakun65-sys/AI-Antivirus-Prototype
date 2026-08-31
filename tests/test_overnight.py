"""
Тесты автономного обучения (``aiav.overnight``).

Сеть не используется: загрузки подменяются фейковым opener, «EMBER-архив»
собирается на лету из синтетических записей в tmp-каталоге.
"""

from __future__ import annotations

import bz2
import hashlib
import io
import json
import tarfile
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aiav.features import FEATURE_NAMES
from aiav.model import MalwareClassifier, ModelBundle
from aiav.overnight import (
    BenignCollector,
    EmberStream,
    NightSettings,
    NightState,
    NightTrainer,
    _append_rows,
    _entropy_from_histogram,
    compute_deadline,
    download_file,
    ember_record_to_features,
    fmt_hms,
    read_status,
    render_status,
    spawn_status_window,
)

# --------------------------------------------------------------------------- #
# Вспомогательные объекты
# --------------------------------------------------------------------------- #


class FakeResponse:
    """Мини-ответ в стиле urllib: read(), статус, контекст-менеджер."""

    def __init__(self, payload: bytes, status: int = 200) -> None:
        self._buf = io.BytesIO(payload)
        self.status = status

    def read(self, size: int = -1) -> bytes:
        return self._buf.read(size)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False


def make_fake_opener(routes: dict[str, bytes], seen: list):
    """Opener-заглушка: сопоставляет URL с байтами, иначе сетевая ошибка."""

    def opener(request, timeout=None):  # noqa: ARG001
        seen.append(request)
        url = request.full_url
        for suffix, payload in routes.items():
            if url.endswith(suffix):
                return FakeResponse(payload)
        raise urllib.error.URLError(f"нет маршрута для {url}")

    return opener


def ember_record(i: int, label: int) -> dict:
    """Синтетическая запись EMBER (slim-схема 2017/2018), классы разделимы."""
    section_entropy = 7.4 if label else 3.2
    imports = (
        {"KERNEL32.dll": ["VirtualAlloc", "CreateFileW", "ordinal12"]}
        if label
        else {"KERNEL32.dll": ["CreateFileW"]}
    )
    return {
        "label": label,
        "sha256": f"{i:064x}",
        "general": {
            "size": 10_000 + i, "vsize": 20_480, "has_debug": 0, "exports": 0,
            "imports": sum(len(v) for v in imports.values()), "has_relocations": 1,
            "has_resources": 1, "has_signature": 0, "has_tls": label, "symbols": 0,
        },
        "header": {
            "coff": {"timestamp": 1, "machine": "AMD64",
                     "characteristics": ["EXECUTABLE_IMAGE"]},
            "optional": {"subsystem": "WINDOWS_GUI", "dll_characteristics": [],
                         "magic": "PE32+", "sizeof_code": 1024,
                         "sizeof_headers": 1024, "sizeof_heap_commit": 4096},
        },
        "section": {"entry": ".text", "sections": [
            {"name": ".text", "size": 2048, "entropy": section_entropy,
             "vsize": 2000, "props": ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]},
            {"name": ".data", "size": 512, "entropy": section_entropy / 2,
             "vsize": 800, "props": ["MEM_READ", "MEM_WRITE"]},
        ]},
        "imports": imports,
        "histogram": [1] * 256,
        "datadirectories": [
            {"type": "IMPORT", "size": 100, "virtual_address": 4096},
            {"type": "OVERLAY", "size": 777, "virtual_address": 0},
        ],
    }


def make_ember_tar(path: Path, records: list[dict],
                   member: str = "ember2018/train_features_1.jsonl") -> Path:
    """Собирает крошечный .tar.bz2 с одним .jsonl — как настоящий EMBER."""
    payload = ("\n".join(json.dumps(r) for r in records)).encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        info = tarfile.TarInfo(member)
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bz2.compress(raw.getvalue()))
    return path


# --------------------------------------------------------------------------- #
# Энтропия и конвертер EMBER
# --------------------------------------------------------------------------- #


def test_entropy_from_histogram_uniform_is_8() -> None:
    assert _entropy_from_histogram([1] * 256) == pytest.approx(8.0, abs=1e-6)


def test_entropy_from_histogram_empty_is_0() -> None:
    assert _entropy_from_histogram([0] * 256) == 0.0


def test_ember_record_maps_to_46_features() -> None:
    record = ember_record(1, label=1)
    values = ember_record_to_features(record)
    assert values is not None
    assert set(values) == set(FEATURE_NAMES)

    # геометрия и энтропия — из реальных полей записи
    assert values["raw_size"] == 10_001
    assert values["virtual_size"] == 20_480
    assert values["num_sections"] == 2
    assert values["entropy_max_section"] == pytest.approx(7.4)
    assert values["entropy_overall"] == pytest.approx(8.0, abs=1e-6)

    # импорты: VirtualAlloc -> memory_ops, CreateFileW -> file_ops
    assert values["imports_memory_ops"] == 1
    assert values["imports_file_ops"] == 1
    assert values["imports_suspicious_count"] == 2

    # флаги и оверлей из data directories
    assert values["is_64bit"] == 1
    assert values["has_tls_callbacks"] == 1
    assert values["num_tls_callbacks"] == 1  # импутация по has_tls
    assert values["overlay_size"] == 777
    assert values["num_data_directories"] == 2


def test_ember_record_unlabeled_rejected() -> None:
    record = ember_record(2, label=1)
    record["label"] = -1
    assert ember_record_to_features(record) is None


def test_ember_record_int_characteristics_branch() -> None:
    record = ember_record(3, label=0)
    record["header"]["coff"]["characteristics"] = 0x2000 | 0x0002  # DLL | EXECUTABLE
    values = ember_record_to_features(record)
    assert values is not None
    assert values["is_dll"] == 1 and values["is_driver"] == 0


# --------------------------------------------------------------------------- #
# Скачивание файлов
# --------------------------------------------------------------------------- #


def test_download_file_writes_payload(tmp_path: Path) -> None:
    dest = tmp_path / "file.bin"
    download_file("https://example.test/a.bin", dest,
                  opener=make_fake_opener({"/a.bin": b"hello world"}, []))
    assert dest.read_bytes() == b"hello world"


def test_download_file_resumes_with_range(tmp_path: Path) -> None:
    dest = tmp_path / "file.bin"
    dest.write_bytes(b"hello")
    seen: list = []

    def opener_206(request, timeout=None):  # noqa: ARG001
        seen.append(request)
        return FakeResponse(b" world", status=206)  # сервер поддержал Range

    download_file("https://example.test/a.bin", dest, opener=opener_206)
    assert dest.read_bytes() == b"hello world"       # хвост дописан
    assert seen[0].get_header("Range") == "bytes=5-"


def test_download_file_server_ignores_range(tmp_path: Path) -> None:
    """Сервер без Range (ответ 200) — файл перекачивается целиком."""
    dest = tmp_path / "file.bin"
    dest.write_bytes(b"stale")
    download_file("https://example.test/a.bin", dest,
                  opener=make_fake_opener({"/a.bin": b"fresh"}, []))
    assert dest.read_bytes() == b"fresh"


def test_download_file_network_error(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        download_file("https://example.test/missing.bin", tmp_path / "x.bin",
                      opener=make_fake_opener({}, []))


# --------------------------------------------------------------------------- #
# Benign-коллектор
# --------------------------------------------------------------------------- #


def test_benign_collector_extracts_and_dedupes(tmp_path: Path, benign_exe: Path) -> None:
    payload = benign_exe.read_bytes()
    state = NightState(path=tmp_path / "state.json")
    settings = NightSettings(
        downloads_dir=tmp_path / "dl",
        state_path=state.path,
        benign_sources=(("Fake App", "https://example.test/app.exe"),),
        opener=make_fake_opener({"/app.exe": payload}, []),
    )
    collector = BenignCollector(settings, state)

    rows = collector.collect_once()
    assert len(rows) == 1
    values, label, digest, name = rows[0]
    assert label == 0 and name == "Fake App"
    assert digest == hashlib.sha256(payload).hexdigest()
    assert set(values) == set(FEATURE_NAMES)

    # повторный запуск — дедупликация по хешу
    assert collector.collect_once() == []


def test_benign_collector_skips_non_pe(tmp_path: Path) -> None:
    state = NightState(path=tmp_path / "state.json")
    settings = NightSettings(
        downloads_dir=tmp_path / "dl",
        state_path=state.path,
        benign_sources=(("Text", "https://example.test/readme.txt"),),
        opener=make_fake_opener({"/readme.txt": b"just text, not a PE"}, []),
    )
    assert BenignCollector(settings, state).collect_once() == []


# --------------------------------------------------------------------------- #
# Потоковое чтение EMBER
# --------------------------------------------------------------------------- #


def test_ember_stream_iterates_and_resumes(tmp_path: Path) -> None:
    records = [ember_record(i, label=i % 2) for i in range(6)]
    records.append({**ember_record(99, label=1), "label": -1})  # неразмец. -> пропуск
    tar_path = make_ember_tar(tmp_path / "ember.tar.bz2", records)

    state = NightState(path=tmp_path / "state.json")
    settings = NightSettings(ember_tar_path=tar_path, state_path=state.path)
    stream = EmberStream(settings, state)

    got = list(stream.iter_records())
    assert len(got) == 6
    assert {label for _, label, _ in got} == {0, 1}
    assert all(set(values) == set(FEATURE_NAMES) for _, _, values in got)
    assert state.ember_lines["ember2018/train_features_1.jsonl"] == 7  # с -1 строкой

    # повторный запуск с тем же state — всё уже обработано
    assert list(EmberStream(settings, state).iter_records()) == []


# --------------------------------------------------------------------------- #
# Состояние сессии
# --------------------------------------------------------------------------- #


def test_state_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    first = NightState(path=path)
    first.rows_added = 42
    first.epochs = 3
    first.distill_merged = 7
    first.ember_exhausted = True
    first.seen_hashes = {"abc"}
    first.save()

    second = NightState.load(path)
    assert second.rows_added == 42 and second.epochs == 3
    assert second.distill_merged == 7 and second.ember_exhausted
    assert second.seen_hashes == {"abc"}


def test_state_corrupted_file_is_not_fatal(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{oops", encoding="utf-8")
    state = NightState.load(path)
    assert state.rows_added == 0 and state.epochs == 0


# --------------------------------------------------------------------------- #
# Дедлайн и точка входа
# --------------------------------------------------------------------------- #


def test_compute_deadline_none_means_forever() -> None:
    assert compute_deadline(None, None) is None


def test_compute_deadline_hours() -> None:
    deadline = compute_deadline(2.0, None)
    assert deadline is not None
    assert deadline > datetime.now(timezone.utc) + timedelta(hours=1.5)


def test_compute_deadline_until_local_time() -> None:
    deadline = compute_deadline(None, "23:59")
    assert deadline is not None
    local = deadline.astimezone()
    assert (local.hour, local.minute) == (23, 59)


def test_compute_deadline_bad_until() -> None:
    with pytest.raises(ValueError):
        compute_deadline(None, "soon")


# --------------------------------------------------------------------------- #
# Полный цикл тренера: эпохи, слияние distill, защита лучшей модели
# --------------------------------------------------------------------------- #


def _trainer_settings(tmp_path: Path, benign_payload: bytes, **overrides) -> NightSettings:
    records = [ember_record(i, label=i % 2) for i in range(120)]
    tar_path = make_ember_tar(tmp_path / "ember.tar.bz2", records)
    base = {
        "deadline": None,           # бесконечный режим
        "epochs": 2,                # ограничиваем эпохи только в тесте
        "epoch_pause": 0.0,
        "csv_path": tmp_path / "ds.csv",
        "model_path": tmp_path / "model.joblib",
        "retrain_every": 50,
        "max_rows": 0,              # без лимита строк
        "downloads_dir": tmp_path / "dl",
        "state_path": tmp_path / "state.json",
        "ember_tar_path": tar_path,
        "distill_path": tmp_path / "distill.csv",
        "status_path": tmp_path / "status.json",
        "retry_backoff": 0.01,
        "benign_sources": (("Fake App", "https://example.test/app.exe"),),
        "opener": make_fake_opener({"/app.exe": benign_payload}, []),
    }
    base.update(overrides)
    return NightSettings(**base)


def test_trainer_two_epochs_end_to_end(tmp_path: Path, benign_exe: Path) -> None:
    settings = _trainer_settings(tmp_path, benign_exe.read_bytes())

    # Две строки от «scan --learn» — должны влиться в ночной CSV.
    values = dict.fromkeys(FEATURE_NAMES, 0.5)
    _append_rows(settings.distill_path, [
        (values, 1, "d1" * 32, "distill-mal"),
        (values, 0, "d2" * 32, "distill-clean"),
    ])

    trainer = NightTrainer(settings)
    assert trainer.run() == 0
    state = NightState.load(settings.state_path)

    assert state.epochs == 2
    assert state.rows_added == 120 + 1 + 2   # EMBER + benign + distill
    assert state.distill_merged == 2
    assert state.ember_exhausted is True
    assert state.retrains >= 2               # минимум по разу на эпоху

    # модель обучена и пригодна к загрузке
    bundle = ModelBundle.load(settings.model_path)
    assert bundle.metrics.cv_f1_mean > 0.5

    # CSV пригоден для ручного train --csv
    clf = MalwareClassifier()
    dataset = clf.load_dataset_from_csv(settings.csv_path)
    assert len(dataset) == 123

    # второй запуск: benign не перекачивается, EMBER не перечитывается
    before = state.rows_added
    trainer2 = NightTrainer(_trainer_settings(tmp_path, benign_exe.read_bytes(),
                                              epochs=3))
    assert trainer2.run() == 0
    after = NightState.load(settings.state_path)
    assert after.rows_added == before        # новых данных нет
    assert after.epochs == 3


def test_trainer_never_degrades_existing_model(tmp_path: Path, benign_exe: Path) -> None:
    """Если текущая модель лучше — она НЕ перезаписывается."""
    settings = _trainer_settings(tmp_path, benign_exe.read_bytes(), epochs=1)

    # «сильная» текущая модель с завышенным CV-F1
    strong = MalwareClassifier()
    _append_rows(settings.csv_path, [
        ({n: float(i % 7) for n in FEATURE_NAMES}, i % 2, f"s{i:062d}", "strong")
        for i in range(40)
    ])
    strong.fit(strong.load_dataset_from_csv(settings.csv_path))
    strong.metrics.cv_f1_mean = 0.9999
    strong.save(settings.model_path)
    digest_before = hashlib.sha256(settings.model_path.read_bytes()).hexdigest()

    # шумовой датасет: метки случайны — CV-F1 заведомо хуже 0.9999
    noise_csv = tmp_path / "noise.csv"
    _append_rows(noise_csv, [
        ({n: float((i * 7 + j) % 13) for n, j in zip(FEATURE_NAMES, range(46), strict=True)},
         (i * 31) % 2, f"n{i:062d}", "noise")
        for i in range(60)
    ])
    settings_noisy = _trainer_settings(tmp_path, benign_exe.read_bytes(),
                                       epochs=1, csv_path=noise_csv,
                                       model_path=settings.model_path,
                                       use_ember=False, benign_sources=())
    NightTrainer(settings_noisy).run()

    digest_after = hashlib.sha256(settings.model_path.read_bytes()).hexdigest()
    assert digest_after == digest_before     # лучшая модель уцелела


def test_trainer_respects_past_deadline(tmp_path: Path, benign_exe: Path) -> None:
    settings = _trainer_settings(
        tmp_path, benign_exe.read_bytes(),
        deadline=datetime.now(timezone.utc) - timedelta(hours=1),
        epochs=None,  # эпохи не ограничены, но дедлайн уже прошёл
    )
    trainer = NightTrainer(settings)
    assert trainer.run() == 0
    state = NightState.load(settings.state_path)
    assert state.epochs == 0
    assert not settings.model_path.exists()


# --------------------------------------------------------------------------- #
# Живой статус, бэкофф и локальный EMBER-архив
# --------------------------------------------------------------------------- #


def test_status_file_written_by_trainer(tmp_path: Path, benign_exe: Path) -> None:
    settings = _trainer_settings(tmp_path, benign_exe.read_bytes(), epochs=1)
    NightTrainer(settings).run()

    status = read_status(settings.status_path)
    assert status is not None
    assert status["running"] is False          # сессия завершилась
    assert status["epochs"] >= 1
    assert status["rows_added"] >= 121
    assert status["phase"] == "остановлено"
    assert status["elapsed_sec"] >= 0


def test_render_status_board() -> None:
    board = render_status({
        "running": True, "elapsed_sec": 3725, "epochs": 42,
        "rows_added": 1234, "retrains": 3, "phase": "EMBER: сбор",
        "cv_f1": 0.9812, "updated_at": datetime.now(timezone.utc).isoformat(),
    })
    assert "01:02:05" in board          # 3725 c -> ЧЧ:ММ:СС
    assert "Эпох пройдено  : 42" in board
    assert "РАБОТАЕТ" in board
    assert "0.9812" in board


def test_fmt_hms() -> None:
    assert fmt_hms(0) == "00:00:00"
    assert fmt_hms(59) == "00:00:59"
    assert fmt_hms(3600) == "01:00:00"
    assert fmt_hms(-5) == "00:00:00"    # защита от отрицательных


def test_read_status_missing_returns_none(tmp_path: Path) -> None:
    assert read_status(tmp_path / "nope.json") is None


def test_backoff_and_ember_autodisable(tmp_path: Path, benign_exe: Path) -> None:
    """EMBER недоступен: бэкофф + автоотключение вместо бесконечных ошибок."""
    seen: list = []

    def failing_opener(request, timeout=None):  # noqa: ARG001
        seen.append(request.full_url)
        if request.full_url.endswith(".tar.bz2"):
            raise urllib.error.HTTPError(
                request.full_url, 403, "Forbidden", {}, None)
        return FakeResponse(benign_exe.read_bytes())

    settings = _trainer_settings(
        tmp_path, benign_exe.read_bytes(),
        epochs=4, epoch_pause=0.0,
        ember_tar_path=tmp_path / "absent" / "ember.tar.bz2",
        ember_fail_limit=2,
        opener=failing_opener,
    )
    trainer = NightTrainer(settings)
    assert trainer.run() == 0

    ember_attempts = [u for u in seen if u.endswith(".tar.bz2")]
    assert len(ember_attempts) == 2      # после 2 ошибок подряд — отключён
    assert trainer._ember_disabled is True  # noqa: SLF001
    state = NightState.load(settings.state_path)
    assert state.epochs == 4             # сессия дошла до конца без EMBER


def test_ember_stream_accepts_local_archive(tmp_path: Path) -> None:
    """--ember-url может быть путём к вручную скачанному файлу."""
    records = [ember_record(i, label=i % 2) for i in range(4)]
    local_tar = make_ember_tar(tmp_path / "manual" / "ember.tar.bz2", records)

    state = NightState(path=tmp_path / "state.json")
    settings = NightSettings(
        ember_url=str(local_tar),
        ember_tar_path=tmp_path / "downloads" / "ember.tar.bz2",  # отсутствует
        state_path=state.path,
        opener=make_fake_opener({}, []),  # сеть дёргаться не должна
    )
    got = list(EmberStream(settings, state).iter_records())
    assert len(got) == 4


def test_spawn_status_window_non_windows(tmp_path: Path) -> None:
    import sys

    if sys.platform == "win32":
        pytest.skip("проверяется отказ только на не-Windows")
    assert spawn_status_window(tmp_path / "status.json") is False
