"""Интеграционные тесты конвейера «скан -> вердикт -> карантин»."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aiav.model import MalwareClassifier, Verdict
from aiav.quarantine import QuarantineManager
from aiav.scanner import FileScanner, ScanResult


@pytest.fixture(scope="module")
def classifier(dataset_dir: Path) -> MalwareClassifier:
    model = MalwareClassifier(backend="random_forest")
    model.train_from_directory(dataset_dir)
    return model


@pytest.fixture()
def target_dir(
    tmp_path: Path, benign_exe: Path, malicious_exe: Path
) -> Path:
    """Каталог со смесью: 2 «безопасных», 2 «вредоносных», мусор и битый PE."""
    root = tmp_path / "scan_target"
    root.mkdir()
    (root / "app.exe").write_bytes(benign_exe.read_bytes())
    (root / "helper.dll").write_bytes(benign_exe.read_bytes())
    (root / "loader.exe").write_bytes(malicious_exe.read_bytes())
    (root / "sub").mkdir()
    (root / "sub" / "dropper.exe").write_bytes(malicious_exe.read_bytes())
    (root / "notes.txt").write_text("not an executable")
    (root / "broken.exe").write_bytes(b"\x00" * 128)  # .exe без PE-заголовка
    return root


def test_scan_classifies_and_quarantines(
    classifier: MalwareClassifier, target_dir: Path, quarantine_dir: Path
) -> None:
    """Полный проход: правильные вердикты + изоляция только вредоносных."""
    quarantine = QuarantineManager(quarantine_dir)
    scanner = FileScanner(classifier, quarantine, action="quarantine")
    summary = scanner.scan_paths([target_dir])

    assert summary.scanned == 4                      # 2 benign + 2 malicious
    assert summary.clean == 2
    assert summary.malicious == 2
    assert summary.quarantined == 2
    assert summary.errors == 1                       # broken.exe

    # вредоносные файлы физически перемещены, безопасные — на месте
    assert not (target_dir / "loader.exe").exists()
    assert not (target_dir / "sub" / "dropper.exe").exists()
    assert (target_dir / "app.exe").is_file()
    assert (target_dir / "helper.dll").is_file()
    assert len(quarantine.list_items()) == 2


def test_scan_records_error_for_broken_pe(
    classifier: MalwareClassifier, target_dir: Path, quarantine_dir: Path
) -> None:
    """Битый .exe попадает в отчёт как ошибка, а не теряется молча."""
    scanner = FileScanner(classifier, QuarantineManager(quarantine_dir))
    summary = scanner.scan_paths([target_dir])

    errors = [r for r in summary.results if r.status == "ERROR"]
    assert len(errors) == 1
    assert errors[0].path.endswith("broken.exe")
    assert errors[0].error


def test_dry_run_does_not_touch_files(
    classifier: MalwareClassifier, target_dir: Path, quarantine_dir: Path
) -> None:
    """--dry-run: вердикты есть, файлы не перемещаются."""
    scanner = FileScanner(
        classifier, QuarantineManager(quarantine_dir), action="quarantine", dry_run=True
    )
    summary = scanner.scan_paths([target_dir])

    assert summary.malicious == 2
    assert summary.quarantined == 0
    assert (target_dir / "loader.exe").is_file()
    assert QuarantineManager(quarantine_dir).list_items() == []


def test_report_action_never_moves(
    classifier: MalwareClassifier, target_dir: Path, quarantine_dir: Path
) -> None:
    """Режим 'report' только фиксирует находки."""
    scanner = FileScanner(
        classifier, QuarantineManager(quarantine_dir), action="report"
    )
    summary = scanner.scan_paths([target_dir])
    assert summary.malicious == 2
    assert summary.quarantined == 0
    assert (target_dir / "loader.exe").is_file()


def test_quarantine_requires_manager(classifier: MalwareClassifier) -> None:
    """Нельзя включить карантин, не передав менеджер (защита от опечатки в CLI)."""
    with pytest.raises(ValueError, match="требуется QuarantineManager"):
        FileScanner(classifier, None, action="quarantine", dry_run=False)


def test_thresholds_change_verdicts(
    classifier: MalwareClassifier, target_dir: Path, quarantine_dir: Path
) -> None:
    """Порог 1.01 недостижим -> всё становится SUSPICIOUS/CLEAN, карантина нет."""
    scanner = FileScanner(
        classifier,
        QuarantineManager(quarantine_dir),
        action="quarantine",
        malicious_threshold=1.01,
        suspicious_threshold=0.5,
    )
    summary = scanner.scan_paths([target_dir])
    assert summary.malicious == 0
    assert summary.quarantined == 0
    assert (target_dir / "loader.exe").is_file()


def test_quarantine_directory_is_never_scanned(
    classifier: MalwareClassifier, tmp_path: Path, quarantine_dir: Path
) -> None:
    """Файлы внутри карантина не сканируются повторно (защита от рекурсии)."""
    quarantine = QuarantineManager(quarantine_dir)
    sample = tmp_path / "threat.exe"
    sample.write_bytes(b"MZ" + b"\x90" * 512)
    quarantine.isolate(sample)

    scanner = FileScanner(classifier, quarantine)
    summary = scanner.scan_paths([quarantine_dir])
    assert summary.scanned == 0
    assert summary.results == []


def test_reports_are_written(
    classifier: MalwareClassifier, target_dir: Path, quarantine_dir: Path, tmp_path: Path
) -> None:
    """JSON и CSV отчёты создаются и содержат ожидаемые поля."""
    scanner = FileScanner(classifier, QuarantineManager(quarantine_dir), action="report")
    summary = scanner.scan_paths([target_dir])

    reports_dir = tmp_path / "reports"
    written = FileScanner.save_report(summary, reports_dir, include_features=True)
    assert set(written) == {"json", "csv"}

    payload = json.loads(written["json"].read_text(encoding="utf-8"))
    assert payload["malicious"] == 2
    assert payload["threats_found"] == 2
    ok_results = [r for r in payload["results"] if r["status"] == "OK"]
    assert ok_results, "в отчёте должны быть успешно разобранные файлы"
    assert ok_results[0]["features"]["num_sections"] > 0   # include_features=True
    assert len(ok_results[0]["sha256"]) == 64

    csv_text = written["csv"].read_text(encoding="utf-8")
    assert csv_text.splitlines()[0].startswith("path,status,verdict")


def test_missing_target_logged_not_fatal(
    classifier: MalwareClassifier, tmp_path: Path, quarantine_dir: Path
) -> None:
    """Несуществующий путь — не исключение, а пустая сводка с ошибкой в логе."""
    scanner = FileScanner(classifier, QuarantineManager(quarantine_dir))
    summary = scanner.scan_paths([tmp_path / "nope"])
    assert summary.scanned == 0
    assert summary.results == []


def test_scan_single_file(
    classifier: MalwareClassifier, malicious_exe: Path, quarantine_dir: Path
) -> None:
    """Проверка одного файла возвращает MALICIOUS и SHA-256."""
    scanner = FileScanner(
        classifier, QuarantineManager(quarantine_dir), action="report"
    )
    result: ScanResult = scanner.scan_file(malicious_exe)
    assert result.status == "OK"
    assert result.verdict == Verdict.MALICIOUS.value
    assert len(result.sha256) == 64
    assert result.malware_probability >= 0.8             # порог MALICIOUS


def test_scan_file_error_is_returned_not_raised(
    classifier: MalwareClassifier, tmp_path: Path, quarantine_dir: Path
) -> None:
    missing = tmp_path / "ghost.exe"
    scanner = FileScanner(classifier, QuarantineManager(quarantine_dir))
    result = scanner.scan_file(missing)
    assert result.status == "ERROR"
    assert "не найден" in result.error


def test_report_records_model_path(
    classifier: MalwareClassifier, target_dir: Path, quarantine_dir: Path, tmp_path: Path
) -> None:
    """В отчёте фиксируется, какой именно моделью вынесены вердикты."""
    scanner = FileScanner(
        classifier,
        QuarantineManager(quarantine_dir),
        action="report",
        model_path="/models/test-model.joblib",
    )
    summary = scanner.scan_paths([target_dir])
    written = FileScanner.save_report(summary, tmp_path / "r")
    payload = json.loads(written["json"].read_text(encoding="utf-8"))
    assert payload["model_path"] == "/models/test-model.joblib"
