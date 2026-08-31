"""Тесты фонового мониторинга (``aiav.monitor``) — без реального watchdog."""

from __future__ import annotations

from pathlib import Path

import pytest

from aiav.model import MalwareClassifier, Verdict
from aiav.monitor import MonitorPipeline
from aiav.quarantine import QuarantineManager
from aiav.scanner import FileScanner


@pytest.fixture(scope="module")
def scanner(dataset_dir: Path) -> FileScanner:
    classifier = MalwareClassifier(backend="random_forest")
    classifier.train_from_directory(dataset_dir)
    return FileScanner(classifier, None, action="report")


def test_non_pe_is_ignored(scanner: FileScanner, tmp_path: Path) -> None:
    pipeline = MonitorPipeline(scanner)
    text = tmp_path / "readme.txt"
    text.write_text("just notes", encoding="utf-8")
    assert pipeline.process(text) is None


def test_missing_file_returns_none(scanner: FileScanner, tmp_path: Path) -> None:
    pipeline = MonitorPipeline(scanner)
    assert pipeline.process(tmp_path / "ghost.exe") is None


def test_malicious_file_is_flagged(
    scanner: FileScanner, tmp_path: Path, malicious_exe: Path
) -> None:
    pipeline = MonitorPipeline(scanner)
    dropped = tmp_path / "dropped.exe"
    dropped.write_bytes(malicious_exe.read_bytes())

    result = pipeline.process(dropped)
    assert result is not None
    assert result.verdict == Verdict.MALICIOUS.value


def test_benign_file_is_clean(
    scanner: FileScanner, tmp_path: Path, benign_exe: Path
) -> None:
    pipeline = MonitorPipeline(scanner)
    dropped = tmp_path / "app.exe"
    dropped.write_bytes(benign_exe.read_bytes())

    result = pipeline.process(dropped)
    assert result is not None
    assert result.verdict == Verdict.CLEAN.value


def test_monitor_quarantines_in_quarantine_mode(
    dataset_dir: Path, tmp_path: Path, malicious_exe: Path
) -> None:
    """Полная связка: monitor-конвейер + карантин изолирует «дроп»."""
    classifier = MalwareClassifier(backend="random_forest")
    classifier.train_from_directory(dataset_dir)
    quarantine = QuarantineManager(tmp_path / "q")
    scanner = FileScanner(classifier, quarantine, action="quarantine")

    dropped = tmp_path / "incoming.exe"
    dropped.write_bytes(malicious_exe.read_bytes())

    result = MonitorPipeline(scanner).process(dropped)
    assert result is not None and result.quarantined is True
    assert not dropped.exists()
    assert len(quarantine.list_items()) == 1
