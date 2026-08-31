"""
Общие фикстуры тестов.

Все тесты работают на **синтетических** PE-файлах из ``tools/generate_samples.py``
и на временных каталогах (``tmp_path``), поэтому не трогают реальные данные
и не требуют сети.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from generate_samples import build_pe  # noqa: E402  (после настройки sys.path)


@pytest.fixture(scope="session")
def benign_exe(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Один «безопасный» PE-манекен на всю сессию тестов."""
    path = tmp_path_factory.mktemp("pe") / "benign.exe"
    path.write_bytes(build_pe(profile="benign", seed=4242))
    return path


@pytest.fixture(scope="session")
def malicious_exe(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Один «вредоносный» PE-манекен (высокая энтропия, UPX, TLS, оверлей)."""
    path = tmp_path_factory.mktemp("pe") / "malicious.exe"
    path.write_bytes(build_pe(profile="malicious", seed=9999))
    return path


@pytest.fixture(scope="session")
def dataset_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """
    Небольшой размеченный датасет (по 12 образцов на класс).

    Объём подобран так, чтобы полный прогон тестов занимал секунды.
    """
    from generate_samples import write_samples

    root = tmp_path_factory.mktemp("dataset")
    write_samples(root, per_class=12, seed_base=31337, quiet=True)
    return root


@pytest.fixture()
def quarantine_dir(tmp_path: Path) -> Path:
    """Пустой каталог карантина для каждого теста."""
    target = tmp_path / "quarantine"
    target.mkdir()
    return target
