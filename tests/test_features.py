"""Тесты модуля извлечения признаков (``aiav.features``)."""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from aiav.features import (
    FEATURE_NAMES,
    N_FEATURES,
    PEFeatureError,
    extract_pe_features,
    file_entropy,
    has_pe_extension,
    is_pe_candidate,
    is_pe_file,
    iter_pe_files,
    shannon_entropy,
)


def test_feature_names_are_unique_and_typed() -> None:
    """Схема признаков — контракт с моделью: имена не должны дублироваться."""
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))
    assert N_FEATURES == len(FEATURE_NAMES) > 30


def test_vector_length_matches_schema(benign_exe: Path) -> None:
    """Длина вектора обязана совпадать с FEATURE_NAMES — иначе модель «поедет»."""
    features = extract_pe_features(benign_exe)
    vector = features.to_vector()
    assert len(vector) == N_FEATURES
    assert all(isinstance(value, float) for value in vector)
    assert all(math.isfinite(value) for value in vector)


def test_benign_profile_markers(benign_exe: Path) -> None:
    """«Безопасный» манекен: низкая энтропия, обычные импорты, есть ресурсы."""
    values = extract_pe_features(benign_exe).values
    assert values["num_sections"] == 4
    assert values["entropy_max_section"] < 5.0
    assert values["imports_process_injection"] == 0
    assert values["imports_network_ops"] == 0
    assert values["is_upx_packed"] == 0
    assert values["num_resources"] == 1
    assert values["has_tls_callbacks"] == 0


def test_malicious_profile_markers(malicious_exe: Path) -> None:
    """«Вредоносный» манекен: упаковщик, инъекции, сеть, TLS, оверлей."""
    values = extract_pe_features(malicious_exe).values
    assert values["entropy_max_section"] > 7.0
    assert values["is_upx_packed"] == 1
    assert values["imports_process_injection"] > 0
    assert values["imports_network_ops"] > 0
    assert values["imports_crypto_ops"] > 0
    assert values["num_tls_callbacks"] == 2
    assert values["overlay_size"] > 0
    assert values["max_section_virtual_raw_gap"] > 0


def test_sha256_is_consistent(benign_exe: Path) -> None:
    """Хеш должен совпадать с независимым подсчётом (sha256sum)."""
    import hashlib

    expected = hashlib.sha256(benign_exe.read_bytes()).hexdigest()
    assert extract_pe_features(benign_exe).sha256 == expected


def test_entropy_of_uniform_data_is_zero() -> None:
    assert shannon_entropy(b"\x00" * 1024) == 0.0
    assert shannon_entropy(b"") == 0.0


def test_entropy_of_random_data_is_high() -> None:
    """Энтропия 256 различных значений стремится к 8 битам."""
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0, abs=1e-6)


def test_file_entropy_matches_full_read(benign_exe: Path) -> None:
    """Потоковая энтропия файла равна энтропии прочитанного целиком."""
    assert file_entropy(benign_exe) == pytest.approx(
        shannon_entropy(benign_exe.read_bytes()), abs=1e-6
    )


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(PEFeatureError, match="не найден"):
        extract_pe_features(tmp_path / "nope.exe")


def test_non_pe_file_raises(tmp_path: Path) -> None:
    """Файл без PE-заголовка — ошибка разбора, а не падение процесса."""
    fake = tmp_path / "fake.exe"
    fake.write_bytes(b"just some text, not a PE at all")
    with pytest.raises(PEFeatureError):
        extract_pe_features(fake)


def test_empty_file_raises(tmp_path: Path) -> None:
    empty = tmp_path / "empty.exe"
    empty.write_bytes(b"")
    with pytest.raises(PEFeatureError, match="пуст"):
        extract_pe_features(empty)


def test_is_pe_file_and_candidate(tmp_path: Path, benign_exe: Path) -> None:
    """Сигнатура и расширение проверяются независимо (маскировка расширения)."""
    text = tmp_path / "notes.txt"
    text.write_text("hello")
    masked = tmp_path / "payload.bin"
    masked.write_bytes(benign_exe.read_bytes())
    broken = tmp_path / "broken.exe"
    broken.write_bytes(b"\x00" * 64)

    assert is_pe_file(benign_exe) is True
    assert is_pe_file(text) is False
    assert is_pe_file(masked) is True          # сигнатура MZ под «чужим» расширением
    assert has_pe_extension(broken) is True
    assert is_pe_file(broken) is False
    assert is_pe_candidate(broken) is True     # попадёт в разбор и даст ошибку
    assert is_pe_candidate(text) is False


def test_iter_pe_files_finds_candidates(tmp_path: Path, benign_exe: Path) -> None:
    """Обход каталога: находит PE, пропускает мусор и симлинки."""
    nested = tmp_path / "sub"
    nested.mkdir()
    (nested / "app.exe").write_bytes(benign_exe.read_bytes())
    (tmp_path / "readme.md").write_text("docs")

    found = {p.name for p in iter_pe_files(tmp_path)}
    assert found == {"app.exe"}

    link = tmp_path / "link.exe"
    try:
        link.symlink_to(nested / "app.exe")
    except OSError:  # платформа без симлинков — не блокируем тесты
        return
    assert {p.name for p in iter_pe_files(tmp_path)} == {"app.exe"}  # симлинк пропущен


def test_iter_pe_files_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        list(iter_pe_files(tmp_path / "does-not-exist"))


# --------------------------------------------------------------------------- #
# Регрессия: PE32+ (x64). Ранее 8-байтовые указатели в таблице импортов и TLS
# записывались как 4-байтовые, из-за чего у x64-образцов молча обнулялись
# num_imports_dll и num_tls_callbacks — модель обучалась на мусорных признаках.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("machine, expect_64", [(0x14C, 0.0), (0x8664, 1.0)])
def test_both_architectures_expose_same_structural_features(
    tmp_path: Path, machine: int, expect_64: float
) -> None:
    from generate_samples import build_pe

    path = tmp_path / f"sample_{machine:x}.exe"
    path.write_bytes(build_pe(profile="malicious", seed=2024, machine=machine))
    values = extract_pe_features(path).values

    assert values["is_64bit"] == expect_64
    assert values["num_imports_dll"] == 6, "таблица импортов не разобралась"
    assert values["num_imports_funcs"] == 59
    assert values["num_tls_callbacks"] == 2, "TLS-callback'и не найдены"
    assert values["imports_process_injection"] > 0
    assert values["imports_network_ops"] > 0
    assert values["num_resources"] == 1
    assert values["is_upx_packed"] == 1
