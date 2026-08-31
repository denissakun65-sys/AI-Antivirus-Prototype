"""Тесты карантина (``aiav.quarantine``)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aiav.features import sha256_of
from aiav.quarantine import (
    EncryptionMode,
    QuarantineError,
    QuarantineManager,
    sha256_of_bytes,
)


def _payload(tmp_path: Path, name: str = "threat.exe", content: bytes | None = None) -> Path:
    """Создаёт файл-жертву для изоляции."""
    path = tmp_path / name
    path.write_bytes(content or b"MZ" + os.urandom(2048))
    return path


def test_isolate_moves_and_encrypts(tmp_path: Path, quarantine_dir: Path) -> None:
    """Файл исчезает из исходного каталога и появляется в карантине."""
    source = _payload(tmp_path)
    original_hash = sha256_of(source)

    manager = QuarantineManager(quarantine_dir)
    item = manager.isolate(source, verdict="MALICIOUS", probability=0.97, model="rf@test")

    assert not source.exists()
    assert item.sha256 == original_hash
    assert item.encryption == EncryptionMode.AES256.value

    payload_path = quarantine_dir / item.payload_file
    assert payload_path.is_file()
    # содержимое зашифровано: байты не совпадают с оригиналом
    assert payload_path.read_bytes() != (b"MZ" + b"\x00" * 2048)
    assert payload_path.read_bytes()[:4] == b"AIAV"


def test_isolate_creates_metadata(tmp_path: Path, quarantine_dir: Path) -> None:
    """Карточка объекта содержит всё необходимое для восстановления."""
    source = _payload(tmp_path)
    manager = QuarantineManager(quarantine_dir)
    item = manager.isolate(source, verdict="MALICIOUS", probability=0.91, reason="test")

    meta_files = list(quarantine_dir.glob("*.json"))
    assert len(meta_files) == 1
    restored = manager.list_items()
    assert len(restored) == 1
    assert restored[0].original_path == str(source)
    assert restored[0].probability == pytest.approx(0.91)
    assert restored[0].item_id == item.item_id


def test_restore_roundtrip_preserves_bytes(tmp_path: Path, quarantine_dir: Path) -> None:
    """Восстановление возвращает побайтово идентичный файл (AES-GCM + SHA-256)."""
    content = b"MZ" + bytes(range(256)) * 8
    source = _payload(tmp_path, content=content)

    manager = QuarantineManager(quarantine_dir)
    item = manager.isolate(source)
    destination = manager.restore(item.item_id)

    assert destination == source
    assert destination.read_bytes() == content
    assert sha256_of(destination) == sha256_of_bytes(content)
    assert manager.list_items() == []  # запись удалена после восстановления


def test_restore_to_custom_target(tmp_path: Path, quarantine_dir: Path) -> None:
    """Можно восстановить в другой каталог (разбор инцидента в песочнице)."""
    source = _payload(tmp_path)
    manager = QuarantineManager(quarantine_dir)
    item = manager.isolate(source)

    sandbox = tmp_path / "sandbox"
    destination = manager.restore(item.item_id, target=sandbox / "sample.bin")
    assert destination.parent == sandbox
    assert destination.is_file()


def test_restore_refuses_overwrite(tmp_path: Path, quarantine_dir: Path) -> None:
    """Без force=True существующий файл не перезаписывается."""
    source = _payload(tmp_path)
    manager = QuarantineManager(quarantine_dir)
    item = manager.isolate(source)

    source.write_bytes(b"important data")
    with pytest.raises(QuarantineError, match="уже есть файл"):
        manager.restore(item.item_id)

    # с force — перезапись разрешена
    manager.restore(item.item_id, force=True)
    assert source.read_bytes() != b"important data"


def test_tampered_payload_detected(tmp_path: Path, quarantine_dir: Path) -> None:
    """Подмена объекта в карантине обнаруживается по нарушению целостности."""
    source = _payload(tmp_path)
    manager = QuarantineManager(quarantine_dir)
    item = manager.isolate(source)

    payload_path = quarantine_dir / item.payload_file
    os.chmod(payload_path, 0o600)
    payload_path.write_bytes(b"AIAV" + os.urandom(512))

    with pytest.raises(QuarantineError):
        manager.extract_payload(item.item_id)


def test_cannot_quarantine_file_already_inside(quarantine_dir: Path) -> None:
    """Защита от самоизоляции и рекурсивного сканирования карантина."""
    manager = QuarantineManager(quarantine_dir)
    inside = quarantine_dir / "already.exe"
    inside.write_bytes(b"MZ" + b"\x00" * 64)

    with pytest.raises(QuarantineError, match="уже находится в карантине"):
        manager.isolate(inside)


def test_restore_into_quarantine_rejected(tmp_path: Path, quarantine_dir: Path) -> None:
    source = _payload(tmp_path)
    manager = QuarantineManager(quarantine_dir)
    item = manager.isolate(source)
    with pytest.raises(QuarantineError, match="внутрь карантина"):
        manager.restore(item.item_id, target=quarantine_dir / "evil.exe")


def test_missing_file_raises(tmp_path: Path, quarantine_dir: Path) -> None:
    manager = QuarantineManager(quarantine_dir)
    with pytest.raises(QuarantineError, match="не найден"):
        manager.isolate(tmp_path / "ghost.exe")


def test_purge_removes_everything(tmp_path: Path, quarantine_dir: Path) -> None:
    source = _payload(tmp_path)
    manager = QuarantineManager(quarantine_dir)
    item = manager.isolate(source)

    manager.purge(item.item_id)
    assert manager.list_items() == []
    assert not (quarantine_dir / item.payload_file).exists()
    assert not list(quarantine_dir.glob("*.json"))


def test_purge_all(tmp_path: Path, quarantine_dir: Path) -> None:
    manager = QuarantineManager(quarantine_dir)
    for index in range(3):
        manager.isolate(_payload(tmp_path, f"sample_{index}.exe"))
    assert len(manager.list_items()) == 3

    removed = manager.purge_all()
    assert removed == 3
    assert manager.stats()["items"] == 0


def test_unknown_item_id(tmp_path: Path, quarantine_dir: Path) -> None:
    manager = QuarantineManager(quarantine_dir)
    with pytest.raises(QuarantineError, match="не найден в карантине"):
        manager.get("does-not-exist")


def test_xor_fallback_without_crypto(tmp_path: Path, quarantine_dir: Path) -> None:
    """Если AES недоступен, используется XOR — и обратимость сохраняется."""
    source = _payload(tmp_path, content=b"MZ" + b"payload-data" * 32)
    manager = QuarantineManager(quarantine_dir, preferred_mode=EncryptionMode.XOR)
    item = manager.isolate(source)
    assert item.encryption == EncryptionMode.XOR.value
    assert manager.extract_payload(item.item_id) == b"MZ" + b"payload-data" * 32


def test_no_encryption_mode(tmp_path: Path, quarantine_dir: Path) -> None:
    """Режим без шифрования сохраняет файл как есть (для отладки)."""
    content = b"MZ" + b"plain" * 64
    source = _payload(tmp_path, content=content)
    manager = QuarantineManager(quarantine_dir, encrypt=False)
    item = manager.isolate(source)

    assert item.encryption == EncryptionMode.NONE.value
    assert (quarantine_dir / item.payload_file).read_bytes() == content
    assert manager.extract_payload(item.item_id) == content


def test_directory_permissions_are_restricted(quarantine_dir: Path) -> None:
    """Каталог карантина доступен только владельцу (POSIX)."""
    QuarantineManager(quarantine_dir)
    if os.name == "posix":
        assert oct(quarantine_dir.stat().st_mode & 0o777) == "0o700"


def test_corrupted_metadata_is_skipped(quarantine_dir: Path) -> None:
    """Битая карточка не ломает список карантина."""
    manager = QuarantineManager(quarantine_dir)
    (quarantine_dir / "broken.json").write_text("{ not valid json", encoding="utf-8")
    assert manager.list_items() == []
