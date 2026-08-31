"""
Карантин: изоляция, хранение и восстановление подозрительных файлов.

Принципы
--------
1. **Объект никогда не исполняется из карантина.** Файл переименовывается в
   ``<id>.quarantined`` (Windows не сможет запустить такой файл как PE),
   а опционально ещё и шифруется AES-256-GCM.
2. **Метаданные рядом с объектом.** ``<id>.json`` хранит исходный путь,
   SHA-256, размер, вердикт модели и время — этого достаточно для
   восстановления и для расследования инцидента.
3. **Контроль целостности.** При восстановлении хеш сверяется: если объект
   в карантине подменили, восстановление прерывается.
4. **Никакой перезаписи.** ``restore()`` отказывается затирать существующий
   файл, если явно не передан ``force=True``.

.. warning::
    Настоящий антивирус дополнительно выставляет ACL/права только для SYSTEM,
    использует защищённое хранилище и журналирование в SIEM. Здесь реализована
    упрощённая, но безопасная по логике версия.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import time
import uuid
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from aiav.features import sha256_of
from aiav.logging_setup import get_logger

logger = get_logger(__name__)

QUARANTINE_SUFFIX = ".quarantined"
META_SUFFIX = ".json"
KEY_FILENAME = ".quarantine.key"
_READ_ONLY = stat.S_IRUSR  # 0o400 — только чтение владельцем

try:  # опциональное усиление: настоящее шифрование вместо обфускации
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False


class EncryptionMode(str, Enum):
    """Режим хранения объекта в карантине."""

    NONE = "none"        # только переименование
    XOR = "xor"          # обратимая обфускация (нет зависимостей)
    AES256 = "aes256"    # AES-256-GCM (требуется пакет `cryptography`)


@dataclass(slots=True)
class QuarantineItem:
    """Запись об одном изолированном объекте."""

    item_id: str
    original_path: str
    sha256: str
    size: int
    quarantined_at: str
    verdict: str = "MALICIOUS"
    probability: float = 0.0
    model: str = ""
    reason: str = ""
    encryption: str = EncryptionMode.NONE.value
    payload_file: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class QuarantineError(Exception):
    """Ошибка операции с карантином."""


class QuarantineManager:
    """Управляет каталогом карантина."""

    def __init__(
        self,
        directory: str | Path,
        *,
        encrypt: bool = True,
        preferred_mode: EncryptionMode = EncryptionMode.AES256,
    ) -> None:
        """
        :param directory: каталог карантина (создаётся при необходимости).
        :param encrypt: шифровать ли содержимое при изоляции.
        :param preferred_mode: желаемый режим; при недоступности ``cryptography``
            выполняется деградация до XOR с предупреждением в лог.
        """
        self.directory = Path(directory).expanduser().resolve()
        self.encrypt = bool(encrypt)
        self.preferred_mode = preferred_mode
        self._ensure_directory()

    # --------------------------- инфраструктура -------------------------- #

    def _ensure_directory(self) -> None:
        """Создаёт каталог карантина и ограничивает права (best effort)."""
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            if os.name == "posix":
                os.chmod(self.directory, 0o700)  # только владелец
            elif os.name == "nt":  # pragma: no cover - Windows-only
                logger.debug(
                    "На Windows права задаются ACL; выполните: "
                    "icacls \"%s\" /inheritance:r /grant:r \"%%USERNAME%%\":(OI)(CI)F",
                    self.directory,
                )
        except OSError as exc:
            raise QuarantineError(f"Не удалось создать каталог карантина {self.directory}: {exc}") from exc

    def _resolve_mode(self) -> EncryptionMode:
        """Выбирает реально доступный режим шифрования."""
        if not self.encrypt:
            return EncryptionMode.NONE
        if self.preferred_mode is EncryptionMode.AES256:
            if _HAS_CRYPTO:
                return EncryptionMode.AES256
            logger.warning(
                "Пакет 'cryptography' не установлен — используется XOR-обфускация "
                "(это НЕ криптостойкая защита). Установите: pip install cryptography"
            )
            return EncryptionMode.XOR
        return self.preferred_mode

    def _get_key(self) -> bytes:
        """Возвращает 32-байтовый ключ, создавая и защищая его при первом запуске."""
        key_path = self.directory / KEY_FILENAME
        if key_path.exists():
            return key_path.read_bytes()
        key = os.urandom(32)
        # fd + O_EXCL: создаём файл сразу с правами 0600, без гонки.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
        logger.info("Создан ключ карантина: %s (права 0600)", key_path)
        return key

    # ------------------------------- изоляция ---------------------------- #

    def isolate(
        self,
        source: str | Path,
        *,
        verdict: str = "MALICIOUS",
        probability: float = 0.0,
        model: str = "",
        reason: str = "",
        extra: dict[str, Any] | None = None,
    ) -> QuarantineItem:
        """
        Перемещает файл в карантин и создаёт карточку с метаданными.

        :raises QuarantineError: файл недоступен, уже в карантине или операция
            копирования/удаления завершилась ошибкой.
        :return: :class:`QuarantineItem` с описанием изолированного объекта.
        """
        src = Path(source).expanduser().resolve()
        try:
            if not src.exists():
                raise QuarantineError(f"Файл не найден: {src}")
            if not src.is_file():
                raise QuarantineError(f"Не является файлом: {src}")
            if self._is_inside_quarantine(src):
                raise QuarantineError(f"Файл уже находится в карантине: {src}")

            size = src.stat().st_size
            digest = sha256_of(src)
            mode = self._resolve_mode()
            item_id = self._make_item_id()
            payload_path = self.directory / f"{item_id}{QUARANTINE_SUFFIX}"

            logger.info("Изоляция: %s -> %s (режим=%s)", src.name, payload_path.name, mode.value)
            self._move_and_transform(src, payload_path, mode)
            self._harden(payload_path)

            item = QuarantineItem(
                item_id=item_id,
                original_path=str(src),
                sha256=digest,
                size=size,
                quarantined_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                verdict=verdict,
                probability=round(float(probability), 6),
                model=model,
                reason=reason,
                encryption=mode.value,
                payload_file=payload_path.name,
                extra=extra or {},
            )
            self._write_meta(item)
            logger.warning(
                "Файл помещён в карантин: %s (id=%s, sha256=%s…)",
                src.name, item_id, digest[:12],
            )
            return item

        except QuarantineError:
            raise
        except PermissionError as exc:
            raise QuarantineError(
                f"Нет прав на перемещение {src} (запустите с правами администратора): {exc}"
            ) from exc
        except OSError as exc:
            raise QuarantineError(f"Ошибка ввода-вывода при изоляции {src}: {exc}") from exc

    def _make_item_id(self) -> str:
        """Генерирует короткий уникальный идентификатор объекта."""
        return f"{int(time.time())}-{uuid.uuid4().hex[:8]}"

    def _is_inside_quarantine(self, path: Path) -> bool:
        """Проверяет, не лежит ли файл уже в карантине (защита от рекурсии)."""
        try:
            path.relative_to(self.directory)
            return True
        except ValueError:
            return False

    def _move_and_transform(
        self, src: Path, dst: Path, mode: EncryptionMode
    ) -> None:
        """
        Переносит файл в карантин.

        Сначала пробуем быстрый путь (``os.replace`` — атомарно на одном томе).
        Если нужно шифрование или тома разные — копируем с преобразованием,
        а оригинал удаляем только после успешной записи и проверки.
        """
        if mode is EncryptionMode.NONE:
            try:
                os.replace(src, dst)
                return
            except OSError as exc:
                logger.debug("os.replace не удался (%s) — копирую", exc)
                shutil.copy2(src, dst)
                self._verify_copy(src, dst)
                src.unlink()
                return

        try:
            with open(src, "rb") as handle:
                payload = handle.read()
            blob = self._encrypt(payload, mode)
            tmp = dst.with_suffix(dst.suffix + ".part")
            with open(tmp, "wb") as handle:
                handle.write(blob)
            tmp.replace(dst)
        except OSError:
            dst.unlink(missing_ok=True)
            raise

        # Оригинал удаляем только убедившись, что объект надёжно сохранён.
        if not dst.is_file() or dst.stat().st_size == 0:
            raise QuarantineError("Запись в карантин не удалась — оригинал не удалён")
        src.unlink()

    @staticmethod
    def _verify_copy(src: Path, dst: Path) -> None:
        """Сверяет хеши копии и оригинала перед удалением оригинала."""
        if sha256_of(src) != sha256_of(dst):
            dst.unlink(missing_ok=True)
            raise QuarantineError(f"Контрольная сумма копии не совпала: {src} -> {dst}")

    @staticmethod
    def _harden(path: Path) -> None:
        """Снимает права на запись/исполнение (POSIX). На Windows — best effort."""
        try:
            if os.name == "posix":
                os.chmod(path, _READ_ONLY)
            else:  # pragma: no cover
                os.chmod(path, stat.S_IREAD)
        except OSError as exc:
            logger.debug("Не удалось ограничить права %s: %s", path, exc)

    # ------------------------------ шифрование --------------------------- #

    def _encrypt(self, data: bytes, mode: EncryptionMode) -> bytes:
        """Шифрует содержимое. Формат: 4-байтовая сигнатура + nonce/IV + тело."""
        if mode is EncryptionMode.AES256:
            nonce = os.urandom(12)
            ciphertext = AESGCM(self._get_key()).encrypt(nonce, data, associated_data=None)
            return b"AIAV" + nonce + ciphertext
        if mode is EncryptionMode.XOR:
            key = self._get_key()
            return b"AIXR" + bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        raise QuarantineError(f"Неподдерживаемый режим шифрования: {mode}")

    def _decrypt(self, blob: bytes, mode: EncryptionMode) -> bytes:
        """Обратное преобразование; проверяет сигнатуру формата."""
        if len(blob) < 4:
            raise QuarantineError("Повреждённый объект карантина: файл слишком мал")
        magic, body = blob[:4], blob[4:]
        if mode is EncryptionMode.AES256:
            if magic != b"AIAV" or len(body) < 12:
                raise QuarantineError("Неверный формат AES-контейнера карантина")
            nonce, ciphertext = body[:12], body[12:]
            try:
                return AESGCM(self._get_key()).decrypt(nonce, ciphertext, associated_data=None)
            except Exception as exc:  # noqa: BLE001 - cryptography бросает InvalidTag
                raise QuarantineError(
                    "Не удалось расшифровать объект (неверный ключ или повреждение): "
                    f"{exc}"
                ) from exc
        if mode is EncryptionMode.XOR:
            if magic != b"AIXR":
                raise QuarantineError("Неверный формат XOR-контейнера карантина")
            key = self._get_key()
            return bytes(b ^ key[i % len(key)] for i, b in enumerate(body))
        raise QuarantineError(f"Неподдерживаемый режим шифрования: {mode}")

    # ------------------------------ чтение ------------------------------- #

    def _write_meta(self, item: QuarantineItem) -> None:
        """Пишет JSON-карточку объекта (атомарно)."""
        meta_path = self.directory / f"{item.item_id}{META_SUFFIX}"
        tmp = meta_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(item.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(meta_path)

    def list_items(self) -> list[QuarantineItem]:
        """Возвращает все записи карантина, отсортированные по дате (новые первыми)."""
        items = list(self._iter_items())
        items.sort(key=lambda it: it.quarantined_at, reverse=True)
        return items

    def _iter_items(self) -> Iterator[QuarantineItem]:
        """Читает карточки; повреждённые/неполные JSON логирует и пропускает."""
        if not self.directory.is_dir():
            return
        known_fields = set(QuarantineItem.__dataclass_fields__)
        for meta_path in self.directory.glob(f"*{META_SUFFIX}"):
            try:
                data = json.loads(meta_path.read_text(encoding="utf-8"))
                payload = {k: v for k, v in data.items() if k in known_fields}
                if "item_id" not in payload:  # без идентификатора объект бесполезен
                    raise ValueError("в карточке нет поля 'item_id'")
                yield QuarantineItem(**payload)
            except (json.JSONDecodeError, TypeError, ValueError, OSError) as exc:
                logger.warning("Пропущена повреждённая карточка %s: %s", meta_path.name, exc)

    def get(self, item_id: str) -> QuarantineItem:
        """Находит запись по идентификатору (поддерживает префикс)."""
        matches = [it for it in self._iter_items() if it.item_id.startswith(item_id)]
        if not matches:
            raise QuarantineError(f"Объект {item_id!r} не найден в карантине")
        if len(matches) > 1:
            ids = ", ".join(it.item_id for it in matches)
            raise QuarantineError(f"Префикс {item_id!r} неоднозначен: {ids}")
        return matches[0]

    def _payload_path(self, item: QuarantineItem) -> Path:
        """Путь к телу объекта в карантине."""
        return self.directory / (item.payload_file or f"{item.item_id}{QUARANTINE_SUFFIX}")

    def extract_payload(self, item_id: str) -> bytes:
        """
        Возвращает исходное содержимое объекта (для анализа в песочнице).

        Дополнительно проверяет SHA-256: при несовпадении объект считается
        подменённым и не выдаётся.
        """
        item = self.get(item_id)
        payload = self._payload_path(item)
        if not payload.is_file():
            raise QuarantineError(f"Тело объекта отсутствует: {payload}")
        try:
            mode = EncryptionMode(item.encryption)
        except ValueError as exc:
            raise QuarantineError(f"Неизвестный режим шифрования: {item.encryption}") from exc

        data = payload.read_bytes()
        if mode is not EncryptionMode.NONE:
            data = self._decrypt(data, mode)
        if item.sha256 and sha256_of_bytes(data) != item.sha256:
            raise QuarantineError(
                f"Целостность объекта {item.item_id} нарушена (SHA-256 не совпадает)"
            )
        return data

    # ---------------------------- восстановление ------------------------- #

    def restore(
        self,
        item_id: str,
        *,
        target: str | Path | None = None,
        force: bool = False,
        keep_record: bool = False,
    ) -> Path:
        """
        Возвращает файл по исходному (или указанному) пути.

        :param target: куда восстановить; по умолчанию — ``original_path``.
        :param force: разрешить перезапись существующего файла.
        :param keep_record: не удалять карточку карантина после восстановления.
        :raises QuarantineError: нарушение целостности, конфликт путей, ошибки IO.
        """
        item = self.get(item_id)
        destination = (
            Path(target).expanduser().resolve()
            if target
            else Path(item.original_path).expanduser()
        )
        data = self.extract_payload(item_id)  # включает проверку целостности

        if destination.exists() and not force:
            raise QuarantineError(
                f"По пути {destination} уже есть файл. Используйте force=True "
                "для перезаписи."
            )
        if self._is_inside_quarantine(destination):
            raise QuarantineError("Нельзя восстанавливать файл внутрь карантина")

        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            tmp = destination.with_suffix(destination.suffix + ".restoring")
            tmp.write_bytes(data)
            tmp.replace(destination)
            if os.name == "posix":
                os.chmod(destination, 0o644)
        except OSError as exc:
            raise QuarantineError(f"Не удалось восстановить файл в {destination}: {exc}") from exc

        logger.warning("Файл восстановлен: %s (id=%s)", destination, item.item_id)
        if not keep_record:
            self.purge(item_id)
        return destination

    # ------------------------------ удаление ----------------------------- #

    def purge(self, item_id: str) -> None:
        """Необратимо удаляет объект и его карточку из карантина."""
        item = self.get(item_id)
        for path in (self._payload_path(item), self.directory / f"{item.item_id}{META_SUFFIX}"):
            try:
                if path.exists():
                    if os.name == "posix":
                        os.chmod(path, stat.S_IRWXU)  # вернуть право на удаление
                    path.unlink()
            except OSError as exc:
                raise QuarantineError(f"Не удалось удалить {path}: {exc}") from exc
        logger.info("Объект удалён из карантина: %s (%s)", item_id, item.original_path)

    def purge_all(self) -> int:
        """Очищает весь карантин. Возвращает число удалённых объектов."""
        items = self.list_items()
        for item in items:
            self.purge(item.item_id)
        logger.warning("Карантин очищен: удалено объектов — %d", len(items))
        return len(items)

    def stats(self) -> dict[str, Any]:
        """Сводка по карантину — используется в отчёте сканирования."""
        items = self.list_items()
        total_bytes = sum(it.size for it in items)
        return {
            "directory": str(self.directory),
            "items": len(items),
            "total_size_bytes": total_bytes,
            "encryption": self._resolve_mode().value,
        }


def sha256_of_bytes(data: bytes) -> str:
    """SHA-256 байтовой строки (для проверки целостности содержимого)."""
    import hashlib

    return hashlib.sha256(data).hexdigest()


__all__ = [
    "QuarantineManager",
    "QuarantineItem",
    "QuarantineError",
    "EncryptionMode",
    "QUARANTINE_SUFFIX",
]
