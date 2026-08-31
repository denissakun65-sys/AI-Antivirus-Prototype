"""
Список доверия (whitelist) — главный борец с ложными срабатываниями.

Два слоя
--------
1. **Доверенные пути.** Файлы внутри системных каталогов (``C:\\Windows``,
   ``/usr/lib`` и т.п. — см. :data:`aiav.config.TRUSTED_PATH_PREFIXES`) не
   сканируются вовсе: вероятность встретить там самописный malware мала,
   а сканировать тысячи системных DLL при каждом прогоне — wasteful.
2. **Доверенные хеши.** Пользователь явно помечает файл как чистый
   (``aiav trust <file>``) — его SHA-256 попадает в список и больше никогда
   не flagged. Именно так «лечатся» ложные срабатывания на конкретном софте.

Список хранится в JSON рядом с моделями и переживает перезапуски.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterable
from pathlib import Path

from aiav.config import TRUSTED_PATH_PREFIXES, TRUSTLIST_PATH
from aiav.features import sha256_of
from aiav.logging_setup import get_logger

logger = get_logger(__name__)


class Trustlist:
    """Потокобезопасный whitelist с персистентностью в JSON."""

    def __init__(
        self,
        path: str | Path | None = None,
        trusted_prefixes: Iterable[str] | None = None,
    ) -> None:
        """
        :param path: JSON со списками; по умолчанию ``models/trustlist.json``.
        :param trusted_prefixes: переопределение доверенных префиксов путей
            (в тестах удобно передавать временные каталоги).
        """
        self.path = Path(path) if path else TRUSTLIST_PATH
        self.prefixes: tuple[str, ...] = (
            tuple(trusted_prefixes) if trusted_prefixes is not None else TRUSTED_PATH_PREFIXES
        )
        self._lock = threading.Lock()
        self._hashes: set[str] = set()
        self._paths: set[str] = set()
        self._load()

    # ------------------------------ загрузка ------------------------------ #

    def _load(self) -> None:
        """Читает JSON; отсутствие файла или битые данные — не ошибка."""
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self._hashes = {str(h).lower() for h in data.get("hashes", [])}
            self._paths = {str(p) for p in data.get("paths", [])}
            logger.debug(
                "Trustlist загружен: %d хеш(ей), %d путь(ей)",
                len(self._hashes), len(self._paths),
            )
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Не удалось прочитать trustlist %s: %s", self.path, exc)

    def _save(self) -> None:
        """Атомарная запись JSON."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(
                {"hashes": sorted(self._hashes), "paths": sorted(self._paths)},
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        tmp.replace(self.path)

    # ------------------------------ проверка ------------------------------ #

    def is_trusted_path(self, path: str | Path) -> bool:
        """Лежит ли файл под доверенным префиксом (системные каталоги и т.п.)."""
        text = str(path)
        with self._lock:
            prefixes = tuple(self._paths) + self.prefixes
        return any(text.startswith(prefix) for prefix in prefixes if prefix)

    def is_trusted_hash(self, sha256: str) -> bool:
        """Помечен ли хеш как доверенный пользователем."""
        with self._lock:
            return sha256.lower() in self._hashes

    # ------------------------------ управление ----------------------------- #

    def trust_file(self, path: str | Path) -> str:
        """
        Помечает файл как доверенный по SHA-256.

        :return: добавленный хеш.
        """
        digest = sha256_of(path)
        with self._lock:
            self._hashes.add(digest.lower())
            self._save()
        logger.warning("Хеш помечен доверенным: %s (%s)", digest[:16], Path(path).name)
        return digest

    def trust_path_prefix(self, prefix: str | Path) -> None:
        """Добавляет префикс пути в доверенные (например, папку с игрой/IDE)."""
        with self._lock:
            self._paths.add(str(prefix))
            self._save()
        logger.warning("Префикс помечен доверенным: %s", prefix)

    def untrust(self, sha_or_prefix: str) -> bool:
        """
        Убирает запись из списка доверия (хеш или префикс пути).

        :return: True, если запись нашлась и удалена.
        """
        needle = sha_or_prefix.lower()
        with self._lock:
            if needle in self._hashes:
                self._hashes.discard(needle)
                self._save()
                return True
            if sha_or_prefix in self._paths:
                self._paths.discard(sha_or_prefix)
                self._save()
                return True
        return False

    def stats(self) -> dict[str, int]:
        """Сводка размеров списков."""
        with self._lock:
            return {"hashes": len(self._hashes), "paths": len(self._paths)}

    def dump(self) -> dict[str, list[str]]:
        """Полное содержимое списков (для ``trust list``)."""
        with self._lock:
            return {"hashes": sorted(self._hashes), "paths": sorted(self._paths)}


__all__ = ["Trustlist"]
