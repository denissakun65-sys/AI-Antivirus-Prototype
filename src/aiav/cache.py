"""
Кэш вердиктов и репутационных ответов (SQLite, без внешних зависимостей).

Зачем это нужно
---------------
1. **Не сканировать одно и то же дважды.** Вердикт по SHA-256 + сигнатуре
   модели сохраняется; повторная встреча с файлом (тот же хеш) отдаёт вердикт
   из кэша за микросекунды — без разбора PE и вызова модели. Это главный
   механизм снижения нагрузки и «повторных ложняков».
2. **Кэшировать ответы threat-intel.** Репутация хеша в MalwareBazaar/
   VirusTotal не меняется ежесекундно, поэтому ответы хранятся с TTL
   (:data:`aiav.config.INTEL_CACHE_TTL_DAYS`).

Хранилище — один SQLite-файл с двумя таблицами. SQLite из стандартной
библиотеки, потокобезопасность обеспечиваем блокировкой (monitor работает
в фоновом потоке).
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aiav.config import INTEL_CACHE_TTL_DAYS, VERDICT_CACHE_PATH
from aiav.logging_setup import get_logger

logger = get_logger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    sha256     TEXT NOT NULL,
    model_sig  TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    probability REAL NOT NULL,
    scanned_at TEXT NOT NULL,
    PRIMARY KEY (sha256, model_sig)
);
CREATE TABLE IF NOT EXISTS intel (
    sha256     TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    malicious  INTEGER NOT NULL,
    clean      INTEGER NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    fetched_at TEXT NOT NULL
);
"""


class VerdictCache:
    """Потокобезопасный кэш вердиктов и репутации."""

    def __init__(self, path: str | Path | None = None) -> None:
        """
        :param path: файл БД; по умолчанию ``models/verdict_cache.db``.
            ``":memory:"`` — для тестов.
        """
        self.path = Path(path) if path else VERDICT_CACHE_PATH
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # check_same_thread=False: пишет и сканер (основной поток), и monitor.
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, timeout=10.0
        )
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
        logger.debug("Кэш вердиктов открыт: %s", self.path)

    # ------------------------------ вердикты ------------------------------ #

    def get_verdict(self, sha256: str, model_sig: str) -> dict[str, object] | None:
        """
        Вердикт из кэша или ``None`` (хеш не встречался / модель переобучена).

        Сигнатура модели в ключе гарантирует, что после переобучения старые
        вердикты не выдаются за свежие.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT verdict, probability, scanned_at FROM verdicts "
                "WHERE sha256 = ? AND model_sig = ?",
                (sha256.lower(), model_sig),
            ).fetchone()
        if row is None:
            return None
        return {"verdict": row[0], "probability": float(row[1]), "scanned_at": row[2]}

    def put_verdict(
        self, sha256: str, model_sig: str, verdict: str, probability: float
    ) -> None:
        """Сохраняет вердикт (upsert)."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO verdicts (sha256, model_sig, verdict, probability, scanned_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(sha256, model_sig) DO UPDATE SET "
                "verdict=excluded.verdict, probability=excluded.probability, "
                "scanned_at=excluded.scanned_at",
                (
                    sha256.lower(),
                    model_sig,
                    verdict,
                    float(probability),
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )
            self._conn.commit()

    # ------------------------------ репутация ----------------------------- #

    def get_intel(self, sha256: str) -> dict[str, object] | None:
        """Кэшированный репутационный ответ, если TTL ещё не истёк."""
        with self._lock:
            row = self._conn.execute(
                "SELECT source, malicious, clean, detail, fetched_at FROM intel "
                "WHERE sha256 = ?",
                (sha256.lower(),),
            ).fetchone()
        if row is None:
            return None
        fetched = datetime.fromisoformat(row[4])
        if datetime.now(timezone.utc) - fetched > timedelta(days=INTEL_CACHE_TTL_DAYS):
            return None  # устарело — запросим заново
        return {
            "source": row[0],
            "malicious": bool(row[1]),
            "clean": bool(row[2]),
            "detail": row[3],
        }

    def put_intel(
        self, sha256: str, source: str, malicious: bool, clean: bool, detail: str = ""
    ) -> None:
        """Сохраняет репутационный ответ (upsert)."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO intel (sha256, source, malicious, clean, detail, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(sha256) DO UPDATE SET source=excluded.source, "
                "malicious=excluded.malicious, clean=excluded.clean, "
                "detail=excluded.detail, fetched_at=excluded.fetched_at",
                (
                    sha256.lower(),
                    source,
                    int(malicious),
                    int(clean),
                    detail,
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                ),
            )
            self._conn.commit()

    # ------------------------------ обслуживание --------------------------- #

    def counts(self) -> dict[str, int]:
        """Счётчики записей — для сводок и отладки."""
        with self._lock:
            verdicts = self._conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
            intel = self._conn.execute("SELECT COUNT(*) FROM intel").fetchone()[0]
        return {"verdicts": int(verdicts), "intel": int(intel)}

    def clear(self) -> None:
        """Полная очистка (например, после глобального переобучения)."""
        with self._lock:
            self._conn.execute("DELETE FROM verdicts")
            self._conn.execute("DELETE FROM intel")
            self._conn.commit()
        logger.info("Кэш вердиктов очищен")

    def close(self) -> None:
        """Закрывает соединение."""
        with self._lock:
            self._conn.close()


__all__ = ["VerdictCache"]
