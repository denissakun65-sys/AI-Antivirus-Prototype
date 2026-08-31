"""
Онлайн-репутация по SHA-256 (threat intelligence).

Как это устроено в реальном мире и у нас
----------------------------------------
В облако уходит **только хеш**, никогда не сам файл. Источники:

* **MalwareBazaar** (abuse.ch) — бесплатная база malware-хешей, ключ не нужен.
  «Хеш найден» => файл известен как вредоносный (плюс семейство).
  «Хеш не найден» => *не* «файл чистый», а «в этой базе не числится».
* **VirusTotal API v3** — нужен бесплатный ключ (env ``AIAV_VT_KEY``).
  Даёт статистику вердиктов десятков вендоров: можно уверенно сказать
  и «известно вредоносный», и «известно чистый» (мощный анти-ложняк).

Любая сетевая ошибка = «репутации нет» (``None``), а не падение: сканер
продолжает работать офлайн, просто без облачного мнения.

Ответы кэшируются в SQLite с TTL (см. :mod:`aiav.cache`), чтобы не долбить
API на каждом прогоне и укладываться в rate-limit'ы.

Тестируемость: транспорт (функция HTTP-запроса) инъектится — в тестах
вместо сети подставляется заглушка, сеть не трогается вовсе.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from aiav.cache import VerdictCache
from aiav.config import VIRUSTOTAL_API_KEY
from aiav.logging_setup import get_logger

logger = get_logger(__name__)

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/"

#: Минимум «чистых» вердиктов VT, чтобы уверенно считать файл известным-чистым.
VT_CLEAN_MIN_HARMLESS = 10

#: Сигнатура HTTP-транспорта: (url, method, headers, data, timeout) -> dict.
Transport = Callable[[str, str, dict, bytes | None, int], dict]


@dataclass(slots=True)
class IntelResult:
    """Репутационное мнение по одному хешу."""

    source: str            # "malwarebazaar" | "virustotal"
    malicious: bool        # база знает этот хеш как вредоносный
    clean: bool            # есть уверенность, что хеш известный-чистый
    detail: str = ""       # человекочитаемая подробность (семейство, статистика)

    def summary(self) -> str:
        if self.malicious:
            return f"{self.source}: ВРЕДОНОСНЫЙ ({self.detail})"
        if self.clean:
            return f"{self.source}: известный чистый ({self.detail})"
        return f"{self.source}: нет уверенного вердикта ({self.detail})"


def _default_transport(
    url: str,
    method: str,
    headers: dict,
    data: bytes | None,
    timeout: int,
) -> dict:
    """Обычный HTTP-запрос через stdlib (без ``requests``)."""
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


class ThreatIntelClient:
    """Клиент репутационных сервисов с кэшем и graceful-офлайном."""

    def __init__(
        self,
        *,
        vt_api_key: str | None = None,
        cache: VerdictCache | None = None,
        timeout: int = 10,
        transport: Transport | None = None,
    ) -> None:
        """
        :param vt_api_key: ключ VirusTotal (по умолчанию — env ``AIAV_VT_KEY``).
        :param cache: кэш ответов; если None — кэширование отключено.
        :param timeout: таймаут HTTP-запросов, сек.
        :param transport: подмена транспорта (тесты/прокси).
        """
        self.vt_api_key = vt_api_key if vt_api_key is not None else VIRUSTOTAL_API_KEY
        self.cache = cache
        self.timeout = timeout
        self._transport: Transport = transport or _default_transport
        logger.debug(
            "ThreatIntel: VT key %s, cache=%s",
            "задан" if self.vt_api_key else "нет",
            "вкл" if cache else "выкл",
        )

    # ------------------------------ публичный API -------------------------- #

    def lookup(self, sha256: str) -> IntelResult | None:
        """
        Репутация хеша: сначала кэш, затем MalwareBazaar, затем (если есть ключ)
        VirusTotal. При любой сетевой ошибке возвращает ``None``.
        """
        digest = sha256.lower()

        if self.cache is not None:
            cached = self.cache.get_intel(digest)
            if cached is not None:
                logger.debug("Репутация из кэша: %s", digest[:12])
                return IntelResult(**cached)

        result = self._lookup_malwarebazaar(digest)
        if result is not None and not result.malicious and self.vt_api_key:
            # MB не знает хеш — уточним у VT, не известный ли это чистый файл.
            vt = self._lookup_virustotal(digest)
            if vt is not None:
                result = vt

        if result is not None and self.cache is not None:
            self.cache.put_intel(
                digest, result.source, result.malicious, result.clean, result.detail
            )
        return result

    # ------------------------------ провайдеры ----------------------------- #

    def _lookup_malwarebazaar(self, sha256: str) -> IntelResult | None:
        """Запрос к MalwareBazaar: «известен ли хеш как malware»."""
        payload = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
        try:
            response = self._transport(
                MALWAREBAZAAR_URL, "POST", {"User-Agent": "ai-antivirus"}, payload,
                self.timeout,
            )
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            logger.debug("MalwareBazaar недоступен: %s", exc)
            return None

        status = response.get("query_status")
        if status == "ok":
            entries = response.get("data", [])
            signature = entries[0].get("signature", "unknown") if entries else "unknown"
            return IntelResult(
                source="malwarebazaar",
                malicious=True,
                clean=False,
                detail=f"семейство: {signature}",
            )
        if status in ("hash_not_found", "illegal_hash"):
            return IntelResult(
                source="malwarebazaar",
                malicious=False,
                clean=False,
                detail="в базе malware не числится",
            )
        logger.debug("MalwareBazaar: неожиданный ответ %r", status)
        return None

    def _lookup_virustotal(self, sha256: str) -> IntelResult | None:
        """Запрос к VirusTotal v3: статистика вердиктов вендоров."""
        try:
            response = self._transport(
                VIRUSTOTAL_URL + sha256,
                "GET",
                {"x-apikey": self.vt_api_key, "User-Agent": "ai-antivirus"},
                None,
                self.timeout,
            )
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            logger.debug("VirusTotal недоступен: %s", exc)
            return None
        except urllib.error.HTTPError as exc:  # 404 = хеш VT неизвестен
            logger.debug("VirusTotal HTTP %s для %s", exc.code, sha256[:12])
            return None

        try:
            attributes = response["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
        except (KeyError, TypeError) as exc:
            logger.debug("VirusTotal: незнакомая схема ответа: %s", exc)
            return None

        malicious_votes = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
        harmless_votes = int(stats.get("harmless", 0))
        label = (
            attributes.get("popular_threat_classification", {})
            .get("suggested_threat_label", "")
        )
        detail = f"malicious={malicious_votes}, harmless={harmless_votes}"
        if label:
            detail += f", label={label}"

        if malicious_votes > 0:
            return IntelResult(source="virustotal", malicious=True, clean=False, detail=detail)
        if harmless_votes >= VT_CLEAN_MIN_HARMLESS:
            return IntelResult(source="virustotal", malicious=False, clean=True, detail=detail)
        return IntelResult(source="virustotal", malicious=False, clean=False, detail=detail)


__all__ = ["ThreatIntelClient", "IntelResult", "MALWAREBAZAAR_URL", "VIRUSTOTAL_URL"]
