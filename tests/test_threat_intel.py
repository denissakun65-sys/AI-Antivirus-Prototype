"""
Тесты онлайн-репутации (``aiav.threat_intel``).

Сеть в тестах НЕ используется: транспорт подменяется заглушкой, которая
возвращает заранее заготовленные JSON-ответы или бросает сетевые ошибки.
"""

from __future__ import annotations

import json
import urllib.error

from aiav.cache import VerdictCache
from aiav.threat_intel import MALWAREBAZAAR_URL, VIRUSTOTAL_URL, ThreatIntelClient

SHA = "c" * 64


def _vt_payload(malicious: int = 0, harmless: int = 0, label: str = "") -> dict:
    stats = {"malicious": malicious, "suspicious": 0, "harmless": harmless}
    attrs = {"last_analysis_stats": stats}
    if label:
        attrs["popular_threat_classification"] = {"suggested_threat_label": label}
    return {"data": {"attributes": attrs}}


def _fake_transport(responses: dict[str, dict], calls: list[str]):
    """Транспорт-заглушка: сопоставляет URL-префикс с заготовленным ответом."""

    def transport(url, method, headers, data, timeout):  # noqa: ARG001
        calls.append(url)
        for prefix, payload in responses.items():
            if url.startswith(prefix):
                return payload
        raise urllib.error.URLError(f"нет заготовки для {url}")

    return transport


def test_malwarebazaar_known_malware() -> None:
    calls: list[str] = []
    client = ThreatIntelClient(
        transport=_fake_transport(
            {MALWAREBAZAAR_URL: {"query_status": "ok",
                                 "data": [{"signature": "Emotet"}]}},
            calls,
        )
    )
    result = client.lookup(SHA)
    assert result is not None
    assert result.malicious is True and result.clean is False
    assert "Emotet" in result.detail
    assert calls == [MALWAREBAZAAR_URL]  # VT не дёргаем: вердикт уже уверенный


def test_malwarebazaar_not_found_is_not_clean() -> None:
    """«Не найден в malware-базе» ≠ «файл чистый» — честная семантика."""
    client = ThreatIntelClient(
        transport=_fake_transport(
            {MALWAREBAZAAR_URL: {"query_status": "hash_not_found"}}, []
        )
    )
    result = client.lookup(SHA)
    assert result is not None
    assert result.malicious is False and result.clean is False


def test_vt_clean_when_mb_silent() -> None:
    """MB не знает хеш, а VT говорит «40 вендоров считают чистым» -> clean."""
    calls: list[str] = []
    client = ThreatIntelClient(
        vt_api_key="test-key",
        transport=_fake_transport(
            {
                MALWAREBAZAAR_URL: {"query_status": "hash_not_found"},
                VIRUSTOTAL_URL: _vt_payload(malicious=0, harmless=45),
            },
            calls,
        ),
    )
    result = client.lookup(SHA)
    assert result is not None
    assert result.clean is True and result.malicious is False
    assert VIRUSTOTAL_URL + SHA in calls


def test_vt_malicious_consensus() -> None:
    client = ThreatIntelClient(
        vt_api_key="test-key",
        transport=_fake_transport(
            {
                MALWAREBAZAAR_URL: {"query_status": "hash_not_found"},
                VIRUSTOTAL_URL: _vt_payload(malicious=38, harmless=2, label="trojan.generic"),
            },
            [],
        ),
    )
    result = client.lookup(SHA)
    assert result is not None and result.malicious is True
    assert "trojan.generic" in result.detail


def test_no_vt_key_no_vt_call() -> None:
    """Без ключа VT не вызывается вообще (экономим rate-limit)."""
    calls: list[str] = []
    client = ThreatIntelClient(
        transport=_fake_transport(
            {MALWAREBAZAAR_URL: {"query_status": "hash_not_found"},
             VIRUSTOTAL_URL: _vt_payload(harmless=60)},
            calls,
        )
    )
    result = client.lookup(SHA)
    assert result is not None and result.clean is False
    assert all(not url.startswith(VIRUSTOTAL_URL) for url in calls)


def test_network_failure_returns_none() -> None:
    """Офлайн/сбой сети = None, а не исключение: сканер живёт дальше."""

    def broken(url, method, headers, data, timeout):  # noqa: ARG001
        raise urllib.error.URLError("нет сети")

    client = ThreatIntelClient(vt_api_key="k", transport=broken)
    assert client.lookup(SHA) is None


def test_vt_http_404_is_none() -> None:
    def not_found(url, method, headers, data, timeout):  # noqa: ARG001
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    client = ThreatIntelClient(
        vt_api_key="k",
        transport=_fake_transport(
            {MALWAREBAZAAR_URL: {"query_status": "hash_not_found"}}, []
        ),
    )
    client._transport = not_found  # noqa: SLF001 - тестируем ветку 404
    assert client.lookup(SHA) is None


def test_lookup_is_cached() -> None:
    """Повторный lookup берётся из кэша — сеть не дёргается второй раз."""
    calls: list[str] = []
    cache = VerdictCache(":memory:")
    client = ThreatIntelClient(
        cache=cache,
        transport=_fake_transport(
            {MALWAREBAZAAR_URL: {"query_status": "ok", "data": [{"signature": "X"}]}},
            calls,
        ),
    )
    assert client.lookup(SHA) is not None
    assert client.lookup(SHA) is not None
    assert calls == [MALWAREBAZAAR_URL]  # ровно один реальный запрос
    assert cache.counts()["intel"] == 1


def test_result_summary_human_readable() -> None:
    client = ThreatIntelClient(
        transport=_fake_transport(
            {MALWAREBAZAAR_URL: {"query_status": "ok", "data": [{"signature": "QakBot"}]}},
            [],
        )
    )
    result = client.lookup(SHA)
    assert result is not None
    assert "ВРЕДОНОСНЫЙ" in result.summary()
    assert json.dumps(result.summary(), ensure_ascii=False)  # юникод не ломается
