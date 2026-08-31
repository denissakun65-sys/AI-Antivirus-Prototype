"""Тесты SQLite-кэша вердиктов и репутации (``aiav.cache``)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aiav.cache import VerdictCache


@pytest.fixture()
def cache() -> VerdictCache:
    """Кэш в памяти — каждый тест изолирован."""
    return VerdictCache(":memory:")


SHA = "a" * 64
SIG = "random_forest:2026-08-31T00:00:00+00:00"


def test_verdict_roundtrip(cache: VerdictCache) -> None:
    assert cache.get_verdict(SHA, SIG) is None
    cache.put_verdict(SHA, SIG, "MALICIOUS", 0.97)

    row = cache.get_verdict(SHA, SIG)
    assert row is not None
    assert row["verdict"] == "MALICIOUS"
    assert row["probability"] == pytest.approx(0.97)


def test_verdict_keyed_by_model_signature(cache: VerdictCache) -> None:
    """После переобучения (новая сигнатура) старые вердикты не всплывают."""
    cache.put_verdict(SHA, SIG, "MALICIOUS", 0.97)
    assert cache.get_verdict(SHA, "lightgbm:2026-09-01") is None


def test_verdict_upsert_overwrites(cache: VerdictCache) -> None:
    cache.put_verdict(SHA, SIG, "MALICIOUS", 0.9)
    cache.put_verdict(SHA, SIG, "CLEAN", 0.05)
    assert cache.get_verdict(SHA, SIG)["verdict"] == "CLEAN"


def test_hash_case_insensitive(cache: VerdictCache) -> None:
    cache.put_verdict(SHA.upper(), SIG, "CLEAN", 0.1)
    assert cache.get_verdict(SHA, SIG) is not None


def test_intel_roundtrip(cache: VerdictCache) -> None:
    assert cache.get_intel(SHA) is None
    cache.put_intel(SHA, "virustotal", malicious=False, clean=True, detail="harmless=40")

    row = cache.get_intel(SHA)
    assert row is not None
    assert row["clean"] is True and row["malicious"] is False
    assert row["detail"] == "harmless=40"


def test_intel_ttl_expiry(cache: VerdictCache, monkeypatch: pytest.MonkeyPatch) -> None:
    """Устаревшая репутация не отдаётся — нужен свежий запрос."""
    cache.put_intel(SHA, "malwarebazaar", malicious=True, clean=False)
    import aiav.cache as cache_module

    future = datetime.now(timezone.utc) + timedelta(days=30)

    class FakeDT(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: N805
            return future

    monkeypatch.setattr(cache_module, "datetime", FakeDT)
    assert cache.get_intel(SHA) is None


def test_counts_and_clear(cache: VerdictCache) -> None:
    cache.put_verdict(SHA, SIG, "CLEAN", 0.1)
    cache.put_intel(SHA, "virustotal", False, True)
    assert cache.counts() == {"verdicts": 1, "intel": 1}

    cache.clear()
    assert cache.counts() == {"verdicts": 0, "intel": 0}


def test_persistence_to_file(tmp_path) -> None:
    """SQLite-файл переживает пересоздание объекта кэша."""
    db = tmp_path / "cache.db"
    first = VerdictCache(db)
    first.put_verdict(SHA, SIG, "SUSPICIOUS", 0.6)
    first.close()

    second = VerdictCache(db)
    assert second.get_verdict(SHA, SIG)["verdict"] == "SUSPICIOUS"
    second.close()
