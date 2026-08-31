"""Тесты whitelist (``aiav.trustlist``) — механизм против ложных срабатываний."""

from __future__ import annotations

import pytest

from aiav.trustlist import Trustlist


@pytest.fixture()
def trustlist(tmp_path) -> Trustlist:
    return Trustlist(
        path=tmp_path / "trustlist.json",
        trusted_prefixes=("/trusted",),
    )


def test_trusted_path_prefix(trustlist: Trustlist) -> None:
    assert trustlist.is_trusted_path("/trusted/game/launcher.exe")
    assert not trustlist.is_trusted_path("/home/user/Downloads/x.exe")


def test_trust_file_by_hash(trustlist: Trustlist, benign_exe) -> None:
    digest = trustlist.trust_file(benign_exe)
    assert trustlist.is_trusted_hash(digest)
    assert trustlist.is_trusted_hash(digest.upper())  # регистр не важен
    assert not trustlist.is_trusted_hash("b" * 64)


def test_untrust_removes(trustlist: Trustlist, benign_exe) -> None:
    digest = trustlist.trust_file(benign_exe)
    assert trustlist.untrust(digest) is True
    assert trustlist.is_trusted_hash(digest) is False
    assert trustlist.untrust(digest) is False  # второй раз — нечего удалять


def test_add_path_prefix(trustlist: Trustlist) -> None:
    trustlist.trust_path_prefix("/games")
    assert trustlist.is_trusted_path("/games/steam/thing.exe")


def test_persistence(tmp_path, benign_exe) -> None:
    """Список переживает пересоздание объекта (JSON на диске)."""
    path = tmp_path / "trust.json"
    first = Trustlist(path=path, trusted_prefixes=())
    digest = first.trust_file(benign_exe)

    second = Trustlist(path=path, trusted_prefixes=())
    assert second.is_trusted_hash(digest)
    assert second.stats()["hashes"] == 1


def test_corrupted_json_is_not_fatal(tmp_path) -> None:
    path = tmp_path / "trust.json"
    path.write_text("{ broken", encoding="utf-8")
    trustlist = Trustlist(path=path, trusted_prefixes=())
    assert trustlist.stats() == {"hashes": 0, "paths": 0}


def test_dump(trustlist: Trustlist, benign_exe) -> None:
    digest = trustlist.trust_file(benign_exe)
    data = trustlist.dump()
    assert data["hashes"] == [digest]
    assert data["paths"] == []
