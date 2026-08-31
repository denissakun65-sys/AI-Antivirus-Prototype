"""
Автономное обучение из интернета — команда ``autolearn`` (алиас ``overnight``).

Модуль реализует непрерывную фоновую сессию обучения: запустил — работает,
остановил (Ctrl+C) — прогресс и улучшенная модель сохранены. Число эпох
не ограничено. Важно понимать, ЧТО именно скачивается (проект никогда не
загружает образцы malware и антивирусное ПО):

1. **EMBER** (``ember.elastic.co``) — публичный датасет от Elastic:
   уже ИЗВЛЕЧЁННЫЕ признаки ~1 млн реальных PE-файлов с метками,
   полученными консенсусом движков VirusTotal. Самих файлов там нет —
   только статистика заголовков/секций/импортов. Мы конвертируем каждую
   запись в нашу схему из 46 признаков и получаем готовую обучающую выборку.

2. **Легальные benign-бинарники** — установщики популярных open-source
   программ с их официальных сайтов (7-Zip, PuTTY, WinMerge, SumatraPDF,
   Nmap). Они пополняют «чистый» класс реальными, подписанными файлами
   вместо синтетики.

Каждые ``retrain_every`` строк модель переобучается; основная модель
заменяется только если CV-F1 новой стал ЛУЧше — худшая модель никогда
не затрёт хорошую. Когда все источники прочитаны, сессия переходит
в эпохальный режим: подтягивает свежие консенсус-метки из ``scan --learn``
и продолжает переобучение на новых случайных перестановках — бесконечно,
пока её не остановят.

Примеры::

    python main.py autolearn                       # до Ctrl+C, эпохи без предела
    python main.py autolearn --until 07:00         # остановка к 7 утра
    python main.py autolearn --backend lightgbm    # быстрее на больших данных
"""

from __future__ import annotations

import bz2  # noqa: F401  (используется tarfile прозрачно)
import csv
import gzip
import json
import logging
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aiav.config import (
    DEFAULT_BACKEND,
    DEFAULT_MODEL_FILENAME,
    DISTILL_PATH,
    EMBER_SAMPLE_CSV,
    EMBER_URL,
    MALICIOUS_THRESHOLD,
    MODELS_DIR,
    NIGHTLY_CSV,
    NIGHTLY_STATUS,
    PROJECT_ROOT,
    RANDOM_STATE,
)
from aiav.features import (
    _API_GROUPS,
    FEATURE_NAMES,
    SUSPICIOUS_APIS,
    PEFeatureError,
    extract_pe_features,
    is_pe_file,
    sha256_of,
)
from aiav.model import MalwareClassifier, ModelBundle

logger = logging.getLogger("aiav.overnight")

#: Официальные источники легальных PE-файлов для benign-класса.
#: Только официальные сайты/релизы проектов; версия в URL зафиксирована,
#: чтобы загрузки были воспроизводимыми.
DEFAULT_BENIGN_SOURCES: tuple[tuple[str, str], ...] = (
    ("7-Zip 24.08 x64", "https://www.7-zip.org/a/7z2408-x64.exe"),
    ("PuTTY (latest w64)", "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe"),
    ("WinMerge 2.16.40 x64",
     "https://github.com/WinMerge/winmerge/releases/download/v2.16.40/WinMerge-2.16.40-x64-setup.exe"),
    ("SumatraPDF 3.5.2 x64",
     "https://www.sumatrapdfreader.org/dl/rel/3.5.2/SumatraPDF-3.5.2-64-install.exe"),
    ("Nmap 7.95 installer", "https://nmap.org/dist/nmap-7.95-setup.exe"),
)

#: Потолок размера одного скачивания (защита от «резиновых» ответов).
MAX_DOWNLOAD_BYTES = 3 * 1024 * 1024 * 1024  # 3 ГБ — весь EMBER влазит

#: Стандартные размеры optional header (для импутации признаков,
#: которых нет в EMBER).
_SIZEOF_OPT_HEADER_PE32 = 96.0
_SIZEOF_OPT_HEADER_PE64 = 224.0

#: Тип сетевой функции-«открывателя» (подменяется в тестах).
Opener = Callable[..., Any]

#: HTTP-коды, которые сами не проходят (блокировка региона, нет файла и т.п.) —
#: повторять запрос бессмысленно, источник отключается сразу.
_PERMANENT_HTTP_CODES: frozenset[int] = frozenset({401, 403, 404, 405, 410, 451})


class PermanentDownloadError(OSError):
    """Постоянная ошибка скачивания — повторы не помогут (403/404/451…)."""


# --------------------------------------------------------------------------- #
# Настройки и состояние ночной сессии
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class NightSettings:
    """Параметры сессии автономного обучения (логируются при старте).

    :ivar deadline: ``None`` — работать бесконечно, пока не остановят.
    :ivar epochs: ``None`` — число эпох не ограничено.
    :ivar epoch_pause: пауза между эпохами, сек (даёт машине «подышать»).
    """

    deadline: datetime | None = None
    epochs: int | None = None
    epoch_pause: float = 60.0
    csv_path: Path = NIGHTLY_CSV
    model_path: Path = MODELS_DIR / DEFAULT_MODEL_FILENAME
    backend: str = DEFAULT_BACKEND
    retrain_every: int = 10_000
    max_rows: int = 0  # 0 — без лимита строк
    use_ember: bool = True
    ember_url: str = EMBER_URL
    ember_sample_path: Path = EMBER_SAMPLE_CSV
    distill_path: Path = DISTILL_PATH
    downloads_dir: Path = PROJECT_ROOT / "data" / "nightly" / "downloads"
    state_path: Path = PROJECT_ROOT / "data" / "nightly" / "state.json"
    ember_tar_path: Path = PROJECT_ROOT / "data" / "nightly" / "ember_dataset.tar.bz2"
    status_path: Path = NIGHTLY_STATUS
    benign_sources: Sequence[tuple[str, str]] = DEFAULT_BENIGN_SOURCES
    threshold: float = MALICIOUS_THRESHOLD
    #: Базовая пауза после ошибки сбора (растёт линейно: 60 c, 120 c, …).
    retry_backoff: float = 60.0
    #: После стольких ошибок подряд EMBER отключается до конца запуска.
    ember_fail_limit: int = 5
    opener: Opener = urllib.request.urlopen  # точка подмены для тестов


@dataclass(slots=True)
class NightState:
    """
    Состояние сессии — переживает перезапуски (JSON на диске).

    :ivar ember_lines: сколько строк уже обработано в каждом .jsonl архива
        (ключ — имя участника tar). Позволяет не обрабатывать одно и то же
        дважды между запусками.
    :ivar seen_hashes: SHA-256, добавленные в текущей сессии (дедупликация).
    :ivar rows_added: всего строк добавлено в ночной CSV.
    :ivar retrains: сколько переобучений выполнено.
    :ivar benign_done: фаза benign-скачиваний завершена.
    """

    path: Path
    ember_lines: dict[str, int] = field(default_factory=dict)
    seen_hashes: set[str] = field(default_factory=set)
    rows_added: int = 0
    retrains: int = 0
    benign_done: bool = False
    epochs: int = 0
    distill_merged: int = 0        # сколько строк DISTILL уже перенесено
    ember_exhausted: bool = False  # EMBER прочитан целиком
    rows_trained: int = 0          # строк в CSV на момент последней тренировки
    ember_sample_done: bool = False  # локальная выборка EMBER влита
    ember_sample_merged: int = 0     # строк локальной выборки уже влито

    @classmethod
    def load(cls, path: str | Path) -> NightState:
        path = Path(path)
        state = cls(path=path)
        try:
            if path.is_file():
                raw = json.loads(path.read_text(encoding="utf-8"))
                state.ember_lines = dict(raw.get("ember_lines", {}))
                state.seen_hashes = set(raw.get("seen_hashes", []))
                state.rows_added = int(raw.get("rows_added", 0))
                state.retrains = int(raw.get("retrains", 0))
                state.benign_done = bool(raw.get("benign_done", False))
                state.epochs = int(raw.get("epochs", 0))
                state.distill_merged = int(raw.get("distill_merged", 0))
                state.ember_exhausted = bool(raw.get("ember_exhausted", False))
                state.rows_trained = int(raw.get("rows_trained", 0))
                state.ember_sample_done = bool(raw.get("ember_sample_done", False))
                state.ember_sample_merged = int(raw.get("ember_sample_merged", 0))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("Состояние повреждено (%s) — начинаем с чистого", exc)
        return state

    def save(self) -> None:
        payload = {
            "ember_lines": self.ember_lines,
            "seen_hashes": sorted(self.seen_hashes),
            "rows_added": self.rows_added,
            "retrains": self.retrains,
            "benign_done": self.benign_done,
            "epochs": self.epochs,
            "distill_merged": self.distill_merged,
            "ember_exhausted": self.ember_exhausted,
            "rows_trained": self.rows_trained,
            "ember_sample_done": self.ember_sample_done,
            "ember_sample_merged": self.ember_sample_merged,
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as exc:
            logger.warning("Не удалось сохранить состояние: %s", exc)


# --------------------------------------------------------------------------- #
# Скачивание файлов
# --------------------------------------------------------------------------- #


def download_file(
    url: str,
    dest: Path,
    *,
    timeout: int = 120,
    opener: Opener = urllib.request.urlopen,
    progress_log_every: float = 60.0,
) -> Path:
    """
    Скачивает ``url`` в ``dest`` с поддержкой докачки (HTTP Range).

    Докачка важна для EMBER (~2 ГБ): обрыв сети ночью не обнуляет прогресс.
    Возвращает путь к файлу; бросает OSError/URLError при сетевых сбоях.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    resume_at = dest.stat().st_size if dest.exists() else 0

    request = urllib.request.Request(url, headers={"User-Agent": "aiav-prototype/0.2"})
    if resume_at:
        request.add_header("Range", f"bytes={resume_at}-")
        logger.info("Докачка %s с %d байт…", url, resume_at)

    try:
        response = opener(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        message = f"не удалось открыть {url}: HTTP Error {exc.code}: {exc.reason}"
        if exc.code in _PERMANENT_HTTP_CODES:
            raise PermanentDownloadError(message) from exc
        raise OSError(message) from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise OSError(f"не удалось открыть {url}: {exc}") from exc

    with response:
        # 206 Partial Content — сервер поддержал Range, дописываем хвост.
        append = resume_at > 0 and getattr(response, "status", 200) == 206
        mode = "ab" if append else "wb"
        if not append and resume_at:
            logger.warning("Сервер не поддержал докачку — качаем заново")
        total = 0
        last_log = time.monotonic()
        with open(dest, mode) as handle:
            while True:
                chunk = response.read(1024 * 512)
                if not chunk:
                    break
                total += len(chunk)
                if resume_at + total > MAX_DOWNLOAD_BYTES:
                    raise OSError(f"превышен лимит {MAX_DOWNLOAD_BYTES} байт для {url}")
                handle.write(chunk)
                now = time.monotonic()
                if now - last_log >= progress_log_every:
                    logger.info("  …%s: %.1f МБ", dest.name, (resume_at + total) / 1024 / 1024)
                    last_log = now
    logger.info("Скачано: %s (%.1f МБ)", dest.name, (resume_at + total) / 1024 / 1024)
    return dest


class BenignCollector:
    """
    Качает легальные PE-файлы с официальных сайтов и извлекает признаки.

    Это реальные подписанные бинарники популярных open-source проектов —
    «чистый» класс, максимально близкий к софту на машине пользователя.
    """

    def __init__(
        self,
        settings: NightSettings,
        state: NightState,
        sources: Sequence[tuple[str, str]] | None = None,
    ) -> None:
        self.settings = settings
        self.state = state
        self.sources = sources if sources is not None else settings.benign_sources

    def collect_once(self) -> list[tuple[dict[str, float], int, str, str]]:
        """
        Один проход по источникам.

        :returns: список кортежей ``(признаки, метка=0, sha256, имя)``;
            неудачи отдельных источников не прерывают остальные.
        """
        rows: list[tuple[dict[str, float], int, str, str]] = []
        for name, url in self.sources:
            try:
                dest = self.settings.downloads_dir / Path(url).name
                if dest.exists() and dest.stat().st_size == 0:
                    dest.unlink()  # битый недокачанный файл
                if not dest.exists():
                    download_file(url, dest, opener=self.settings.opener)
                if not is_pe_file(dest):
                    logger.warning("%s: не PE-файл, пропуск", name)
                    continue
                digest = sha256_of(dest)
                if digest in self.state.seen_hashes:
                    logger.debug("%s: уже обработан, пропуск", name)
                    continue
                features = extract_pe_features(dest)
                rows.append((features.values, 0, digest, name))
                self.state.seen_hashes.add(digest)
                logger.info("Benign-образец добавлен: %s", name)
            except (OSError, PEFeatureError) as exc:
                logger.warning("Benign-источник %s недоступен: %s", name, exc)
        return rows


# --------------------------------------------------------------------------- #
# Конвертер EMBER -> наша схема из 46 признаков
# --------------------------------------------------------------------------- #


def _entropy_from_histogram(histogram: Sequence[int]) -> float:
    """Точная энтропия Шеннона по 256-корзиночному гистограммному профилю."""
    import math  # локальный импорт: функция вызывается построчно, math дешёв

    total = sum(histogram)
    if not total:
        return 0.0
    entropy = 0.0
    for count in histogram:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 6)


def ember_record_to_features(record: dict[str, Any]) -> dict[str, float] | None:
    """
    Конвертирует одну запись EMBER (2017/2018 slim-схема) в наши 46 признаков.

    Схема EMBER содержит готовые заголовки, секции с энтропией и полные
    списки импортов — этого достаточно, чтобы восстановить большинство
    наших признаков без самого файла. Признаки, которых в EMBER нет
    (entry point, оверлей, чексумма, объём ресурсов), импутируются
    консервативными значениями — это осознанный компромисс дистилляции.

    :returns: словарь имя-признака -> значение либо ``None``, если запись
        не похожа на валидную (нет header/section/label).
    """
    try:
        label = int(record.get("label", -1))
        if label not in (0, 1):
            return None
        general = record.get("general") or {}
        header = record.get("header") or {}
        coff = header.get("coff") or {}
        optional = header.get("optional") or {}
        sections = (record.get("section") or {}).get("sections") or []
        imports_map: dict[str, list[str]] = record.get("imports") or {}

        values: dict[str, float] = dict.fromkeys(FEATURE_NAMES, 0.0)

        # --- геометрия (реальные значения из EMBER) ---
        raw_size = float(general.get("size", 0) or 0)
        virtual_size = float(general.get("vsize", 0) or 0)
        values["raw_size"] = raw_size
        values["virtual_size"] = virtual_size
        values["header_size"] = float(optional.get("sizeof_headers", 0) or 0)
        values["size_of_code"] = float(optional.get("sizeof_code", 0) or 0)
        values["num_sections"] = float(len(sections))
        values["num_symbols"] = float(general.get("symbols", 0) or 0)
        values["ratio_raw_to_virtual"] = (
            round(raw_size / virtual_size, 6) if virtual_size else 0.0
        )

        # --- импорты (реальные значения: у нас есть имена функций!) ---
        func_count = 0
        for functions in imports_map.values():
            func_count += len(functions)
        values["num_imports_dll"] = float(len(imports_map))
        values["num_imports_funcs"] = float(func_count or general.get("imports", 0) or 0)
        values["has_imports"] = 1.0 if func_count or general.get("imports") else 0.0

        suspicious_total = 0
        for functions in imports_map.values():
            for name in functions:
                if name.startswith("ordinal"):
                    continue  # импорт по ординалу — имени нет
                for feature_name, api_set in _API_GROUPS.items():
                    if name in api_set:
                        values[feature_name] += 1.0
                if name in SUSPICIOUS_APIS:
                    suspicious_total += 1
        values["imports_suspicious_count"] = float(suspicious_total)

        # --- энтропия: точная из гистограммы + секции ---
        histogram = record.get("histogram") or []
        if histogram:
            values["entropy_overall"] = _entropy_from_histogram(histogram)
        if sections:
            entropies = [float(s.get("entropy", 0.0)) for s in sections]
            values["entropy_min_section"] = round(min(entropies), 6)
            values["entropy_max_section"] = round(max(entropies), 6)
            values["entropy_mean_section"] = round(sum(entropies) / len(entropies), 6)
            mean = values["entropy_mean_section"]
            variance = sum((e - mean) ** 2 for e in entropies) / len(entropies)
            values["entropy_std_section"] = round(variance**0.5, 6)

            max_gap = 0.0
            for section in sections:
                gap = float(section.get("vsize", 0) or 0) - float(section.get("size", 0) or 0)
                max_gap = max(max_gap, gap)
            values["max_section_virtual_raw_gap"] = max_gap

            for section in sections:
                sname = str(section.get("name", "")).upper()
                if sname in ("UPX0", "UPX1", "UPX2") or sname.startswith("UPX"):
                    values["is_upx_packed"] = 1.0
                    break

        # --- флаги (реальные значения) ---
        characteristics = coff.get("characteristics") or []
        if isinstance(characteristics, int):  # старые дампы дают число
            values["is_dll"] = float(bool(characteristics & 0x2000))
            values["is_driver"] = float(bool(characteristics & 0x1000))
        else:
            names = {str(c).upper() for c in characteristics}
            values["is_dll"] = float("DLL" in names)
            values["is_driver"] = float("SYSTEM" in names)

        magic = str(optional.get("magic", "")).upper()
        machine = str(coff.get("machine", "")).upper()
        values["is_64bit"] = float(magic == "PE32+" or machine in ("AMD64", "X64", "X86_64"))
        values["has_debug_directory"] = float(bool(general.get("has_debug")))
        values["has_tls_callbacks"] = float(bool(general.get("has_tls")))
        values["has_relocations"] = float(bool(general.get("has_relocations")))
        values["has_signature"] = float(bool(general.get("has_signature")))
        values["has_resources"] = float(bool(general.get("has_resources")))

        # --- анатомия data directories (если присутствует в записи) ---
        datadirs = record.get("datadirectories") or record.get("datadirs") or []
        # Каталог считается заполненным, если указан адрес ИЛИ размер
        # (у OVERLAY-записи адрес часто нулевой — это данные после секций).
        dir_types = {str(d.get("type", "")).upper(): d for d in datadirs
                     if isinstance(d, dict) and (d.get("virtual_address") or d.get("size"))}
        values["num_data_directories"] = float(len(dir_types)) if dir_types else float(
            # консервативная оценка по флагам, если каталога нет в записи
            bool(general.get("imports")) + bool(general.get("has_resources"))
            + bool(general.get("has_signature")) + bool(general.get("has_tls"))
            + bool(general.get("has_debug")) + bool(general.get("exports"))
        )
        overlay = dir_types.get("OVERLAY")
        if overlay:
            values["overlay_size"] = float(overlay.get("size", 0) or 0)
        values["has_exceptions"] = float("EXCEPTION" in dir_types) if dir_types else 0.0

        # --- импутация того, чего в EMBER нет (осознанный компромисс) ---
        values["size_of_optional_header"] = (
            _SIZEOF_OPT_HEADER_PE64 if values["is_64bit"] else _SIZEOF_OPT_HEADER_PE32
        )
        values["num_tls_callbacks"] = values["has_tls_callbacks"]  # обычно 1 callback
        values["num_resources"] = values["has_resources"]          # >=1, точное число неизвестно
        # entrypoint_offset, overlay_size (без datadirs), resources_total_bytes,
        # size_of_initialized/uninitialized_data, checksum_mismatch остаются 0.0

        # --- аномалии заголовков (частично воспроизводимы) ---
        anomalies = 0
        if virtual_size and virtual_size < values["header_size"]:
            anomalies += 1
        if not sections:
            anomalies += 1
        values["is_header_anomalous"] = float(anomalies > 0)

        return values
    except (AttributeError, TypeError, ValueError) as exc:
        logger.debug("Запись EMBER отброшена: %s", exc)
        return None


# --------------------------------------------------------------------------- #
# Потоковое чтение EMBER-архива
# --------------------------------------------------------------------------- #


class EmberStream:
    """
    Последовательно читает ``.jsonl``-участников из ``.tar.bz2`` EMBER.

    Архив распаковывается потоково (без полного извлечения на диск),
    прогресс по каждому .jsonl сохраняется в :class:`NightState` —
    повторный запуск продолжает с того же места.
    """

    def __init__(self, settings: NightSettings, state: NightState) -> None:
        self.settings = settings
        self.state = state

    def ensure_downloaded(self) -> Path:
        """
        Даёт локальный путь к архиву.

        Порядок: уже скачанный файл -> ``ember_url`` как локальный путь
        (можно скормить вручную скачанный архив) -> докачка из интернета.
        """
        tar_path = self.settings.ember_tar_path
        if tar_path.exists() and tar_path.stat().st_size > 0:
            logger.info("EMBER-архив уже на диске: %s", tar_path)
            return tar_path
        local = Path(self.settings.ember_url).expanduser()
        if local.is_file():
            logger.info("EMBER-архив взят с локального пути: %s", local)
            return local
        return download_file(self.settings.ember_url, tar_path,
                             timeout=300, opener=self.settings.opener)

    def iter_records(self) -> Iterator[tuple[str, int, dict[str, float]]]:
        """
        Итератор ``(sha256, label, признаки)`` по всем размеченным записям.

        Неразмеченные записи (label = -1) и битые строки пропускаются.
        """
        tar_path = self.ensure_downloaded()
        try:
            with tarfile.open(tar_path, "r:bz2") as archive:
                for member in archive:
                    if not member.isfile() or not member.name.endswith(".jsonl"):
                        continue
                    done = self.state.ember_lines.get(member.name, 0)
                    handle = archive.extractfile(member)
                    if handle is None:
                        continue
                    logger.info("Читаю %s (пропущено обработанных: %d)…", member.name, done)
                    with handle:
                        for line_no, line in enumerate(handle):
                            if line_no < done:
                                continue
                            try:
                                record = json.loads(line)
                            except (UnicodeDecodeError, json.JSONDecodeError):
                                continue  # обрезанная последняя строка и т.п.
                            self.state.ember_lines[member.name] = line_no + 1
                            values = ember_record_to_features(record)
                            if values is None:
                                continue
                            sha256 = str(record.get("sha256", ""))
                            if sha256 in self.state.seen_hashes:
                                continue
                            self.state.seen_hashes.add(sha256)
                            yield sha256, int(record["label"]), values
                    logger.info("Завершён %s: обработано до строки %d",
                                member.name, self.state.ember_lines.get(member.name, 0))
        except (tarfile.TarError, OSError) as exc:
            raise OSError(f"EMBER-архив повреждён или не докачан: {exc}") from exc


# --------------------------------------------------------------------------- #
# Ночной тренер
# --------------------------------------------------------------------------- #

_CSV_HEADER = ("path", "sha256", "size", *FEATURE_NAMES, "label")


def _append_rows(
    csv_path: Path, rows: Sequence[tuple[dict[str, float], int, str, str]]
) -> None:
    """Дописывает строки в ночной CSV (тот же формат, что у ``train --csv``)."""
    if not rows:
        return
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not csv_path.exists() or csv_path.stat().st_size == 0
    with open(csv_path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if write_header:
            writer.writerow(_CSV_HEADER)
        for values, label, sha256, name in rows:
            writer.writerow([name, sha256, int(values.get("raw_size", 0))]
                            + [values[f] for f in FEATURE_NAMES] + [label])


class NightTrainer:
    """
    Оркестратор ночной сессии: сбор данных -> периодическое переобучение.

    Ключевое правило: основная модель заменяется ТОЛЬКО если новая лучше
    по CV-F1. Ночной эксперимент никогда не ухудшит боевую модель.
    """

    def __init__(self, settings: NightSettings) -> None:
        self.settings = settings
        self.state = NightState.load(settings.state_path)
        self._rows_since_retrain = 0
        self._started = datetime.now(timezone.utc)
        self._ember_disabled = False     # EMBER отключён после серии ошибок
        self._consecutive_failures = 0   # ошибки сбора подряд (для бэкоффа)
        self._best_cv: float | None = None  # кэш CV-F1 текущей модели

    # -- публичный API ------------------------------------------------------ #

    def run(self) -> int:
        """
        Главный цикл эпох. Возвращает код возврата CLI (0 — штатно).

        Эпоха 1: сбор данных (benign + EMBER) с периодическим переобучением.
        Эпохи 2..N: подтягивание свежих консенсус-меток из ``scan --learn``
        и повторное переобучение на новых случайных перестановках — модель
        продолжает «дозревать», даже когда все источники уже прочитаны.
        Цикл бесконечен, если не заданы ``--epochs`` / ``--hours`` / ``--until``;
        штатная остановка — Ctrl+C (прогресс сохраняется, модель дообучается).
        """
        settings = self.settings
        logger.info("=" * 62)
        logger.info("АВТОНОМНАЯ СЕССИЯ ОБУЧЕНИЯ")
        logger.info("  остановка      : %s",
                    settings.deadline.isoformat(timespec="seconds")
                    if settings.deadline else "только вручную (Ctrl+C)")
        logger.info("  эпохи          : %s", settings.epochs or "без ограничений")
        logger.info("  CSV датасет    : %s", settings.csv_path)
        logger.info("  модель         : %s (backend=%s)", settings.model_path, settings.backend)
        logger.info("  EMBER          : %s", "вкл" if settings.use_ember else "выкл")
        logger.info("  переобучение   : каждые %d строк, лимит строк: %s",
                    settings.retrain_every, settings.max_rows or "без лимита")
        logger.info("  строк в CSV    : %d (с прошлых запусков)", self.state.rows_added)
        logger.info("=" * 62)

        self._best_cv = self._current_cv_f1()
        self._write_status("старт")
        try:
            while not self._time_is_up():
                epoch = self._begin_epoch()
                collection_failed = False
                rows_before = self.state.rows_added
                try:
                    if self._collection_incomplete():
                        self._phase_benign()
                        if settings.use_ember and not self._ember_disabled:
                            self._phase_ember()
                    self._phase_merge_distill()
                    if self.state.rows_added != rows_before:
                        self._retrain(force=True, epoch=epoch)
                    else:
                        # быстрая эпоха: данных не прибавилось — тренировать нечего
                        logger.info("Новых данных нет — переобучение пропущено")
                except KeyboardInterrupt:
                    raise
                except (OSError, tarfile.TarError) as exc:
                    collection_failed = True
                    self._consecutive_failures += 1
                    logger.error("Сбор данных прерван ошибкой: %s", exc)
                    self._handle_collection_failure(exc)
                else:
                    self._consecutive_failures = 0
                self.state.save()

                if settings.epochs and epoch >= settings.epochs:
                    break
                if self._time_is_up():
                    break

                if collection_failed and self._collection_incomplete():
                    # БЭКОФФ: не долбим источник ошибками — ждём всё дольше.
                    # (Если источник только что отключён — ждать незачем,
                    #  повторять нечего: следующая эпоха пойдёт сразу.)
                    pause = settings.retry_backoff * self._consecutive_failures
                    logger.warning("Пауза %.0f c перед повтором (ошибок подряд: %d)",
                                   pause, self._consecutive_failures)
                    self._write_status(f"ожидание повтора ({pause:.0f} c)")
                    if not self._sleep_responsive(min(pause, 3600.0)):
                        break
                elif not self._collection_incomplete() and settings.epoch_pause > 0:
                    logger.info("Все источники прочитаны — пауза %.0f c до следующей эпохи",
                                settings.epoch_pause)
                    self._write_status("пауза между эпохами")
                    if not self._sleep_responsive(settings.epoch_pause):
                        break
        except KeyboardInterrupt:
            raise
        finally:
            # «выключили» — дообучаем модель, если собраны не все строки
            if self.state.rows_added != self.state.rows_trained:
                self._retrain(force=True, epoch=self.state.epochs)
            self.state.save()
            self._write_status("остановлено", running=False)
            self._print_summary()
        return 0

    def _begin_epoch(self) -> int:
        """Открывает новую эпоху: счётчик, лог, статус. Возвращает её номер."""
        self.state.epochs += 1
        logger.info("--- ЭПОХА %d ---", self.state.epochs)
        self._write_status(f"эпоха {self.state.epochs}")
        return self.state.epochs

    def _handle_collection_failure(self, exc: Exception) -> None:
        """
        Политика отказов: постоянные ошибки (403/451/404) отключают EMBER
        СРАЗУ — повторять их бессмысленно; временные (сеть, таймауты)
        получают бэкофф и отключение только после серии неудач.
        """
        if not isinstance(exc, PermanentDownloadError) \
                and self._consecutive_failures < self.settings.ember_fail_limit:
            return
        if self._ember_disabled or not self.settings.use_ember:
            return
        self._ember_disabled = True
        logger.warning("=" * 62)
        logger.warning("EMBER отключён до конца запуска (%s)",
                       "постоянная ошибка — повторы бессмысленны"
                       if isinstance(exc, PermanentDownloadError)
                       else f"{self._consecutive_failures} ошибок подряд")
        logger.warning("Последняя ошибка: %s", exc)
        logger.warning("Возможные причины и решения:")
        logger.warning("  • HTTP 403/451 — CDN elastic.co блокирует ваш регион.")
        logger.warning("    Официальное зеркало (торрент): academictorrents.com,")
        logger.warning("    раздача 34854ec5114020b33224cedc97fe78731d057df4 (1.7 ГБ).")
        logger.warning("    Скачанный файл положите сюда: %s", self.settings.ember_tar_path)
        logger.warning("    (или откройте напрямую: %s)", self.settings.ember_url)
        logger.warning("  • или задайте зеркало: --ember-url <URL> (или AIAV_EMBER_URL)")
        logger.warning("Сессия продолжит работу: benign-источники, метки scan --learn")
        logger.warning("и переобучение накопленных данных.")
        logger.warning("=" * 62)

    def _collection_incomplete(self) -> bool:
        """Есть ли ещё непрочитанные источники данных?"""
        if not self.state.benign_done:
            return True
        if not self.settings.use_ember or self._ember_disabled:
            return False
        if self.settings.ember_sample_path.is_file() and not self.state.ember_sample_done:
            return True  # локальная выборка из репозитория ещё не влита
        return not self.state.ember_exhausted

    def _sleep_responsive(self, seconds: float) -> bool:
        """Спит, но следит за дедлайном. False — время вышло."""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self._time_is_up():
                return False
            time.sleep(min(5.0, end - time.monotonic()))
        return True

    def _write_status(self, phase: str = "", running: bool = True) -> None:
        """
        Пишет живой статус в ``status.json`` — его читает отдельное окно
        ``python main.py autolearn-status --watch``.

        Ошибки записи не фатальны: статус — удобство, а не часть конвейера.
        """
        now = datetime.now(timezone.utc)
        payload = {
            "running": running,
            "started_at": self._started.isoformat(timespec="seconds"),
            "elapsed_sec": round((now - self._started).total_seconds(), 1),
            "epochs": self.state.epochs,
            "rows_added": self.state.rows_added,
            "retrains": self.state.retrains,
            "phase": phase,
            "cv_f1": self._best_cv,
            "updated_at": now.isoformat(timespec="seconds"),
        }
        try:
            self.settings.status_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.settings.status_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.settings.status_path)
        except OSError as exc:
            logger.debug("Не удалось записать статус: %s", exc)

    # -- фазы --------------------------------------------------------------- #

    def _phase_benign(self) -> None:
        """Фаза 1: легальные benign-бинарники с официальных сайтов."""
        if self.state.benign_done:
            logger.info("Benign-фаза уже выполнена ранее — пропускаю")
            return
        logger.info("--- ФАЗА 1/2: легальные open-source бинарники (benign) ---")
        collector = BenignCollector(self.settings, self.state)
        rows = collector.collect_once()
        _append_rows(self.settings.csv_path, rows)
        self.state.rows_added += len(rows)
        self._rows_since_retrain += len(rows)
        self.state.benign_done = True
        self.state.save()
        logger.info("Benign-фаза завершена: +%d строк", len(rows))

    def _phase_merge_distill(self) -> None:
        """
        Подтягивает свежие строки из ``scan --learn`` (DISTILL_PATH).

        Так дневные сканирования с облачным консенсусом движков продолжают
        питать автономное обучение: каждая эпоха забирает только новые строки.
        """
        distill = self.settings.distill_path
        if not distill.is_file():
            return
        try:
            with open(distill, newline="", encoding="utf-8") as handle:
                reader = csv.reader(handle)
                rows = list(reader)
        except OSError as exc:
            logger.warning("Не удалось прочитать %s: %s", distill, exc)
            return
        if not rows:
            return
        header, body = rows[0], rows[1:]
        merged = self.state.distill_merged
        fresh = body[merged:]
        if not fresh:
            return
        if header[:2] != ["path", "sha256"] or header[-1] != "label":
            logger.warning("%s: неожиданный формат — слияние пропущено", distill)
            return
        added = 0
        for row in fresh:
            try:
                values = dict(zip(FEATURE_NAMES,
                                  (float(v) for v in row[3:3 + len(FEATURE_NAMES)]),
                                  strict=True))
                label = int(row[-1])
                sha256 = row[1]
            except (ValueError, IndexError):
                continue
            _append_rows(self.settings.csv_path, [(values, label, sha256, row[0])])
            self.state.rows_added += 1
            added += 1
        self.state.distill_merged = len(body)
        if added:
            logger.info("Из scan --learn подтянуто новых меток: %d", added)

    def _merge_ember_sample(self) -> bool:
        """
        Вливает готовую выборку EMBER из репозитория (без сети!).

        Файл ``datasets/ember_2018_sample.csv.gz`` — заранее конвертированные
        признаки реальных PE из EMBER 2018 (метки — консенсус VirusTotal).
        Это основной путь для регионов, где CDN elastic.co блокирует
        скачивание полного архива (HTTP 403).

        :returns: ``True`` — выборка влита полностью (или отсутствует),
            можно переходить к полному архиву; ``False`` — прервались
            по дедлайну/лимиту, продолжим в следующей эпохе.
        """
        sample = self.settings.ember_sample_path
        if not sample.is_file() or self.state.ember_sample_done:
            return True
        logger.info("--- ФАЗА 2/2: локальная выборка EMBER (%s) ---", sample.name)
        self._write_status("EMBER-выборка: слияние")

        merged_now = 0
        buffer: list[tuple[dict[str, float], int, str, str]] = []
        try:
            with gzip.open(sample, "rt", encoding="utf-8", newline="") as handle:
                reader = csv.reader(handle)
                header = next(reader, None)
                if not header or header[:2] != ["path", "sha256"] or header[-1] != "label":
                    logger.warning("%s: неожиданный формат — пропущен", sample)
                    self.state.ember_sample_done = True
                    return True
                for row_no, row in enumerate(reader):
                    if row_no < self.state.ember_sample_merged:
                        continue  # возобновление: уже влитые строки не трогаем
                    try:
                        values = dict(zip(
                            FEATURE_NAMES,
                            (float(v) for v in row[3:3 + len(FEATURE_NAMES)]),
                            strict=True))
                        label = int(row[-1])
                        sha256 = row[1]
                    except (ValueError, IndexError):
                        continue
                    buffer.append((values, label, sha256, row[0]))
                    if len(buffer) >= 2_000:
                        self._flush(buffer)
                        buffer.clear()
                        merged_now += 2_000
                        limit = self.settings.max_rows
                        if self._time_is_up() or (limit and self.state.rows_added >= limit):
                            return False
            if buffer:
                self._flush(buffer)
                merged_now += len(buffer)
        except OSError as exc:
            logger.error("Не удалось прочитать выборку %s: %s", sample, exc)
            self.state.ember_sample_done = True  # битый файл не перечитываем бесконечно
            return True

        self.state.ember_sample_done = True
        logger.info("Локальная выборка EMBER влита полностью: +%d строк", merged_now)
        return True

    def _phase_ember(self) -> None:
        """Фаза 2: EMBER — сначала локальная выборка, затем полный архив."""
        if not self._merge_ember_sample():
            return  # дедлайн/лимит — полный архив подождёт до следующей эпохи
        logger.info("--- ФАЗА 2/2: EMBER (признаки ~1 млн реальных PE) ---")
        self._write_status("EMBER: скачивание/чтение архива")
        stream = EmberStream(self.settings, self.state)
        buffer: list[tuple[dict[str, float], int, str, str]] = []
        flush_every = 2_000
        exhausted = True

        for sha256, label, values in stream.iter_records():
            buffer.append((values, label, sha256, f"ember:{sha256[:16]}"))
            if len(buffer) >= flush_every:
                self._flush(buffer)
                buffer.clear()
            limit = self.settings.max_rows
            if self._time_is_up() or (limit and self.state.rows_added >= limit):
                exhausted = False
                break
        if buffer:
            self._flush(buffer)
        if exhausted:
            self.state.ember_exhausted = True
            logger.info("EMBER прочитан полностью (%d строк всего)", self.state.rows_added)

    def _flush(self, buffer: list[tuple[dict[str, float], int, str, str]]) -> None:
        _append_rows(self.settings.csv_path, buffer)
        self._write_status(f"EMBER: собрано {self.state.rows_added + len(buffer)} строк")
        self.state.rows_added += len(buffer)
        self._rows_since_retrain += len(buffer)
        if self.state.rows_added % 20_000 < 2_000:  # периодический чекпойнт
            self.state.save()
        if self._rows_since_retrain >= self.settings.retrain_every:
            # эпохи идут и во время сбора: «собрал 10k -> обучил» = эпоха
            self._begin_epoch()
            self._retrain(epoch=self.state.epochs)

    # -- переобучение -------------------------------------------------------- #

    def _retrain(self, force: bool = False, epoch: int = 1) -> None:
        """
        Переобучает модель на накопленном CSV.

        Основная модель перезаписывается только при улучшении CV-F1 —
        автономная учёба физически не может её ухудшить. На эпохах 2+
        данные перемешиваются новым сидом — повторные проходы дают
        модели новые случайные сплиты, а не копию предыдущего прогона.
        """
        if not force and self._rows_since_retrain < self.settings.retrain_every:
            return
        if self.state.rows_added < 100:
            logger.info("Мало данных для переобучения (%d строк) — пропускаю",
                        self.state.rows_added)
            self._rows_since_retrain = 0
            return
        self._rows_since_retrain = 0

        logger.info("--- ПЕРЕОБУЧЕНИЕ на %d строках (backend=%s) ---",
                    self.state.rows_added, self.settings.backend)
        self._write_status("переобучение модели")
        try:
            classifier = MalwareClassifier(
                backend=self.settings.backend,
                threshold=self.settings.threshold,
                random_state=RANDOM_STATE + epoch,
            )
            dataset = classifier.load_dataset_from_csv(self.settings.csv_path)
            if epoch > 1:
                # новая перестановка строк — эпоха не повторяет прошлую бит-в-бит
                dataset = dataset.sample(frac=1.0, random_state=RANDOM_STATE + epoch)
                dataset = dataset.reset_index(drop=True)
            metrics = classifier.fit(dataset)
        except (FileNotFoundError, ValueError, ImportError) as exc:
            logger.error("Переобучение не удалось: %s", exc)
            return
        except Exception:  # noqa: BLE001 — ночная сессия не должна падать
            logger.exception("Переобучение упало с непредвиденной ошибкой")
            return

        self.state.rows_trained = self.state.rows_added
        current_cv = self._current_cv_f1()
        improved = current_cv is None or metrics.cv_f1_mean > current_cv + 1e-6
        if improved:
            try:
                classifier.save(self.settings.model_path)
                self._best_cv = metrics.cv_f1_mean
                logger.info("Модель УЛУЧШЕНА: CV-F1 %.4f -> %.4f (сохранена)",
                            current_cv if current_cv is not None else 0.0,
                            metrics.cv_f1_mean)
            except OSError as exc:
                logger.error("Не удалось сохранить модель: %s", exc)
        else:
            logger.info("Модель оставлена прежней: новый CV-F1 %.4f <= текущий %.4f",
                        metrics.cv_f1_mean, current_cv if current_cv is not None else 0.0)
        self.state.retrains += 1
        self.state.save()

    def _current_cv_f1(self) -> float | None:
        try:
            bundle = ModelBundle.load(self.settings.model_path, strict_features=False)
        except (FileNotFoundError, ValueError):
            return None
        return float(bundle.metrics.cv_f1_mean)

    # -- служебное ----------------------------------------------------------- #

    def _time_is_up(self) -> bool:
        if self.settings.deadline is None:
            return False
        return datetime.now(timezone.utc) >= self.settings.deadline

    def _print_summary(self) -> None:
        elapsed = datetime.now(timezone.utc) - self._started
        logger.info("=" * 62)
        logger.info("СЕССИЯ ОБУЧЕНИЯ ЗАВЕРШЕНА за %s", str(elapsed).split(".")[0])
        logger.info("  эпох пройдено       : %d", self.state.epochs)
        logger.info("  строк собрано всего : %d", self.state.rows_added)
        logger.info("  переобучений        : %d", self.state.retrains)
        logger.info("  CSV датасет         : %s", self.settings.csv_path)
        logger.info("  текущий CV-F1 модели: %s", self._current_cv_f1())
        logger.info("  Продолжить: python main.py autolearn (прогресс сохранён)")
        logger.info("=" * 62)


# --------------------------------------------------------------------------- #
# Живой статус: файл + доска для отдельного окна
# --------------------------------------------------------------------------- #


def fmt_hms(seconds: float) -> str:
    """Секунды -> ЧЧ:ММ:СС."""
    total = max(0, int(seconds))
    hours, rem = divmod(total, 3600)
    minutes, sec = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{sec:02d}"


def read_status(path: str | Path) -> dict[str, Any] | None:
    """Читает status.json; ``None``, если файла нет или он битый."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def render_status(status: dict[str, Any], now: datetime | None = None) -> str:
    """Рендерит человекочитаемую доску статуса (для отдельного окна)."""
    now = now or datetime.now(timezone.utc)
    running = bool(status.get("running"))
    cv_f1 = status.get("cv_f1")

    stale = ""
    updated_raw = str(status.get("updated_at", ""))
    try:
        age = (now - datetime.fromisoformat(updated_raw)).total_seconds()
        if running and age > 60:
            stale = f"  (нет обновлений {int(age)} c)"
    except ValueError:
        pass

    line = "═" * 46
    rows = [
        line,
        "  AI-ANTIVIRUS · АВТОНОМНОЕ ОБУЧЕНИЕ",
        line,
        f"  Статус         : {'● РАБОТАЕТ' if running else '■ ОСТАНОВЛЕНО'}",
        f"  Прошло времени : {fmt_hms(float(status.get('elapsed_sec', 0)))}",
        f"  Эпох пройдено  : {status.get('epochs', 0)}",
        f"  Строк собрано  : {status.get('rows_added', 0)}",
        f"  Переобучений   : {status.get('retrains', 0)}",
        f"  Фаза           : {status.get('phase') or '—'}",
        f"  Лучший CV-F1   : {cv_f1:.4f}" if isinstance(cv_f1, (int, float))
        else "  Лучший CV-F1   : —",
        f"  Обновлено      : {updated_raw}{stale}",
        line,
    ]
    return "\n".join(rows)


def spawn_status_window(status_path: Path) -> bool:
    """
    На Windows открывает отдельное окно PowerShell с живой доской статуса.

    Основной процесс продолжает писать полный лог в своё окно — отдельное
    окно purely для удобства («сколько прошло времени / эпох»).
    """
    if sys.platform != "win32":
        return False
    main_py = PROJECT_ROOT / "main.py"
    if not main_py.is_file():
        return False
    command = (
        f"& '{sys.executable}' '{main_py}' autolearn-status --watch "
        f"--status '{status_path}'"
    )
    try:
        subprocess.Popen(  # noqa: S603 — фиксированная команда, свои же пути
            ["powershell", "-NoExit", "-NoLogo", "-Command", command],
            creationflags=0x00000010,  # CREATE_NEW_CONSOLE
            close_fds=True,
        )
        return True
    except OSError as exc:
        logger.warning("Не удалось открыть окно статуса: %s", exc)
        return False


# --------------------------------------------------------------------------- #
# Точка входа для CLI
# --------------------------------------------------------------------------- #


def compute_deadline(hours: float | None, until: str | None) -> datetime | None:
    """
    Дедлайн сессии.

    ``None`` (ничего не задано) — учиться бесконечно, до ручной остановки.
    ``--until ЧЧ:ММ`` — ближайшее наступление указанного местного времени.
    ``--hours N`` — N часов от текущего момента.
    """
    now = datetime.now(timezone.utc)
    if not until and hours is None:
        return None
    if until:
        try:
            hh, mm = (int(part) for part in until.split(":"))
        except ValueError as exc:
            raise ValueError(f"--until ожидает ЧЧ:ММ, получено {until!r}") from exc
        target = now.astimezone().replace(hour=hh, minute=mm, second=0, microsecond=0)
        if target <= now.astimezone():
            target += timedelta(days=1)  # ближайшее будущее наступление
        return target.astimezone(timezone.utc)
    return now + timedelta(hours=hours if hours is not None else 8.0)


def run_autolearn(
    *,
    hours: float | None = None,
    until: str | None = None,
    epochs: int | None = None,
    epoch_pause: float = 60.0,
    csv_path: Path = NIGHTLY_CSV,
    model_path: Path | None = None,
    backend: str = DEFAULT_BACKEND,
    retrain_every: int = 10_000,
    max_rows: int = 0,
    use_ember: bool = True,
    ember_url: str | None = None,
    status_window: bool = True,
) -> int:
    """CLI-обёртка: Ctrl+C завершает сессию корректно (код 130)."""
    try:
        deadline = compute_deadline(hours, until)
    except ValueError as exc:
        logger.error("%s", exc)
        return 2

    settings = NightSettings(
        deadline=deadline,
        epochs=epochs or None,
        epoch_pause=max(0.0, epoch_pause),
        csv_path=csv_path,
        model_path=model_path or (MODELS_DIR / DEFAULT_MODEL_FILENAME),
        backend=backend,
        retrain_every=max(100, retrain_every),
        max_rows=max(0, max_rows),
        use_ember=use_ember,
        ember_url=ember_url or EMBER_URL,
    )

    if status_window:
        if spawn_status_window(settings.status_path):
            logger.info("Открыто отдельное окно статуса (полный лог — в этом окне)")
        elif sys.platform != "win32":
            logger.info("Живой статус: python main.py autolearn-status --watch")

    trainer = NightTrainer(settings)
    try:
        return trainer.run()
    except KeyboardInterrupt:
        trainer.state.save()
        logger.warning("Сессия прервана пользователем — прогресс сохранён")
        return 130


#: Обратная совместимость с прежним именем подкоманды.
run_overnight = run_autolearn


__all__ = [
    "BenignCollector",
    "EmberStream",
    "NightSettings",
    "NightState",
    "NightTrainer",
    "compute_deadline",
    "download_file",
    "ember_record_to_features",
    "fmt_hms",
    "read_status",
    "render_status",
    "run_autolearn",
    "run_overnight",
    "spawn_status_window",
]
