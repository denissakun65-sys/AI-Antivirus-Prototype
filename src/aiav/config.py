"""
Централизованная конфигурация проекта.

Все «магические числа», пути и пороги вынесены сюда, чтобы их можно было
менять в одном месте (или переопределять переменными окружения).
"""

from __future__ import annotations

import os
from pathlib import Path

# --------------------------------------------------------------------------- #
# Пути
# --------------------------------------------------------------------------- #

#: Корень репозитория (…/ai-antivirus)
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]

#: Каталог с обученными моделями (*.joblib)
MODELS_DIR: Path = Path(os.environ.get("AIAV_MODELS_DIR", PROJECT_ROOT / "models"))

#: Каталог карантина по умолчанию
QUARANTINE_DIR: Path = Path(
    os.environ.get("AIAV_QUARANTINE_DIR", PROJECT_ROOT / "quarantine")
)

#: Каталог с отчётами о сканировании (JSON/CSV)
REPORTS_DIR: Path = Path(os.environ.get("AIAV_REPORTS_DIR", PROJECT_ROOT / "reports"))

#: Имя файла модели по умолчанию
DEFAULT_MODEL_FILENAME: str = "malware_classifier.joblib"

#: SQLite-кэш вердиктов (sha256 + сигнатура модели -> вердикт).
VERDICT_CACHE_PATH: Path = Path(
    os.environ.get("AIAV_CACHE_DB", MODELS_DIR / "verdict_cache.db")
)

#: JSON со списками доверия (хеши + пути).
TRUSTLIST_PATH: Path = Path(
    os.environ.get("AIAV_TRUSTLIST", MODELS_DIR / "trustlist.json")
)

#: Ключ VirusTotal API (если задан — онлайн-репутация богаче).
VIRUSTOTAL_API_KEY: str = os.environ.get("AIAV_VT_KEY", "")

#: Пути, которые считаем заведомо доверенными и не сканируем.
#: Переопределяется env-переменной AIAV_TRUSTED_PREFIXES (разделитель — os.pathsep).
if os.name == "nt":  # pragma: no cover - зависит от ОС
    _DEFAULT_TRUSTED_PREFIXES = (
        "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
    )
else:
    _DEFAULT_TRUSTED_PREFIXES = ("/usr/lib", "/usr/share", "/lib", "/lib64", "/bin", "/sbin")

_env_prefixes = os.environ.get("AIAV_TRUSTED_PREFIXES", "")
TRUSTED_PATH_PREFIXES: tuple[str, ...] = (
    tuple(p for p in _env_prefixes.split(os.pathsep) if p)
    if _env_prefixes
    else _DEFAULT_TRUSTED_PREFIXES
)

#: TTL для кэша репутационных ответов (дни): репутация со временем меняется.
INTEL_CACHE_TTL_DAYS: int = int(os.environ.get("AIAV_INTEL_TTL_DAYS", 7))

#: CSV, куда ``scan --learn`` складывает пары «признаки -> вердикт консенсуса
#: мировых движков» для последующего переобучения локальной модели.
DISTILL_PATH: Path = Path(
    os.environ.get("AIAV_DISTILL_CSV", PROJECT_ROOT / "data" / "distill" / "dataset.csv")
)

#: URL EMBER-датасета: ИЗВЛЕЧЁННЫЕ признаки ~1 млн реальных PE-файлов
#: с метками консенсуса VirusTotal. Самих malware-файлов там нет —
#: это легальный способ «учиться из интернета», не скачивая образцы.
EMBER_URL: str = os.environ.get(
    "AIAV_EMBER_URL", "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
)

#: CSV ночного обучения — накапливается командой `overnight`,
#: пригоден для ручного переобучения: `train --csv <путь>`.
NIGHTLY_CSV: Path = Path(
    os.environ.get("AIAV_NIGHTLY_CSV", PROJECT_ROOT / "data" / "nightly" / "dataset.csv")
)

#: Готовая конвертированная выборка EMBER (лежит в репозитории, ~30 МБ):
#: спасение для регионов, где CDN elastic.co отвечает 403.
EMBER_SAMPLE_CSV: Path = Path(
    os.environ.get("AIAV_EMBER_SAMPLE", PROJECT_ROOT / "datasets" / "ember_2018_sample.csv.gz")
)

#: Живой статус автономной сессии (читает отдельное окно `autolearn-status`).
NIGHTLY_STATUS: Path = Path(
    os.environ.get("AIAV_NIGHTLY_STATUS", PROJECT_ROOT / "data" / "nightly" / "status.json")
)

# --------------------------------------------------------------------------- #
# Пороги принятия решений
# --------------------------------------------------------------------------- #

#: Вероятность «вредоносности» >= MALICIOUS_THRESHOLD  ->  файл уходит в карантин.
MALICIOUS_THRESHOLD: float = float(os.environ.get("AIAV_T_MALICIOUS", 0.80))

#: Вероятность в диапазоне [SUSPICIOUS, MALICIOUS) -> файл помечается как
#: подозрительный (по умолчанию только попадает в отчёт, но не блокируется).
SUSPICIOUS_THRESHOLD: float = float(os.environ.get("AIAV_T_SUSPICIOUS", 0.50))

# --------------------------------------------------------------------------- #
# Ограничения парсера
# --------------------------------------------------------------------------- #

#: Файлы крупнее этого значения не разбираются (защита от «бомб» и дампов памяти).
MAX_FILE_SIZE_BYTES: int = 256 * 1024 * 1024  # 256 МБ

#: Расширения, которые считаем PE-кандидатами при поверхностном отборе.
PE_EXTENSIONS: frozenset[str] = frozenset(
    {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi", ".drv", ".node"}
)

#: PE-сигнатуры DOS/NE/LE — по ним подтверждаем, что файл действительно PE.
PE_MAGIC_SIGNATURES: tuple[bytes, ...] = (b"MZ", b"NE", b"LE")

# --------------------------------------------------------------------------- #
# Обучение
# --------------------------------------------------------------------------- #

DEFAULT_BACKEND: str = os.environ.get("AIAV_BACKEND", "random_forest")
TEST_SIZE: float = 0.25
RANDOM_STATE: int = 42

__all__ = [
    "PROJECT_ROOT",
    "VERDICT_CACHE_PATH",
    "TRUSTLIST_PATH",
    "VIRUSTOTAL_API_KEY",
    "TRUSTED_PATH_PREFIXES",
    "INTEL_CACHE_TTL_DAYS",
    "DISTILL_PATH",
    "MODELS_DIR",
    "QUARANTINE_DIR",
    "REPORTS_DIR",
    "DEFAULT_MODEL_FILENAME",
    "EMBER_SAMPLE_CSV",
    "EMBER_URL",
    "NIGHTLY_CSV",
    "NIGHTLY_STATUS",
    "MALICIOUS_THRESHOLD",
    "SUSPICIOUS_THRESHOLD",
    "MAX_FILE_SIZE_BYTES",
    "PE_EXTENSIONS",
    "PE_MAGIC_SIGNATURES",
    "DEFAULT_BACKEND",
    "TEST_SIZE",
    "RANDOM_STATE",
]
