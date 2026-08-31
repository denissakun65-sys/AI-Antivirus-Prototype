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
    "MODELS_DIR",
    "QUARANTINE_DIR",
    "REPORTS_DIR",
    "DEFAULT_MODEL_FILENAME",
    "MALICIOUS_THRESHOLD",
    "SUSPICIOUS_THRESHOLD",
    "MAX_FILE_SIZE_BYTES",
    "PE_EXTENSIONS",
    "PE_MAGIC_SIGNATURES",
    "DEFAULT_BACKEND",
    "TEST_SIZE",
    "RANDOM_STATE",
]
