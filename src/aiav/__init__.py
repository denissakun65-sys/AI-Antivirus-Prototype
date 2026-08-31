"""
AI-Antivirus (Next-Gen AV prototype)
====================================

Учебный прототип антивируса нового поколения: статический анализ PE-файлов
(``pefile``) + классификация на ML-модели (`scikit-learn` / `LightGBM`) +
автоматический карантин подозрительных объектов.

Публичный API пакета::

    from aiav.features import extract_pe_features, FEATURE_NAMES
    from aiav.model import MalwareClassifier
    from aiav.quarantine import QuarantineManager

.. warning::
    Проект предназначен ИСКЛЮЧИТЕЛЬНО для обучения и исследований.
    Это НЕ замена промышленному антивирусу/EDR.
"""

from __future__ import annotations

__version__ = "0.4.1"
__author__ = "AI-Antivirus contributors"
__license__ = "MIT"

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "PEFeatureError",
    "PEFeatures",
    "FEATURE_NAMES",
    "extract_pe_features",
    "MalwareClassifier",
    "ModelBundle",
    "Verdict",
    "QuarantineManager",
    "QuarantineItem",
]


def __getattr__(name: str):  # pragma: no cover - ленивый импорт, ускоряет старт CLI
    """Ленивая загрузка тяжёлых символов (sklearn/pefile грузятся только по запросу)."""
    import importlib

    lazy_map = {
        "PEFeatureError": "aiav.features",
        "PEFeatures": "aiav.features",
        "FEATURE_NAMES": "aiav.features",
        "extract_pe_features": "aiav.features",
        "MalwareClassifier": "aiav.model",
        "ModelBundle": "aiav.model",
        "Verdict": "aiav.model",
        "QuarantineManager": "aiav.quarantine",
        "QuarantineItem": "aiav.quarantine",
    }
    if name in lazy_map:
        module = importlib.import_module(lazy_map[name])
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
