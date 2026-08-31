#!/usr/bin/env python3
"""
AI-Antivirus — точка входа для запуска из корня репозитория.

Вся логика CLI живёт в :mod:`aiav.cli`; этот файл нужен только для того, чтобы
``python main.py …`` работал без установки пакета (добавляет ``src/`` в
``sys.path``). При установке пакета доступен эквивалентный консольный скрипт
``aiav`` (см. ``[project.scripts]`` в ``pyproject.toml``).

.. warning::
    Учебный прототип. Не заменяет промышленный антивирус/EDR.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Позволяем запускать ``python main.py`` из корня репозитория без установки пакета.
PROJECT_ROOT = Path(__file__).resolve().parent
_SRC = PROJECT_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aiav.cli import main  # noqa: E402  (импорт после настройки sys.path)

if __name__ == "__main__":
    sys.exit(main())
