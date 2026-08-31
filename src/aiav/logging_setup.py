"""
Настройка логирования.

Единая точка конфигурации: цветной вывод в консоль + опциональный файл.
Импортируется всеми модулями как::

    from aiav.logging_setup import get_logger
    logger = get_logger(__name__)
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-18s | %(message)s"
_DATE_FORMAT = "%H:%M:%S"

# ANSI-коды. Отключаются автоматически, если вывод не в терминал (CI, файлы,
# Windows-консоль без поддержки VT-последовательностей).
_COLORS = {
    "DEBUG": "\033[36m",      # cyan
    "INFO": "\033[32m",       # green
    "WARNING": "\033[33m",    # yellow
    "ERROR": "\033[31m",      # red
    "CRITICAL": "\033[1;41m", # white on red
}
_RESET = "\033[0m"


class ColorFormatter(logging.Formatter):
    """Форматтер, раскрашивающий уровень сообщения в консоли."""

    def __init__(self, use_color: bool) -> None:
        super().__init__(_LOG_FORMAT, _DATE_FORMAT)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if self.use_color:
            color = _COLORS.get(record.levelname, "")
            return f"{color}{message}{_RESET}" if color else message
        return message


def setup_logging(
    level: int | str = logging.INFO,
    log_file: str | Path | None = None,
    quiet: bool = False,
) -> logging.Logger:
    """
    Инициализирует корневой логгер проекта.

    :param level: уровень логирования (``logging.DEBUG``, ``"INFO"`` и т.д.).
    :param log_file: если задан — дополнительно писать лог в файл (с ротацией).
    :param quiet: если True — в консоль выводятся только WARNING и выше.
    :return: корневой логгер пакета ``aiav``.
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    root = logging.getLogger("aiav")
    root.setLevel(logging.DEBUG)          # фильтр делаем на обработчиках
    root.propagate = False
    root.handlers.clear()                # защита от дублей при повторном вызове

    console_level = logging.WARNING if quiet else level
    console = logging.StreamHandler(stream=sys.stderr)
    console.setLevel(console_level)
    console.setFormatter(ColorFormatter(use_color=sys.stderr.isatty()))
    root.addHandler(console)

    if log_file:
        try:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, _DATE_FORMAT))
            root.addHandler(file_handler)
        except OSError as exc:  # нет прав / нет места — не роняем из-за этого скан
            root.warning("Не удалось создать лог-файл %s: %s", log_file, exc)

    # Приглушаем болтливые сторонние библиотеки
    for noisy in ("numba", "matplotlib", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return root


def get_logger(name: str) -> logging.Logger:
    """Возвращает дочерний логгер внутри пространства имён ``aiav``."""
    if name.startswith("aiav"):
        return logging.getLogger(name)
    short = name.rsplit(".", maxsplit=1)[-1]
    return logging.getLogger(f"aiav.{short}")
