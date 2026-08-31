"""
Фоновый мониторинг каталогов (on-access lite).

Как это соотносится с «настоящим» антивирусом
---------------------------------------------
Полноценная реальная защита на Windows — это kernel-минифильтр, который
перехватывает создание/запись файла ДО того, как он будет запущен. Python
так не умеет (и это правильно: самописный драйвер — прямой путь к BSOD и
дырам в безопасности). Поэтому здесь — честный пользовательский уровень:
``watchdog`` следит за событиями ФС в выбранных каталогах и прогоняет новый
файл через тот же конвейер (кэш -> trustlist -> признаки -> модель ->
репутация -> карантин).

Этого достаточно для сценариев «смотрю за Downloads», «проверяю съёмные
носители», «карантин папки обмена файлами». Для автозапуска используйте
планировщик задач ОС; процесс просто живёт в фоне до Ctrl+C.

Тестируемость: ``MonitorPipeline`` не зависит от watchdog — её можно
вызывать напрямую из тестов, передавая путь «как будто» пришло событие.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from aiav.features import is_pe_candidate
from aiav.logging_setup import get_logger
from aiav.scanner import FileScanner, ScanResult

logger = get_logger(__name__)

#: Сколько секунд ждём, пока файл «допишется» (размер стабилизируется).
STABILIZE_TIMEOUT_SEC = 10.0
STABILIZE_STEP_SEC = 0.5


class MonitorPipeline:
    """
    Обработка одного «прилетевшего» файла.

    Отделена от watchdog-наблюдателя, чтобы тесты и CLI могли вызывать её
    без зависимости от события ФС.
    """

    def __init__(self, scanner: FileScanner) -> None:
        self.scanner = scanner

    def process(self, path: str | Path) -> ScanResult | None:
        """
        Проверяет новый файл; возвращает ``None``, если файл не PE-кандидат.

        Ждёт стабилизации размера (браузер/торрент дописывает файл не
        мгновенно), затем передаёт в обычный конвейер сканера — со всеми
        быстрыми фильтрами (кэш, trustlist) и действиями.
        """
        file_path = Path(path)
        try:
            if not self._wait_stable(file_path):
                logger.debug("Файл не стабилизировался, пропускаю: %s", file_path)
                return None
            if not is_pe_candidate(file_path):
                logger.debug("Не PE-кандидат, мониторинг пропускает: %s", file_path)
                return None
        except OSError as exc:
            logger.debug("Файл исчез до проверки (%s): %s", file_path, exc)
            return None

        logger.info("MONITOR: новый файл — %s", file_path)
        return self.scanner.scan_file(file_path)

    @staticmethod
    def _wait_stable(file_path: Path) -> bool:
        """Возвращает True, когда размер файла не меняется два шага подряд."""
        deadline = time.monotonic() + STABILIZE_TIMEOUT_SEC
        previous = -1
        while time.monotonic() < deadline:
            try:
                current = file_path.stat().st_size
            except OSError:
                return False
            if current == previous and current > 0:
                return True
            previous = current
            time.sleep(STABILIZE_STEP_SEC)
        return False


def run_monitor(
    watch_paths: list[Path],
    scanner: FileScanner,
    *,
    recursive: bool = True,
) -> int:
    """
    Запускает фоновое наблюдение до Ctrl+C.

    :raises ImportError: если не установлен пакет ``watchdog``
        (``pip install watchdog``).
    :return: код возврата (0 — штатная остановка, 130 — Ctrl+C).
    """
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError as exc:
        raise ImportError(
            "Фоновый мониторинг требует пакет watchdog: pip install watchdog"
        ) from exc

    pipeline = MonitorPipeline(scanner)

    class _Handler(FileSystemEventHandler):  # noqa: N801 - имя диктует watchdog
        """Реагирует на появление/перемещение файлов в зону наблюдения."""

        def on_created(self, event: Any) -> None:
            self._maybe_scan(event)

        def on_moved(self, event: Any) -> None:
            self._maybe_scan(event)

        @staticmethod
        def _maybe_scan(event: Any) -> None:
            if getattr(event, "is_directory", False):
                return
            target = getattr(event, "dest_path", None) or event.src_path
            try:
                pipeline.process(target)
            except Exception as exc:  # noqa: BLE001 — фон не должен падать
                logger.exception("Ошибка мониторинга на %s: %s", target, exc)

    observer = Observer()
    for watch in watch_paths:
        if not watch.is_dir():
            logger.error("Каталог наблюдения не существует: %s", watch)
            continue
        observer.schedule(_Handler(), str(watch), recursive=recursive)
        logger.warning("Наблюдаю за %s (recursive=%s)", watch, recursive)

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.warning("Мониторинг остановлен пользователем")
        return 130
    finally:
        observer.stop()
        observer.join(timeout=5)
    return 0


__all__ = ["MonitorPipeline", "run_monitor"]
