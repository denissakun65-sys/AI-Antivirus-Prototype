"""
Сканер: склейка «извлечение признаков -> предсказание -> действие».

Здесь живёт бизнес-логика проверки каталога. :mod:`main` лишь разбирает
аргументы командной строки и красиво печатает результат.

Ключевые решения
----------------
* **Пакетное предсказание.** Признаки извлекаются по одному файлу (это IO-bound),
  а модель вызывается один раз для всего набора — так скан заметно быстрее.
* **Один битый файл != упавший скан.** Любая ошибка разбора/IO фиксируется в
  отчёте со статусом ``ERROR``, обход продолжается.
* **Dry-run по умолчанию для «подозрительных».** В карантин уходит только
  вердикт MALICIOUS, и только если не передан флаг ``--dry-run``.
"""

from __future__ import annotations

import csv
import json
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiav.config import (
    MALICIOUS_THRESHOLD,
    MAX_FILE_SIZE_BYTES,
    REPORTS_DIR,
    SUSPICIOUS_THRESHOLD,
)
from aiav.features import (
    PEFeatureError,
    PEFeatures,
    extract_pe_features,
    iter_pe_files,
)
from aiav.logging_setup import get_logger
from aiav.model import MalwareClassifier, Prediction, Verdict
from aiav.quarantine import QuarantineError, QuarantineItem, QuarantineManager

logger = get_logger(__name__)


@dataclass(slots=True)
class ScanResult:
    """Итог проверки одного файла."""

    path: str
    status: str                      # OK | ERROR | SKIPPED
    verdict: str = Verdict.UNKNOWN.value
    malware_probability: float = 0.0
    sha256: str = ""
    size: int = 0
    entropy: float = 0.0
    quarantined: bool = False
    quarantine_id: str = ""
    error: str = ""
    features: dict[str, float] = field(default_factory=dict, repr=False)

    @property
    def is_threat(self) -> bool:
        return self.verdict == Verdict.MALICIOUS.value


@dataclass(slots=True)
class ScanSummary:
    """Сводка по всему прогону сканирования."""

    target: str
    started_at: str
    duration_sec: float
    scanned: int = 0
    clean: int = 0
    suspicious: int = 0
    malicious: int = 0
    errors: int = 0
    quarantined: int = 0
    dry_run: bool = False
    model_path: str = ""
    results: list[ScanResult] = field(default_factory=list)

    def threats(self) -> list[ScanResult]:
        """Все файлы с вердиктом MALICIOUS или SUSPICIOUS."""
        return [r for r in self.results if r.verdict in
                (Verdict.MALICIOUS.value, Verdict.SUSPICIOUS.value)]

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["threats_found"] = len(self.threats())
        return data

    def headline(self) -> str:
        return (
            f"Просканировано: {self.scanned} | clean: {self.clean} | "
            f"suspicious: {self.suspicious} | malicious: {self.malicious} | "
            f"errors: {self.errors} | в карантин: {self.quarantined}"
        )


class FileScanner:
    """Сканирует файлы и каталоги с помощью обученной модели."""

    def __init__(
        self,
        classifier: MalwareClassifier,
        quarantine: QuarantineManager | None = None,
        *,
        action: str = "quarantine",
        suspicious_threshold: float = SUSPICIOUS_THRESHOLD,
        malicious_threshold: float = MALICIOUS_THRESHOLD,
        max_file_size: int = MAX_FILE_SIZE_BYTES,
        dry_run: bool = False,
        model_path: str | Path | None = None,
    ) -> None:
        """
        :param classifier: обученная/загруженная модель.
        :param quarantine: менеджер карантина (нужен, если ``action="quarantine"``).
        :param action: ``"quarantine"`` | ``"report"`` — что делать с угрозами.
        :param suspicious_threshold: нижняя граница «серой зоны».
        :param malicious_threshold: граница гарантированного карантина.
        :param dry_run: если True — файлы не перемещаются, только отчёт.
        :param model_path: путь к файлу модели — попадает в отчёт (важно для
            расследования: нужно знать, какой именно моделью вынесен вердикт).
        """
        self.classifier = classifier
        self.quarantine = quarantine
        self.action = action.lower().strip()
        self.suspicious_threshold = float(suspicious_threshold)
        self.malicious_threshold = float(malicious_threshold)
        self.max_file_size = int(max_file_size)
        self.dry_run = bool(dry_run)
        self.model_path = str(model_path) if model_path else ""

        if self.action == "quarantine" and self.quarantine is None and not self.dry_run:
            raise ValueError("Для действия 'quarantine' требуется QuarantineManager")
        logger.debug(
            "FileScanner: action=%s dry_run=%s пороги=%.2f/%.2f",
            self.action, self.dry_run, self.suspicious_threshold, self.malicious_threshold,
        )

    # ---------------------------- одиночный файл -------------------------- #

    def scan_file(self, path: str | Path) -> ScanResult:
        """
        Проверяет один файл: признаки -> предсказание -> (опционально) карантин.

        Все ошибки перехватываются и возвращаются в ``ScanResult.error``.
        """
        file_path = Path(path).expanduser()
        started = time.perf_counter()
        try:
            features = extract_pe_features(file_path, max_file_size=self.max_file_size)
        except PEFeatureError as exc:
            logger.warning("Не удалось разобрать %s: %s", file_path.name, exc)
            return ScanResult(path=str(file_path), status="ERROR", error=str(exc))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Непредвиденная ошибка при разборе %s", file_path)
            return ScanResult(path=str(file_path), status="ERROR", error=repr(exc))

        try:
            prediction = self.classifier.predict_one(features)
        except Exception as exc:  # noqa: BLE001
            logger.error("Ошибка предсказания для %s: %s", file_path.name, exc)
            return ScanResult(
                path=str(file_path), status="ERROR", error=f"prediction failed: {exc}",
                sha256=features.sha256, size=features.size,
            )

        verdict = self._refine_verdict(prediction)
        result = ScanResult(
            path=str(file_path),
            status="OK",
            verdict=verdict.value,
            malware_probability=prediction.malware_probability,
            sha256=features.sha256,
            size=features.size,
            entropy=features.values.get("entropy_overall", 0.0),
            features=features.to_dict(),
        )

        if verdict is Verdict.MALICIOUS and self.action == "quarantine":
            self._quarantine(result, features, prediction)

        logger.log(
            _level_for(verdict),
            "%-11s %s  (P(malware)=%.3f, энтропия=%.2f, %.2f c)",
            verdict.value, file_path, prediction.malware_probability,
            result.entropy, time.perf_counter() - started,
        )
        return result

    def _refine_verdict(self, prediction: Prediction) -> Verdict:
        """
        Приводит вердикт модели к порогам сканера.

        Модель знает один порог, а сканер использует два — поэтому «серая зона»
        пересчитывается здесь, чтобы её можно было настраивать без переобучения.
        """
        proba = prediction.malware_probability
        if proba >= self.malicious_threshold:
            return Verdict.MALICIOUS
        if proba >= self.suspicious_threshold:
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN

    def _quarantine(
        self, result: ScanResult, features: PEFeatures, prediction: Prediction
    ) -> None:
        """Изолирует файл; ошибка карантина не прерывает сканирование."""
        if self.dry_run:
            logger.warning("[DRY-RUN] Файл был бы перемещён в карантин: %s", result.path)
            return
        assert self.quarantine is not None  # проверено в __init__
        try:
            item: QuarantineItem = self.quarantine.isolate(
                features.path,
                verdict=result.verdict,
                probability=prediction.malware_probability,
                model=f"{self.classifier.backend}@{self.classifier.trained_at}",
                reason=f"P(malware)={prediction.malware_probability:.4f} "
                       f">= {self.malicious_threshold:.2f}",
                extra={
                    "entropy_overall": features.values.get("entropy_overall", 0.0),
                    "is_upx_packed": features.values.get("is_upx_packed", 0.0),
                    "imports_suspicious_count": features.values.get(
                        "imports_suspicious_count", 0.0
                    ),
                },
            )
            result.quarantined = True
            result.quarantine_id = item.item_id
        except QuarantineError as exc:
            logger.error("Карантин не выполнен для %s: %s", result.path, exc)
            result.error = f"quarantine failed: {exc}"

    # ------------------------------ каталог ------------------------------ #

    def scan_paths(self, paths: Iterable[str | Path]) -> ScanSummary:
        """
        Сканирует список путей (файлы и/или каталоги) одним пакетным вызовом модели.
        """
        started = time.perf_counter()
        targets = self._collect_targets(paths)
        summary = ScanSummary(
            target=", ".join(str(p) for p in paths),
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            duration_sec=0.0,
            dry_run=self.dry_run,
            model_path=self.model_path,
        )
        if not targets:
            logger.warning("PE-файлы для сканирования не найдены")
            summary.duration_sec = round(time.perf_counter() - started, 3)
            return summary

        logger.info("Найдено PE-кандидатов: %d", len(targets))

        # 1) Извлечение признаков (пофайлово: ошибки не прерывают обход)
        parsed: list[tuple[Path, PEFeatures]] = []
        for path in targets:
            try:
                parsed.append((path, extract_pe_features(path, max_file_size=self.max_file_size)))
            except PEFeatureError as exc:
                logger.warning("Пропуск %s: %s", path.name, exc)
                summary.errors += 1
                summary.results.append(
                    ScanResult(path=str(path), status="ERROR", error=str(exc))
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Непредвиденная ошибка на %s", path)
                summary.errors += 1
                summary.results.append(
                    ScanResult(path=str(path), status="ERROR", error=repr(exc))
                )

        # 2) Один вызов модели для всех образцов
        predictions: list[Prediction] = []
        if parsed:
            try:
                predictions = self.classifier.predict_many(
                    [features.to_vector() for _, features in parsed]
                )
            except Exception as exc:  # noqa: BLE001 — модель не смогла ответить
                logger.error("Пакетное предсказание не удалось: %s", exc)
                for path, _ in parsed:
                    summary.errors += 1
                    summary.results.append(
                        ScanResult(path=str(path), status="ERROR",
                                   error=f"prediction failed: {exc}")
                    )
                parsed = []

        # 3) Применение вердиктов и действий
        for (path, features), prediction in zip(parsed, predictions, strict=True):
            verdict = self._refine_verdict(prediction)
            result = ScanResult(
                path=str(path),
                status="OK",
                verdict=verdict.value,
                malware_probability=prediction.malware_probability,
                sha256=features.sha256,
                size=features.size,
                entropy=features.values.get("entropy_overall", 0.0),
                features=features.to_dict(),
            )
            if verdict is Verdict.MALICIOUS and self.action == "quarantine":
                self._quarantine(result, features, prediction)
            summary.results.append(result)

        self._tally(summary)
        summary.duration_sec = round(time.perf_counter() - started, 3)
        logger.info("Скан завершён за %.2f c. %s", summary.duration_sec, summary.headline())
        return summary

    def scan_directory(self, directory: str | Path) -> ScanSummary:
        """Удобная обёртка для одного каталога."""
        return self.scan_paths([directory])

    def _collect_targets(self, paths: Iterable[str | Path]) -> list[Path]:
        """Разворачивает пути в плоский список PE-файлов (без дублей)."""
        found: list[Path] = []
        seen: set[Path] = set()
        for raw in paths:
            path = Path(raw).expanduser().resolve()
            try:
                if path.is_dir():
                    for candidate in iter_pe_files(path):
                        if self._accept(candidate, seen):
                            found.append(candidate)
                elif path.is_file():
                    if self._accept(path, seen):
                        found.append(path)
                else:
                    logger.warning("Путь не существует: %s", path)
            except (FileNotFoundError, NotADirectoryError) as exc:
                logger.error("%s", exc)
            except OSError as exc:
                logger.error("Ошибка доступа к %s: %s", path, exc)
        return found

    def _accept(self, candidate: Path, seen: set[Path]) -> bool:
        """Фильтр кандидатов: не дубль, не внутри карантина, проходит по размеру."""
        if candidate in seen:
            return False
        seen.add(candidate)

        if self.quarantine is not None:
            try:
                candidate.relative_to(self.quarantine.directory)
                logger.debug("Пропуск файла из карантина: %s", candidate)
                return False
            except ValueError:
                pass

        try:
            size = candidate.stat().st_size
        except OSError as exc:
            logger.warning("Нет доступа к %s: %s", candidate, exc)
            return False
        if size == 0:
            logger.debug("Пропуск пустого файла: %s", candidate)
            return False
        if size > self.max_file_size:
            logger.warning("Пропуск слишком большого файла: %s (%d байт)", candidate, size)
            return False
        return True

    # ------------------------------- отчёты ------------------------------ #

    @staticmethod
    def _tally(summary: ScanSummary) -> None:
        """Считает агрегаты по результатам."""
        for result in summary.results:
            if result.status != "OK":
                continue
            summary.scanned += 1
            if result.verdict == Verdict.CLEAN.value:
                summary.clean += 1
            elif result.verdict == Verdict.SUSPICIOUS.value:
                summary.suspicious += 1
            elif result.verdict == Verdict.MALICIOUS.value:
                summary.malicious += 1
            if result.quarantined:
                summary.quarantined += 1

    @staticmethod
    def save_report(
        summary: ScanSummary,
        directory: str | Path = REPORTS_DIR,
        *,
        include_features: bool = False,
        basename: str | None = None,
    ) -> dict[str, Path]:
        """
        Сохраняет отчёт в JSON (полный) и CSV (таблица для Excel/SIEM).

        :param include_features: включать ли весь вектор признаков в JSON.
        """
        out_dir = Path(directory).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        stem = basename or f"scan-{stamp}"
        written: dict[str, Path] = {}

        # --- JSON ---
        json_path = out_dir / f"{stem}.json"
        payload = summary.as_dict()
        if not include_features:
            for item in payload.get("results", []):
                item.pop("features", None)
        try:
            json_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            written["json"] = json_path
        except OSError as exc:
            logger.error("Не удалось сохранить JSON-отчёт: %s", exc)

        # --- CSV ---
        csv_path = out_dir / f"{stem}.csv"
        columns = ["path", "status", "verdict", "malware_probability", "sha256",
                   "size", "entropy", "quarantined", "quarantine_id", "error"]
        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
                writer.writeheader()
                for result in summary.results:
                    writer.writerow(asdict(result))
            written["csv"] = csv_path
        except OSError as exc:
            logger.error("Не удалось сохранить CSV-отчёт: %s", exc)

        if written:
            logger.info("Отчёты сохранены: %s", ", ".join(str(p) for p in written.values()))
        return written


def _level_for(verdict: Verdict) -> int:
    """Уровень логирования в зависимости от серьёзности вердикта."""
    import logging

    return {
        Verdict.CLEAN: logging.INFO,
        Verdict.SUSPICIOUS: logging.WARNING,
        Verdict.MALICIOUS: logging.ERROR,
        Verdict.UNKNOWN: logging.WARNING,
    }.get(verdict, logging.INFO)


__all__ = ["FileScanner", "ScanResult", "ScanSummary"]
