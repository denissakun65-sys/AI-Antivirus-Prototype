"""
Командный интерфейс AI-Antivirus.

Команды
-------
* ``scan``       — проверить файл/каталог, при необходимости отправить в карантин.
* ``train``      — обучить модель на каталоге образцов или CSV-датасете.
* ``features``   — показать вектор признаков одного файла (отладка).
* ``quarantine`` — просмотр/восстановление/удаление объектов карантина.
* ``model-info`` — сведения об обученной модели.

Примеры
-------
.. code-block:: bash

    python main.py train --dataset data/samples --backend random_forest
    python main.py scan ~/Downloads --action quarantine
    python main.py scan suspicious.exe --dry-run --verbose
    python main.py quarantine list
    python main.py quarantine restore 1735689600-1a2b3c4d

Модуль импортируется тонкой обёрткой ``main.py`` в корне репозитория и
консольной точкой входа ``aiav`` (см. ``pyproject.toml``).

.. warning::
    Учебный прототип. Не заменяет промышленный антивирус/EDR.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from aiav import __version__  # noqa: E402
from aiav.cache import VerdictCache  # noqa: E402
from aiav.config import (  # noqa: E402
    DEFAULT_BACKEND,
    DEFAULT_MODEL_FILENAME,
    DISTILL_PATH,
    MALICIOUS_THRESHOLD,
    MAX_FILE_SIZE_BYTES,
    MODELS_DIR,
    NIGHTLY_CSV,
    QUARANTINE_DIR,
    REPORTS_DIR,
    SUSPICIOUS_THRESHOLD,
)
from aiav.features import (  # noqa: E402
    FEATURE_NAMES,
    PEFeatureError,
    extract_pe_features,
)
from aiav.logging_setup import get_logger, setup_logging  # noqa: E402
from aiav.model import MalwareClassifier  # noqa: E402
from aiav.quarantine import QuarantineError, QuarantineManager  # noqa: E402
from aiav.scanner import FileScanner, ScanSummary  # noqa: E402
from aiav.threat_intel import ThreatIntelClient  # noqa: E402
from aiav.trustlist import Trustlist  # noqa: E402

logger = get_logger("main")

BANNER = r"""
     _    ___   ___         _          _
    / \  |_ _| / _ \  _ __ | |_  _   _(_)__  ___
   / _ \  | | | | | || '_ \| __|| | | | | \/ / / __|
  / ___ \ | | | |_| || | | | |_ | |_| | |   <  \__ \
 /_/   \_\___| \___/ |_| \_|\__| \__,_|_|_|\_\ |___/
  Next-Gen AV prototype | статический PE-анализ + ML
"""

DISCLAIMER = (
    "ВНИМАНИЕ: учебный прототип. Результаты требуют проверки; "
    "не используйте как единственное средство защиты."
)


# --------------------------------------------------------------------------- #
# Вспомогательный вывод
# --------------------------------------------------------------------------- #


def _print_table(summary: ScanSummary, limit: int = 25) -> None:
    """Печатает консольную таблицу результатов (без внешних зависимостей)."""
    threats = summary.threats()
    if not threats:
        print("\nУгроз не обнаружено.")
        return

    print(f"\nОбнаружено подозрительных объектов: {len(threats)}")
    header = f"{'ВЕРДИКТ':<11} {'P(MAL)':>7} {'КАРАНТИН':>9}  ФАЙЛ"
    print("-" * len(header))
    print(header)
    print("-" * len(header))
    for result in threats[:limit]:
        flag = "ДА" if result.quarantined else ("DRY-RUN" if summary.dry_run else "нет")
        print(
            f"{result.verdict:<11} {result.malware_probability:>7.3f} {flag:>9}  {result.path}"
        )
    if len(threats) > limit:
        print(f"… и ещё {len(threats) - limit} (см. JSON/CSV-отчёт)")


def _print_summary(summary: ScanSummary) -> None:
    """Итоговый блок сканирования."""
    print("\n" + "=" * 62)
    print("ИТОГИ СКАНИРОВАНИЯ")
    print("=" * 62)
    print(f"  Цель            : {summary.target}")
    print(f"  Длительность    : {summary.duration_sec:.2f} c")
    print(f"  Просканировано  : {summary.scanned}")
    print(f"  Чистые          : {summary.clean}")
    print(f"  Подозрительные  : {summary.suspicious}")
    print(f"  Вредоносные     : {summary.malicious}")
    print(f"  Ошибки разбора  : {summary.errors}")
    print(f"  В карантин      : {summary.quarantined}")
    print("=" * 62)


# --------------------------------------------------------------------------- #
# Команды
# --------------------------------------------------------------------------- #


def cmd_scan(args: argparse.Namespace) -> int:
    """Подкоманда ``scan``: проверка файлов/каталогов."""
    model_path = Path(args.model).expanduser()
    try:
        classifier = MalwareClassifier.load(model_path, strict_features=not args.lenient)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("%s", exc)
        logger.error("Подсказка: сначала выполните `python main.py train --dataset <каталог>`")
        return 2

    quarantine: QuarantineManager | None = None
    if args.action == "quarantine":
        try:
            quarantine = QuarantineManager(
                args.quarantine_dir, encrypt=not args.no_encrypt
            )
        except QuarantineError as exc:
            logger.error("Карантин недоступен: %s", exc)
            return 2

    if args.learn:
        args.online = True
    cache = None if args.no_cache else VerdictCache()
    trustlist = Trustlist()
    intel = ThreatIntelClient(cache=cache) if args.online else None
    if args.online:
        logger.info("Онлайн-репутация включена (MalwareBazaar%s)",
                    " + VirusTotal" if intel and intel.vt_api_key else "")
    learn_path = DISTILL_PATH if args.learn else None

    scanner = FileScanner(
        classifier,
        quarantine,
        action=args.action,
        suspicious_threshold=args.suspicious_threshold,
        malicious_threshold=args.malicious_threshold,
        dry_run=args.dry_run,
        model_path=model_path,
        cache=cache,
        trustlist=trustlist,
        intel=intel,
        online=args.online,
        learn_path=learn_path,
        max_file_size=(
            int(args.max_file_size * 1024 * 1024)
            if args.max_file_size is not None
            else MAX_FILE_SIZE_BYTES
        ),
    )

    try:
        summary = scanner.scan_paths(args.targets)
    except KeyboardInterrupt:
        logger.warning("Сканирование прервано пользователем")
        return 130
    except Exception as exc:  # noqa: BLE001 — CLI не должен падать с трейсбеком
        logger.exception("Сканирование завершилось ошибкой: %s", exc)
        return 1

    _print_summary(summary)
    _print_table(summary, limit=args.limit)

    if not args.no_report:
        scanner.save_report(summary, args.report_dir, include_features=args.full_report)

    if args.learn and summary.labels_collected:
        print(
            f"\nСобрано обучающих пар (консенсус движков): {summary.labels_collected}. "
            f"Переобучение: python main.py train --csv {DISTILL_PATH}"
        )

    # Код возврата в стиле антивирусов: 0 — чисто, 1 — найдены угрозы, 2 — ошибка.
    return 1 if summary.malicious or summary.suspicious else 0


def cmd_train(args: argparse.Namespace) -> int:
    """Подкоманда ``train``: обучение и сохранение модели."""
    classifier = MalwareClassifier(
        backend=args.backend, threshold=args.threshold, n_jobs=args.jobs
    )
    try:
        if args.csv:
            dataset = classifier.load_dataset_from_csv(args.csv)
            metrics = classifier.fit(dataset, test_size=args.test_size)
        else:
            metrics = classifier.train_from_directory(
                args.dataset,
                limit_per_class=args.limit,
                test_size=args.test_size,
            )
    except (FileNotFoundError, ValueError, ImportError) as exc:
        logger.error("Обучение невозможно: %s", exc)
        return 2
    except KeyboardInterrupt:
        logger.warning("Обучение прервано пользователем")
        return 130

    model_path = Path(args.output).expanduser()
    try:
        classifier.save(model_path)
    except OSError as exc:
        logger.error("Не удалось сохранить модель: %s", exc)
        return 1

    print("\n" + "=" * 62)
    print("ОБУЧЕНИЕ ЗАВЕРШЕНО")
    print("=" * 62)
    print(f"  Бэкенд          : {classifier.backend}")
    print(f"  Обучающих/тест  : {metrics.samples_train}/{metrics.samples_test}")
    print(f"  Accuracy        : {metrics.accuracy:.4f}")
    print(f"  Precision       : {metrics.precision:.4f}")
    print(f"  Recall          : {metrics.recall:.4f}")
    print(f"  F1              : {metrics.f1:.4f}")
    print(f"  ROC-AUC         : {metrics.roc_auc:.4f}")
    print(f"  CV F1           : {metrics.cv_f1_mean:.4f} ± {metrics.cv_f1_std:.4f}")
    print(f"  Confusion [TN,FP,FN,TP]: {metrics.confusion}")
    print(f"  Модель          : {model_path}")
    print("=" * 62)
    return 0


def cmd_features(args: argparse.Namespace) -> int:
    """Подкоманда ``features``: дамп признаков одного файла."""
    try:
        features = extract_pe_features(args.path)
    except PEFeatureError as exc:
        logger.error("Извлечение признаков не удалось: %s", exc)
        return 2

    print(f"\nФайл   : {features.path}")
    print(f"Размер : {features.size:,} байт")
    print(f"SHA-256: {features.sha256}")
    print("-" * 62)
    for name in FEATURE_NAMES:
        value = features.values.get(name, 0.0)
        print(f"  {name:<32} {value:>14,.4f}")
    print("-" * 62)
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    """Подкоманда ``quarantine``: управление хранилищем изолированных объектов."""
    try:
        manager = QuarantineManager(args.quarantine_dir, encrypt=not args.no_encrypt)
    except QuarantineError as exc:
        logger.error("%s", exc)
        return 2

    try:
        if args.qaction == "list":
            items = manager.list_items()
            if not items:
                print("Карантин пуст.")
                return 0
            print(f"\n{'ID':<22} {'ВЕРДИКТ':<11} {'P(MAL)':>7}  ИСХОДНЫЙ ПУТЬ")
            print("-" * 78)
            for item in items:
                print(
                    f"{item.item_id:<22} {item.verdict:<11} "
                    f"{item.probability:>7.3f}  {item.original_path}"
                )
            stats = manager.stats()
            print(
                f"\nВсего объектов: {stats['items']} | "
                f"объём: {stats['total_size_bytes']:,} байт | "
                f"шифрование: {stats['encryption']} | {stats['directory']}"
            )
            return 0

        if args.qaction == "restore":
            if not args.item_id:
                logger.error("Укажите идентификатор: quarantine restore <ID>")
                return 2
            destination = manager.restore(
                args.item_id, target=args.target, force=args.force, keep_record=args.keep
            )
            print(f"Файл восстановлен: {destination}")
            if not args.force:
                print("Напоминание: объект считается вредоносным — не запускайте его.")
            return 0

        if args.qaction == "purge":
            if args.all:
                removed = manager.purge_all()
                print(f"Удалено объектов: {removed}")
                return 0
            if not args.item_id:
                logger.error("Укажите идентификатор или используйте --all")
                return 2
            manager.purge(args.item_id)
            print(f"Объект {args.item_id} удалён из карантина.")
            return 0

        logger.error("Неизвестное действие карантина: %s", args.qaction)
        return 2

    except QuarantineError as exc:
        logger.error("%s", exc)
        return 1


def cmd_trust(args: argparse.Namespace) -> int:
    """Подкоманда ``trust``: управление whitelist (борьба с ложными срабатываниями)."""
    try:
        trustlist = Trustlist()
    except OSError as exc:
        logger.error("Trustlist недоступен: %s", exc)
        return 2

    if args.taction == "list":
        data = trustlist.dump()
        print("Доверенные хеши:")
        for digest in data["hashes"]:
            print(f"  {digest}")
        print("Доверенные пути:")
        for prefix in data["paths"]:
            print(f"  {prefix}")
        stats = trustlist.stats()
        print(f"\nВсего: {stats['hashes']} хеш(ей), {stats['paths']} путь(ей)")
        return 0

    if args.taction == "add":
        if not args.paths:
            logger.error("Укажите файлы: trust add <file> [file …]")
            return 2
        for target in args.paths:
            path = Path(target).expanduser()
            if not path.is_file():
                logger.error("Не файл: %s", path)
                return 2
            digest = trustlist.trust_file(path)
            print(f"Доверено: {path.name} ({digest[:16]}…)")
        return 0

    if args.taction == "add-path":
        if not args.paths:
            logger.error("Укажите каталог: trust add-path <dir>")
            return 2
        for target in args.paths:
            trustlist.trust_path_prefix(str(Path(target).expanduser().resolve()))
            print(f"Доверенный префикс: {target}")
        return 0

    if args.taction == "remove":
        if not args.paths:
            logger.error("Укажите хеш или путь: trust remove <token>")
            return 2
        removed = 0
        for token in args.paths:
            removed += int(trustlist.untrust(token))
        print(f"Удалено записей: {removed}")
        return 0 if removed else 1

    logger.error("Неизвестное действие trust: %s", args.taction)
    return 2


def cmd_autolearn(args: argparse.Namespace) -> int:
    """Подкоманда ``autolearn``: фоновое обучение из интернета (до Ctrl+C)."""
    from aiav.overnight import run_autolearn

    return run_autolearn(
        hours=args.hours,
        until=args.until,
        epochs=args.epochs or None,
        epoch_pause=args.epoch_pause,
        csv_path=Path(args.csv).expanduser(),
        model_path=Path(args.model).expanduser(),
        backend=args.backend,
        retrain_every=args.retrain_every,
        max_rows=args.max_rows,
        use_ember=not args.no_ember,
    )


def cmd_monitor(args: argparse.Namespace) -> int:
    """Подкоманда ``monitor``: фоновое наблюдение за каталогами."""
    from aiav.monitor import run_monitor

    model_path = Path(args.model).expanduser()
    try:
        classifier = MalwareClassifier.load(model_path)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("%s", exc)
        return 2

    quarantine: QuarantineManager | None = None
    if args.action == "quarantine":
        try:
            quarantine = QuarantineManager(args.quarantine_dir, encrypt=not args.no_encrypt)
        except QuarantineError as exc:
            logger.error("Карантин недоступен: %s", exc)
            return 2

    cache = VerdictCache()
    trustlist = Trustlist()
    intel = ThreatIntelClient(cache=cache) if args.online else None
    scanner = FileScanner(
        classifier,
        quarantine,
        action=args.action,
        cache=cache,
        trustlist=trustlist,
        intel=intel,
        online=args.online,
        model_path=model_path,
    )
    try:
        return run_monitor(
            [Path(t).expanduser().resolve() for t in args.targets],
            scanner,
            recursive=not args.no_recursive,
        )
    except ImportError as exc:
        logger.error("%s", exc)
        return 2


def cmd_model_info(args: argparse.Namespace) -> int:
    """Подкоманда ``model-info``: сведения о сохранённой модели."""
    try:
        classifier = MalwareClassifier.load(args.model, strict_features=not args.lenient)
    except (FileNotFoundError, ValueError) as exc:
        logger.error("%s", exc)
        return 2
    print(classifier.describe())
    return 0


# --------------------------------------------------------------------------- #
# Разбор аргументов
# --------------------------------------------------------------------------- #


def _add_common_flags(target: argparse.ArgumentParser) -> None:
    """
    Общие флаги логирования.

    Добавляются и в корневой парсер, и в каждую подкоманду — иначе
    ``main.py train --dataset X -v`` падает с «unrecognized arguments»,
    а такое поведение CLI раздражает.
    """
    target.add_argument("-v", "--verbose", action="store_true",
                        help="подробный вывод (DEBUG)")
    target.add_argument("-q", "--quiet", action="store_true",
                        help="только предупреждения и ошибки")
    target.add_argument("--log-file", default=None,
                        help="дополнительно писать лог в файл")


def build_parser() -> argparse.ArgumentParser:
    """Собирает CLI (argparse, без внешних зависимостей)."""
    parser = argparse.ArgumentParser(
        prog="aiav",
        description="AI-Antivirus — статический PE-анализ + ML-классификация + карантин",
        epilog=DISCLAIMER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"aiav {__version__}")
    _add_common_flags(parser)

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- scan ---
    scan = subparsers.add_parser("scan", help="просканировать файл или каталог")
    _add_common_flags(scan)
    scan.add_argument("targets", nargs="+", help="файлы и/или каталоги для проверки")
    scan.add_argument("--model", default=str(MODELS_DIR / DEFAULT_MODEL_FILENAME),
                      help="путь к обученной модели (.joblib)")
    scan.add_argument("--action", choices=("quarantine", "report"), default="quarantine",
                      help="действие при обнаружении угрозы (по умолчанию quarantine)")
    scan.add_argument("--quarantine-dir", default=str(QUARANTINE_DIR),
                      help="каталог карантина")
    scan.add_argument("--report-dir", default=str(REPORTS_DIR), help="каталог отчётов")
    scan.add_argument("--no-report", action="store_true", help="не сохранять отчёты")
    scan.add_argument("--full-report", action="store_true",
                      help="включить в JSON-отчёт весь вектор признаков")
    scan.add_argument("--dry-run", action="store_true",
                      help="ничего не перемещать — только отчёт")
    scan.add_argument("--no-encrypt", action="store_true",
                      help="хранить объекты карантина без шифрования")
    scan.add_argument("--malicious-threshold", type=float, default=MALICIOUS_THRESHOLD,
                      help=f"порог карантина (по умолчанию {MALICIOUS_THRESHOLD})")
    scan.add_argument("--suspicious-threshold", type=float, default=SUSPICIOUS_THRESHOLD,
                      help=f"порог «подозрительно» (по умолчанию {SUSPICIOUS_THRESHOLD})")
    scan.add_argument("--limit", type=int, default=25,
                      help="сколько строк таблицы выводить в консоль")
    scan.add_argument("--lenient", action="store_true",
                      help="не падать при несовпадении схемы признаков модели")
    scan.add_argument("--online", action="store_true",
                      help="консультироваться с онлайн-репутацией по «серой зоне» "
                           "(MalwareBazaar; + VirusTotal при AIAV_VT_KEY)")
    scan.add_argument("--learn", action="store_true",
                      help="учиться на консенсусе мировых движков: складывать пары "
                           "«признаки -> вердикт движков» в CSV для переобучения "
                           "(включает --online)")
    scan.add_argument("--no-cache", action="store_true",
                      help="не использовать кэш вердиктов (принудительно разбирать всё)")
    scan.add_argument("--max-file-size", type=float, default=None, metavar="MB",
                      help=f"лимит размера разбираемого файла в МБ "
                           f"(по умолчанию {MAX_FILE_SIZE_BYTES // (1024 * 1024)}; "
                           f"крупные инсталляторы пропускаются с предупреждением)")
    scan.set_defaults(handler=cmd_scan)

    # --- train ---
    train = subparsers.add_parser("train", help="обучить модель")
    _add_common_flags(train)
    source = train.add_mutually_exclusive_group(required=True)
    source.add_argument("--dataset", help="каталог с подкаталогами malware/ и benign/")
    source.add_argument("--csv", help="CSV-датасет с колонками признаков и 'label'")
    train.add_argument("--backend", default=DEFAULT_BACKEND,
                       choices=("random_forest", "lightgbm"), help="алгоритм классификации")
    train.add_argument("--output", default=str(MODELS_DIR / DEFAULT_MODEL_FILENAME),
                       help="куда сохранить модель")
    train.add_argument("--threshold", type=float, default=MALICIOUS_THRESHOLD,
                       help="порог вердикта MALICIOUS")
    train.add_argument("--test-size", type=float, default=0.25, help="доля тестовой выборки")
    train.add_argument("--limit", type=int, default=None,
                       help="максимум образцов на класс (для быстрых прогонов)")
    train.add_argument("--jobs", type=int, default=-1, help="число потоков (-1 = все ядра)")
    train.set_defaults(handler=cmd_train)

    # --- features ---
    feats = subparsers.add_parser("features", help="показать признаки одного PE-файла")
    _add_common_flags(feats)
    feats.add_argument("path", help="путь к .exe/.dll")
    feats.set_defaults(handler=cmd_features)

    # --- quarantine ---
    quar = subparsers.add_parser("quarantine", help="управление карантином")
    _add_common_flags(quar)
    quar.add_argument("qaction", choices=("list", "restore", "purge"), help="действие")
    quar.add_argument("item_id", nargs="?", default=None, help="идентификатор объекта (или префикс)")
    quar.add_argument("--target", default=None, help="куда восстановить файл")
    quar.add_argument("--force", action="store_true", help="перезаписать существующий файл")
    quar.add_argument("--keep", action="store_true", help="не удалять запись карантина")
    quar.add_argument("--all", action="store_true", help="применить ко всем объектам")
    quar.add_argument("--quarantine-dir", default=str(QUARANTINE_DIR), help="каталог карантина")
    quar.add_argument("--no-encrypt", action="store_true", help="объекты не зашифрованы")
    quar.set_defaults(handler=cmd_quarantine)

    # --- trust ---
    trust = subparsers.add_parser("trust", help="управление списком доверия")
    _add_common_flags(trust)
    trust.add_argument("taction", choices=("add", "add-path", "remove", "list"),
                       help="действие")
    trust.add_argument("paths", nargs="*", default=[],
                       help="файлы (add), префикс каталога (add-path) или хеш/путь (remove)")
    trust.set_defaults(handler=cmd_trust)

    # --- monitor ---
    monitor = subparsers.add_parser(
        "monitor", help="фоновое наблюдение за каталогами (нужен пакет watchdog)")
    _add_common_flags(monitor)
    monitor.add_argument("targets", nargs="+", help="каталоги для наблюдения")
    monitor.add_argument("--model", default=str(MODELS_DIR / DEFAULT_MODEL_FILENAME),
                         help="путь к обученной модели (.joblib)")
    monitor.add_argument("--action", choices=("quarantine", "report"), default="quarantine",
                         help="действие при обнаружении угрозы")
    monitor.add_argument("--quarantine-dir", default=str(QUARANTINE_DIR))
    monitor.add_argument("--no-recursive", action="store_true",
                         help="не наблюдать подкаталоги")
    monitor.add_argument("--online", action="store_true",
                         help="онлайн-репутация для «серой зоны»")
    monitor.add_argument("--no-encrypt", action="store_true",
                         help="хранить объекты карантина без шифрования")
    monitor.set_defaults(handler=cmd_monitor)

    autolearn = subparsers.add_parser(
        "autolearn", aliases=["overnight"],
        help="фоновое обучение из интернета: EMBER + benign-бинарники, до Ctrl+C",
    )
    _add_common_flags(autolearn)
    autolearn.add_argument("--hours", type=float, default=None,
                           help="ограничить сессию N часами (по умолчанию — до остановки)")
    autolearn.add_argument("--until", default=None, metavar="ЧЧ:ММ",
                           help="учиться до указанного местного времени, напр. 07:00")
    autolearn.add_argument("--epochs", type=int, default=0,
                           help="предел эпох (0 = неограниченно, по умолчанию)")
    autolearn.add_argument("--epoch-pause", type=float, default=300.0,
                           help="пауза между эпохами в секундах (по умолчанию 300)")
    autolearn.add_argument("--csv", default=str(NIGHTLY_CSV),
                           help="CSV-датасет обучения (по умолчанию data/nightly/dataset.csv)")
    autolearn.add_argument("--model", default=str(MODELS_DIR / DEFAULT_MODEL_FILENAME),
                           help="куда сохранять улучшенную модель")
    autolearn.add_argument("--backend", default=DEFAULT_BACKEND,
                           choices=["random_forest", "lightgbm"],
                           help="ML-бэкенд (lightgbm заметно быстрее на больших данных)")
    autolearn.add_argument("--retrain-every", type=int, default=10000,
                           help="переобучаться каждые N строк (по умолчанию 10000)")
    autolearn.add_argument("--max-rows", type=int, default=0,
                           help="предел строк данных (0 = без лимита, по умолчанию)")
    autolearn.add_argument("--no-ember", action="store_true",
                           help="не скачивать EMBER (только benign-бинарники)")
    autolearn.set_defaults(handler=cmd_autolearn)

    # --- model-info ---
    info = subparsers.add_parser("model-info", help="сведения о модели")
    _add_common_flags(info)
    info.add_argument("--model", default=str(MODELS_DIR / DEFAULT_MODEL_FILENAME))
    info.add_argument("--lenient", action="store_true",
                      help="не падать при несовпадении схемы признаков")
    info.set_defaults(handler=cmd_model_info)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Точка входа CLI. Возвращает код возврата процесса."""
    parser = build_parser()
    args = parser.parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=level, log_file=args.log_file, quiet=args.quiet)

    if not args.quiet:
        print(BANNER)
        logger.debug(DISCLAIMER)

    handler = getattr(args, "handler", None)
    if handler is None:  # защита на случай добавления подкоманды без handler
        parser.print_help()
        return 2
    try:
        return int(handler(args))
    except KeyboardInterrupt:
        logger.warning("Прервано пользователем")
        return 130
    except Exception as exc:  # noqa: BLE001 — аккуратный вывод вместо трейсбека
        logger.exception("Критическая ошибка: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
