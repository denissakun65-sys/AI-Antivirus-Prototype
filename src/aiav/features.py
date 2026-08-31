"""
Извлечение статических признаков из PE-файлов (Portable Executable).

Модуль превращает ``.exe``/``.dll`` в фиксированный вектор числовых признаков,
который можно скормить любой ML-модели. Порядок признаков задаётся константой
:data:`FEATURE_NAMES` и **не должен меняться** между обучением и инференсом —
иначе модель начнёт интерпретировать колонки неверно.

Используемые группы признаков
-----------------------------
1. **Базовая геометрия** — размеры файла, заголовков, число секций.
2. **Энтропия** — Shannon-энтропия всего файла и каждой секции
   (упакованные/зашифрованные образцы имеют энтропию > 7.0).
3. **Импорты** — количество DLL/функций и наличие «тревожных» API
   (инъекции, отладка, работа с реестром, сеть, криптография).
4. **Флаги и аномалии заголовков** — ``DLL``, ``UPX``, ``DEBUG``, 32/64 бит,
   повреждённые заголовки, TLS-callbacks, оверлей.

Типичные ошибки разбора (обрубленный файл, не-PE, нет прав) перехватываются
и превращаются в :class:`PEFeatureError`, чтобы один «битый» файл не ронял
весь проход сканирования.
"""

from __future__ import annotations

import hashlib
import math
import os
from collections import Counter
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

try:  # pefile объявлен в requirements.txt, но даём понятную ошибку при его отсутствии
    import pefile
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Не установлена библиотека 'pefile'. Выполните: pip install -r requirements.txt"
    ) from exc

from aiav.config import MAX_FILE_SIZE_BYTES, PE_EXTENSIONS, PE_MAGIC_SIGNATURES
from aiav.logging_setup import get_logger

logger = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Каталог признаков
# --------------------------------------------------------------------------- #

#: Имена признаков в строгом порядке. Модель хранит этот список в метаданных
#: и сверяет его при загрузке (см. :mod:`aiav.model`).
FEATURE_NAMES: tuple[str, ...] = (
    # --- геометрия файла ---
    "virtual_size",               # SizeOfImage (виртуальный размер образа)
    "raw_size",                   # фактический размер файла на диске
    "header_size",                # SizeOfHeaders
    "num_sections",               # количество секций
    "num_imports_dll",            # количество импортируемых DLL
    "num_imports_funcs",          # общее количество импортируемых функций
    "num_resources",              # количество записей в таблице ресурсов
    "num_data_directories",       # заполненные элементы Data Directory
    "num_symbols",                # число символов в COFF Symbol Table
    "size_of_optional_header",    # размер optional header
    "size_of_code",               # суммарный размер кода
    "size_of_initialized_data",   # размер инициализированных данных
    "size_of_uninitialized_data", # размер неинициализированных данных
    "entrypoint_offset",          # смещение точки входа
    "overlay_size",               # размер «хвоста» после последней секции
    # --- энтропия ---
    "entropy_overall",            # энтропия всего файла, бит/байт (0..8)
    "entropy_min_section",
    "entropy_max_section",
    "entropy_mean_section",
    "entropy_std_section",
    # --- соотношение размеров (признак упаковщика) ---
    "ratio_raw_to_virtual",
    "max_section_virtual_raw_gap",
    # --- флаги заголовков ---
    "is_dll",
    "is_driver",
    "is_64bit",
    "has_debug_directory",
    "has_tls_callbacks",
    "num_tls_callbacks",
    "has_relocations",
    "has_signature",              # наличие каталога Security (Authenticode)
    "has_resources",
    "has_imports",
    "has_exceptions",
    "is_upx_packed",
    "is_header_anomalous",        # повреждённые/противоречивые заголовки
    "checksum_mismatch",
    # --- импорты: «тревожные» API ---
    "imports_process_injection",
    "imports_memory_ops",
    "imports_registry_ops",
    "imports_process_execution",
    "imports_network_ops",
    "imports_crypto_ops",
    "imports_file_ops",
    "imports_service_ops",
    "imports_suspicious_count",
    # --- ресурсы ---
    "resources_total_bytes",
)

N_FEATURES: int = len(FEATURE_NAMES)

# --------------------------------------------------------------------------- #
# Списки «тревожных» API (эвристика, основанная на общедоступных исследованиях
# EMBER / MalwareBazaar; не является сигнатурным детектом).
# --------------------------------------------------------------------------- #

#: Инъекции кода в чужие процессы и манипуляции с потоками.
PROCESS_INJECTION_APIS: frozenset[str] = frozenset(
    {
        "WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
        "ReadProcessMemory", "NtReadVirtualMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
        "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread",
        "SetThreadContext", "GetThreadContext", "NtSetContextThread",
        "VirtualAllocEx", "VirtualAllocExNuma", "NtAllocateVirtualMemory",
        "VirtualProtectEx", "NtProtectVirtualMemory",
        "MapViewOfFile", "MapViewOfFile2",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
        "SuspendThread", "ResumeThread", "NtSuspendThread",
        "NtMapViewOfSection", "CreateProcessInternalW",
    }
)

#: Работа с памятью и загрузкой модулей «вручную».
MEMORY_APIS: frozenset[str] = frozenset(
    {
        "VirtualAlloc", "VirtualProtect", "VirtualFree", "VirtualQuery",
        "HeapAlloc", "HeapCreate", "GlobalAlloc", "LocalAlloc",
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    }
)

#: Реестр: автозапуск, персистентность, отключение защиты.
REGISTRY_APIS: frozenset[str] = frozenset(
    {
        "RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "RegSetValueExA", "RegSetValueExW", "RegDeleteKeyA", "RegDeleteKeyW",
        "RegDeleteValueA", "RegDeleteValueW", "RegQueryValueExA", "RegQueryValueExW",
        "RegCloseKey", "RegEnumKeyExA", "RegEnumKeyExW", "RegNotifyChangeKeyValue",
    }
)

#: Создание/перечисление/завершение процессов.
PROCESS_EXECUTION_APIS: frozenset[str] = frozenset(
    {
        "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA",
        "CreateProcessAsUserW", "CreateProcessWithLogonW",
        "CreateProcessWithTokenW", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExA", "ShellExecuteExW", "WinExec", "system",
        "TerminateProcess", "NtTerminateProcess", "OpenProcess",
        "GetCurrentProcess", "GetCurrentProcessId", "Process32First",
        "Process32Next", "CreateToolhelp32Snapshot", "Module32First",
        "Module32Next", "ExitProcess", "NtQueryInformationProcess",
    }
)

#: Сеть: C2-связь, загрузка полезной нагрузки, разведка.
NETWORK_APIS: frozenset[str] = frozenset(
    {
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetConnectA", "InternetConnectW", "InternetReadFile",
        "InternetWriteFile", "InternetCloseHandle", "InternetSetOptionA",
        "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
        "HttpQueryInfoA", "HttpQueryInfoW",
        "WSAStartup", "WSASocketA", "WSASocketW", "WSASend", "WSARecv",
        "socket", "connect", "send", "recv", "gethostbyname", "getaddrinfo",
        "inet_addr", "inet_pton", "DnsQuery_A", "DnsQuery_W",
        "URLDownloadToFileA", "URLDownloadToFileW", "FtpGetFileA", "FtpGetFileW",
        "NetUserAdd", "WNetAddConnection2A", "WNetAddConnection2W",
    }
)

#: Криптография: шифрование полезной нагрузки / файлы-шифровальщики.
CRYPTO_APIS: frozenset[str] = frozenset(
    {
        "CryptAcquireContextA", "CryptAcquireContextW", "CryptGenKey",
        "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptHashData",
        "CryptDeriveKey", "CryptImportKey", "CryptExportKey", "CryptDestroyKey",
        "CryptReleaseContext", "CryptStringToBinaryA", "CryptBinaryToStringA",
        "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
        "BCryptGenerateSymmetricKey", "BCryptCreateHash",
    }
)

#: Файловые операции и поиск данных на диске.
FILE_APIS: frozenset[str] = frozenset(
    {
        "CreateFileA", "CreateFileW", "CreateFile2", "DeleteFileA", "DeleteFileW",
        "MoveFileA", "MoveFileW", "MoveFileExA", "MoveFileExW", "CopyFileA",
        "CopyFileW", "FindFirstFileA", "FindFirstFileW", "FindNextFileA",
        "FindNextFileW", "FindFirstFileExA", "FindFirstFileExW",
        "SetFileAttributesA", "SetFileAttributesW", "GetFileAttributesA",
        "GetFileAttributesW", "GetFileAttributesExW", "ReadFile", "WriteFile",
        "SetFileTime", "GetTempPathA", "GetTempPathW", "CreateDirectoryA",
        "CreateDirectoryW", "RemoveDirectoryA", "RemoveDirectoryW",
    }
)

#: Службы, драйверы, отладка, снимки экрана, буфер обмена.
SERVICE_APIS: frozenset[str] = frozenset(
    {
        "OpenSCManagerA", "OpenSCManagerW", "OpenServiceA", "OpenServiceW",
        "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW",
        "ControlService", "DeleteService", "ChangeServiceConfigA",
        "ChangeServiceConfigW", "RegisterServiceCtrlHandlerA",
        "RegisterServiceCtrlHandlerW", "StartServiceCtrlDispatcherA",
        "StartServiceCtrlDispatcherW", "NtLoadDriver", "DeviceIoControl",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "OutputDebugStringW", "DebugActiveProcess",
        "BitBlt", "GetDC", "GetDesktopWindow", "GetAsyncKeyState",
        "GetKeyState", "GetClipboardData", "OpenClipboard", "SetWindowsHookExA",
        "SetWindowsHookExW", "GetForegroundWindow", "EnumWindows",
        "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
        "OpenProcessToken", "GetTokenInformation", "ImpersonateLoggedOnUser",
    }
)

#: Все «тревожные» API одним множеством — для суммарного счётчика.
SUSPICIOUS_APIS: frozenset[str] = (
    PROCESS_INJECTION_APIS
    | MEMORY_APIS
    | REGISTRY_APIS
    | PROCESS_EXECUTION_APIS
    | NETWORK_APIS
    | CRYPTO_APIS
    | FILE_APIS
    | SERVICE_APIS
)

#: Группы -> счётчики признаков (порядок не важен, имена должны совпадать
#: с FEATURE_NAMES).
_API_GROUPS: dict[str, frozenset[str]] = {
    "imports_process_injection": PROCESS_INJECTION_APIS,
    "imports_memory_ops": MEMORY_APIS,
    "imports_registry_ops": REGISTRY_APIS,
    "imports_process_execution": PROCESS_EXECUTION_APIS,
    "imports_network_ops": NETWORK_APIS,
    "imports_crypto_ops": CRYPTO_APIS,
    "imports_file_ops": FILE_APIS,
    "imports_service_ops": SERVICE_APIS,
}

# Имена секций, характерные для популярных упаковщиков.
_PACKER_SECTION_NAMES: frozenset[str] = frozenset(
    {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", "MPRESS1", "MPRESS2", ".themida",
     ".vmp0", ".vmp1", ".enigma1", ".enigma2", ".petite", "FSG!", ".nsp0", ".nsp1"}
)


# --------------------------------------------------------------------------- #
# Исключения и контейнер признаков
# --------------------------------------------------------------------------- #


class PEFeatureError(Exception):
    """Файл не удалось разобрать как PE (не PE, повреждён, слишком велик, нет прав)."""


@dataclass(slots=True)
class PEFeatures:
    """
    Результат разбора одного файла.

    :ivar path: исходный путь файла.
    :ivar sha256: SHA-256 файла (удобно для IOC и дедупликации в карантине).
    :ivar size: размер файла в байтах.
    :ivar values: словарь признак -> значение.
    """

    path: Path
    sha256: str = ""
    size: int = 0
    values: dict[str, float] = field(default_factory=dict)

    def to_vector(self) -> list[float]:
        """Вектор признаков в порядке :data:`FEATURE_NAMES`."""
        return [float(self.values.get(name, 0.0)) for name in FEATURE_NAMES]

    def to_dict(self) -> dict[str, float]:
        """Словарь признаков (для pandas / CSV-датасетов)."""
        return {name: float(self.values.get(name, 0.0)) for name in FEATURE_NAMES}

    def to_dataset_row(self, label: int | None = None) -> dict[str, object]:
        """Строка датасета: признаки + служебные поля (путь, хеш, метка)."""
        row: dict[str, object] = {"path": str(self.path), "sha256": self.sha256,
                                  "size": self.size}
        row.update(self.to_dict())
        if label is not None:
            row["label"] = int(label)
        return row


# --------------------------------------------------------------------------- #
# Вспомогательные функции
# --------------------------------------------------------------------------- #


def sha256_of(path: str | Path, chunk_size: int = 1 << 20) -> str:
    """Считает SHA-256 файла поблочно (не грузит файл целиком в память)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def shannon_entropy(data: bytes | bytearray | memoryview) -> float:
    """
    Shannon-энтропия в битах на байт (0..8).

    0 — все байты одинаковы (нулевая секция), ~4-6 — обычный код,
    > 7.2 — сжатые/зашифрованные данные (признак упаковщика).
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return round(float(entropy), 6)


def file_entropy(path: str | Path, chunk_size: int = 1 << 20) -> float:
    """
    Энтропия всего файла. Читает файл поблочно, поэтому подходит и для
    больших образов (в память попадает только гистограмма на 256 счётчиков).
    """
    histogram = np.zeros(256, dtype=np.int64)
    total = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            histogram += np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
            total += len(chunk)
    if total == 0:
        return 0.0
    probabilities = histogram / total
    nonzero = probabilities[probabilities > 0]
    return round(float(-(nonzero * np.log2(nonzero)).sum()), 6)


def fast_entropy(path: str | Path, sample_limit: int = 8 * 1024 * 1024) -> float:
    """
    Энтропия для «быстрого» предварительного отбора (без полного чтения файла).

    Читает не более ``sample_limit`` байт — достаточно, чтобы отбросить
    очевидно пустые/однородные файлы до дорогого разбора PE.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            data = handle.read(min(size, sample_limit))
        return shannon_entropy(data)
    except OSError as exc:
        logger.debug("fast_entropy(%s) не удалась: %s", path, exc)
        return 0.0


def has_pe_extension(path: str | Path) -> bool:
    """Расширение из «исполняемого» списка (может быть подменено, но это сигнал)."""
    return Path(path).suffix.lower() in PE_EXTENSIONS


def is_pe_file(path: str | Path) -> bool:
    """
    Дешёвая проверка «похож ли файл на PE» по сигнатуре (``MZ``/``NE``/``LE``).

    Не заменяет полный разбор, но позволяет не тратить время на картинки,
    документы и прочий мусор при сканировании больших каталогов.
    """
    p = Path(path)
    try:
        with open(p, "rb") as handle:
            head = handle.read(2)
        return head in PE_MAGIC_SIGNATURES
    except OSError as exc:
        logger.debug("is_pe_file(%s): %s", p, exc)
        return False


def is_pe_candidate(path: str | Path) -> bool:
    """
    Является ли файл кандидатом на PE-разбор.

    Проверяется и сигнатура, и расширение: ``loader.bin`` со сигнатурой ``MZ``
    попадёт в разбор, а ``broken.exe`` без сигнатуры — тоже (но уже как ошибка
    разбора, а не молчаливый пропуск). Это важно: маскировка расширения —
    обычный приём, и сканер не должен его «проглатывать».
    """
    return is_pe_file(path) or has_pe_extension(path)


def iter_pe_files(directory: str | Path, follow_symlinks: bool = False) -> Iterator[Path]:
    """
    Рекурсивно перечисляет PE-кандидатов в каталоге.

    Символические ссылки пропускаются (защита от петель и от подмены цели),
    ошибки доступа к отдельным подкаталогам логируются и не прерывают обход.
    """
    root = Path(directory)
    if not root.exists():
        raise FileNotFoundError(f"Каталог не найден: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Это не каталог: {root}")

    for path in sorted(root.rglob("*")):
        try:
            if path.is_symlink() and not follow_symlinks:
                logger.debug("Пропуск симлинка: %s", path)
                continue
            if not path.is_file():
                continue
            if is_pe_candidate(path):
                yield path
        except OSError as exc:  # нет прав на stat — продолжаем обход
            logger.warning("Нет доступа к %s: %s", path, exc)


# --------------------------------------------------------------------------- #
# Основная функция извлечения признаков
# --------------------------------------------------------------------------- #


def extract_pe_features(
    path: str | Path,
    *,
    compute_hash: bool = True,
    max_file_size: int = MAX_FILE_SIZE_BYTES,
) -> PEFeatures:
    """
    Извлекает полный вектор признаков из одного PE-файла.

    :param path: путь к ``.exe``/``.dll``.
    :param compute_hash: считать ли SHA-256 (нужен для карантина и IOC).
    :param max_file_size: лимит размера файла.
    :raises PEFeatureError: файл не является валидным PE или недоступен.
    :return: заполненный :class:`PEFeatures`.
    """
    file_path = Path(path).expanduser().resolve()
    pe: pefile.PE | None = None

    try:
        if not file_path.exists():
            raise PEFeatureError(f"Файл не найден: {file_path}")
        if not file_path.is_file():
            raise PEFeatureError(f"Не является файлом: {file_path}")

        size = file_path.stat().st_size
        if size == 0:
            raise PEFeatureError("Файл пуст (0 байт)")
        if size > max_file_size:
            raise PEFeatureError(
                f"Файл слишком велик: {size} > {max_file_size} байт"
            )

        logger.debug("Разбираю PE: %s (%d байт)", file_path, size)
        # fast_load пропускает разбор ресурсов/импортов — их грузим явно ниже.
        pe = pefile.PE(str(file_path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"],
            ]
        )

        features = PEFeatures(
            path=file_path,
            sha256=sha256_of(file_path) if compute_hash else "",
            size=size,
        )
        values: dict[str, float] = dict.fromkeys(FEATURE_NAMES, 0.0)

        _fill_header_features(pe, values, size)
        _fill_section_features(pe, values)
        try:  # энтропия всего файла — отдельный проход по диску
            values["entropy_overall"] = file_entropy(file_path)
        except OSError as exc:
            logger.warning("Не удалось вычислить энтропию %s: %s", file_path.name, exc)
        _fill_import_features(pe, values)
        _fill_resource_features(pe, values)
        _fill_anomaly_features(pe, values)

        features.values = values
        logger.debug(
            "Извлечено признаков: %d | энтропия=%.2f | секций=%d | импортов=%d",
            N_FEATURES,
            values["entropy_overall"],
            int(values["num_sections"]),
            int(values["num_imports_funcs"]),
        )
        return features

    except PEFeatureError:
        raise
    except pefile.PEFormatError as exc:
        raise PEFeatureError(f"Некорректный PE-заголовок ({file_path}): {exc}") from exc
    except (OSError, PermissionError) as exc:
        raise PEFeatureError(f"Нет доступа к файлу ({file_path}): {exc}") from exc
    except Exception as exc:  # noqa: BLE001 — последний рубеж: скан не должен падать
        raise PEFeatureError(f"Непредвиденная ошибка разбора {file_path}: {exc}") from exc
    finally:
        if pe is not None:
            pe.close()


def extract_many(
    paths: Iterable[str | Path],
    *,
    label: int | None = None,
    stop_on_error: bool = False,
) -> list[PEFeatures]:
    """
    Пакетное извлечение. Ошибочные файлы пропускаются (или прерывают цикл,
    если задан ``stop_on_error=True``).

    :param label: необязательная метка для каждого образца (1 — malware, 0 — benign).
    """
    results: list[PEFeatures] = []
    for path in paths:
        try:
            results.append(extract_pe_features(path))
        except PEFeatureError as exc:
            logger.warning("Пропуск %s: %s", path, exc)
            if stop_on_error:
                raise
    logger.info("Извлечено признаков из %d файл(ов)", len(results))
    return results


# --------------------------------------------------------------------------- #
# Внутренние «заполнители» признаков
# --------------------------------------------------------------------------- #


def _fill_header_features(pe: pefile.PE, v: dict[str, float], file_size: int) -> None:
    """Признаки из DOS/NT/FILE/OPTIONAL заголовков."""
    file_header = pe.FILE_HEADER
    optional = pe.OPTIONAL_HEADER

    v["header_size"] = float(getattr(optional, "SizeOfHeaders", 0))
    v["virtual_size"] = float(getattr(optional, "SizeOfImage", 0))
    v["raw_size"] = float(file_size)
    v["size_of_optional_header"] = float(file_header.SizeOfOptionalHeader)
    v["num_symbols"] = float(getattr(file_header, "NumberOfSymbols", 0))
    v["num_data_directories"] = float(
        sum(1 for entry in getattr(optional, "DATA_DIRECTORY", []) if entry.VirtualAddress)
    )

    if optional is not None:
        v["size_of_code"] = float(optional.SizeOfCode)
        v["size_of_initialized_data"] = float(optional.SizeOfInitializedData)
        v["size_of_uninitialized_data"] = float(optional.SizeOfUninitializedData)
        v["entrypoint_offset"] = float(optional.AddressOfEntryPoint)

    characteristics = file_header.Characteristics
    v["is_dll"] = float(bool(characteristics & pefile.IMAGE_CHARACTERISTICS["IMAGE_FILE_DLL"]))
    v["is_driver"] = float(
        bool(characteristics & pefile.IMAGE_CHARACTERISTICS["IMAGE_FILE_SYSTEM"])
    )
    v["is_64bit"] = float(
        optional.Magic in (pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS,) if optional else False
    )
    v["has_relocations"] = float(
        bool(characteristics & pefile.IMAGE_CHARACTERISTICS["IMAGE_FILE_RELOCS_STRIPPED"]) is False
    )

    # Каталоги данных
    v["has_imports"] = float(hasattr(pe, "DIRECTORY_ENTRY_IMPORT"))
    v["has_resources"] = float(hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"))
    v["has_debug_directory"] = float(hasattr(pe, "DIRECTORY_ENTRY_DEBUG"))
    v["has_signature"] = float(hasattr(pe, "DIRECTORY_ENTRY_SECURITY"))
    v["has_exceptions"] = float(hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION"))

    v["overlay_size"] = float(_overlay_size(pe, file_size))


def _overlay_size(pe: pefile.PE, file_size: int) -> int:
    """
    Размер оверлея — данных, дописанных после последней секции.

    Часто используется для «пришивания» полезной нагрузки или стеганографии,
    поэтому это сильный самостоятельный признак.
    """
    try:
        end_of_sections = 0
        for section in pe.sections:
            end = int(section.PointerToRawData) + int(section.SizeOfRawData)
            end_of_sections = max(end_of_sections, end)
        return max(0, file_size - end_of_sections)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Не удалось вычислить оверлей: %s", exc)
        return 0


def _fill_section_features(pe: pefile.PE, v: dict[str, float]) -> None:
    """Секции: количество, энтропия, аномалии размеров, упаковщики."""
    sections = list(getattr(pe, "sections", []) or [])
    v["num_sections"] = float(len(sections))
    if not sections:
        return

    entropies: list[float] = []
    max_gap = 0
    upx_like = False

    for section in sections:
        try:
            data = section.get_data()
        except Exception as exc:  # noqa: BLE001 — битая секция не роняет разбор
            logger.debug("Секция без данных (%r): %s", section.Name, exc)
            data = b""

        entropies.append(shannon_entropy(data))

        virtual = int(section.Misc_VirtualSize)
        raw = int(section.SizeOfRawData)
        max_gap = max(max_gap, max(0, virtual - raw))

        name = _decode_name(section.Name)
        if name.upper() in _PACKER_SECTION_NAMES or name.upper().startswith("UPX"):
            upx_like = True

    v["entropy_min_section"] = round(min(entropies), 6)
    v["entropy_max_section"] = round(max(entropies), 6)
    v["entropy_mean_section"] = round(float(np.mean(entropies)), 6)
    v["entropy_std_section"] = round(float(np.std(entropies)), 6)
    v["max_section_virtual_raw_gap"] = float(max_gap)
    v["is_upx_packed"] = float(upx_like)

    virtual_size = float(v["virtual_size"])
    v["ratio_raw_to_virtual"] = round(float(v["raw_size"]) / virtual_size, 6) if virtual_size else 0.0


def _fill_import_features(pe: pefile.PE, v: dict[str, float]) -> None:
    """Импорты: количество + счётчики по группам «тревожных» API."""
    entry = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
    if not entry:
        return

    dll_count = 0
    func_count = 0
    counters: Counter[str] = Counter()

    for dll_entry in entry:
        dll_count += 1
        for imp in dll_entry.imports:
            func_count += 1
            name = imp.name.decode("ascii", errors="ignore") if imp.name else ""
            if not name:
                continue  # импорт по ординалу — имени нет
            for feature_name, api_set in _API_GROUPS.items():
                if name in api_set:
                    counters[feature_name] += 1
            if name in SUSPICIOUS_APIS:
                counters["imports_suspicious_count"] += 1

    v["num_imports_dll"] = float(dll_count)
    v["num_imports_funcs"] = float(func_count)
    for feature_name in _API_GROUPS:
        v[feature_name] = float(counters[feature_name])
    v["imports_suspicious_count"] = float(counters["imports_suspicious_count"])


def _fill_resource_features(pe: pefile.PE, v: dict[str, float]) -> None:
    """Ресурсы: количество записей и суммарный объём (в них часто прячут payload)."""
    entry = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if not entry:
        return
    try:
        count = 0
        total_bytes = 0
        # Таблица ресурсов — трёхуровневое дерево: type -> id -> language.
        for res_type in getattr(entry, "entries", []) or []:
            type_dir = getattr(res_type, "directory", None)
            for res_id in getattr(type_dir, "entries", []) or []:
                id_dir = getattr(res_id, "directory", None)
                for res_lang in getattr(id_dir, "entries", []) or []:
                    data_entry = getattr(res_lang, "data", None)
                    struct = getattr(data_entry, "struct", None)
                    if struct is not None:
                        count += 1
                        total_bytes += int(getattr(struct, "Size", 0) or 0)
        v["num_resources"] = float(count)
        v["resources_total_bytes"] = float(total_bytes)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Не удалось разобрать ресурсы: %s", exc)


def _fill_anomaly_features(pe: pefile.PE, v: dict[str, float]) -> None:
    """Аномалии: TLS-callbacks, повреждённые заголовки, несовпадение checksum."""
    # --- TLS-callbacks: классический способ выполнить код до main() ---
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is not None:
        v["has_tls_callbacks"] = 1.0
        v["num_tls_callbacks"] = float(_count_tls_callbacks(pe, tls))

    # --- Противоречивые заголовки ---
    optional = pe.OPTIONAL_HEADER
    anomalies = 0
    if optional is not None:
        if optional.SizeOfImage < optional.SizeOfHeaders:
            anomalies += 1
        if pe.sections and optional.AddressOfEntryPoint == 0 and not v["is_dll"]:
            anomalies += 1
        for section in pe.sections:
            # Секция без имени или с нечитаемым именем — подозрительно.
            if not _decode_name(section.Name):
                anomalies += 1
                break
    if not pe.sections:
        anomalies += 1
    v["is_header_anomalous"] = float(anomalies > 0)

    # --- Checksum: у «честных» подписанных бинарников он совпадает,
    #     у собранных вручную/пропатченных образцов — почти всегда нет. ---
    try:
        if optional is not None:
            declared = int(getattr(optional, "CheckSum", 0) or 0)
            if declared:
                computed = pe.generate_checksum()
                v["checksum_mismatch"] = float(computed != declared)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Проверка checksum пропущена: %s", exc)


def _count_tls_callbacks(pe: pefile.PE, tls) -> int:
    """Считает TLS-callback'и, читая массив указателей (терминатор — 0)."""
    try:
        callbacks_rva = int(tls.struct.AddressOfCallBacks)
        if not callbacks_rva:
            return 0
        pointer_size = 8 if _is_pe64(pe) else 4
        count = 0
        # Разумный потолок, чтобы не читать мусор до конца файла.
        while count < 512:
            raw = pe.get_data(callbacks_rva + count * pointer_size, pointer_size)
            if len(raw) < pointer_size:
                break
            if int.from_bytes(raw, "little") == 0:  # конец массива
                break
            count += 1
        return count
    except Exception as exc:  # noqa: BLE001
        logger.debug("Подсчёт TLS-callbacks не удался: %s", exc)
        return 0


def _is_pe64(pe: pefile.PE) -> bool:
    """PE32+ (64-битный) образ?"""
    optional = pe.OPTIONAL_HEADER
    return optional is not None and optional.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS


def _decode_name(raw: Sequence[int] | bytes | None) -> str:
    """Безопасно декодирует имя секции (8 байт, без завершающего нуля)."""
    if not raw:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        data: bytes = bytes(raw)
    else:
        data = bytes(bytearray(raw))
    return data.split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()


__all__ = [
    "FEATURE_NAMES",
    "N_FEATURES",
    "PEFeatureError",
    "PEFeatures",
    "extract_pe_features",
    "extract_many",
    "iter_pe_files",
    "is_pe_file",
    "is_pe_candidate",
    "has_pe_extension",
    "shannon_entropy",
    "file_entropy",
    "fast_entropy",
    "sha256_of",
    "SUSPICIOUS_APIS",
]
