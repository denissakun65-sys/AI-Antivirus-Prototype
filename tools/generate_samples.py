#!/usr/bin/env python3
"""
Генератор синтетических PE-файлов для тестов и демонстрации.

Зачем это нужно
---------------
Настоящие вредоносные образцы нельзя коммитить в репозиторий, а обучать и
тестировать сканер на чём-то нужно. Этот скрипт собирает **валидные** PE-файлы
с нуля (DOS-заголовок, NT-заголовки, секции, таблица импортов, ресурсы, TLS),
которые корректно разбираются библиотекой ``pefile``, но имеют настраиваемые
характеристики: энтропию, набор импортов, число секций, признаки упаковщика.

Файлы НЕ являются исполняемой полезной нагрузкой — в ``.text`` лежат только
байты-заполнители. Это чистые «манекены» для проверки конвейера извлечения
признаков.

Поддерживаются PE32 (x86) и PE32+ (x64): размеры полей-указателей в optional
header, таблице импортов и TLS-директории отличаются, и это учтено.

Использование
-------------
.. code-block:: bash

    # датасет: 60 «вредоносных» и 60 «безопасных» образцов
    python tools/generate_samples.py --out data/samples --per-class 60

    # один файл для ручной проверки
    python tools/generate_samples.py --single /tmp/test.exe --profile malicious --machine x64
"""

from __future__ import annotations

import argparse
import random
import struct
import sys
import zlib
from collections.abc import Sequence
from pathlib import Path

IMAGE_BASE = 0x400000
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
SUBSYSTEM_WINDOWS_GUI = 2

MACHINE_I386 = 0x14C
MACHINE_AMD64 = 0x8664

# Типичный «безопасный» набор импортов обычного GUI-приложения.
BENIGN_IMPORTS: dict[str, list[str]] = {
    "KERNEL32.dll": [
        "GetModuleHandleW", "GetProcAddress", "LoadLibraryW", "ExitProcess",
        "GetLastError", "HeapAlloc", "HeapFree", "GetCommandLineW",
        "InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
        "DeleteCriticalSection", "GetCurrentThreadId", "CloseHandle",
        "CreateFileW", "ReadFile", "WriteFile",
    ],
    "USER32.dll": [
        "MessageBoxW", "RegisterClassExW", "CreateWindowExW", "ShowWindow",
        "UpdateWindow", "GetMessageW", "TranslateMessage", "DispatchMessageW",
        "PostQuitMessage", "DefWindowProcW",
    ],
    "GDI32.dll": ["CreateFontW", "SelectObject", "DeleteObject", "TextOutW"],
    "msvcrt.dll": ["malloc", "free", "printf", "memcpy", "strlen", "exit"],
}

# Набор, характерный для загрузчиков/дроперов/инъекторов (учебная эвристика).
MALICIOUS_IMPORTS: dict[str, list[str]] = {
    "KERNEL32.dll": [
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "QueueUserAPC", "SetThreadContext", "GetThreadContext",
        "OpenProcess", "CreateProcessW", "TerminateProcess", "LoadLibraryA",
        "GetProcAddress", "GetModuleHandleA", "ExitProcess", "CreateFileW",
        "DeleteFileW", "MoveFileExW", "GetTempPathW", "CreateToolhelp32Snapshot",
        "Process32First", "Process32Next", "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", "Sleep", "GetTickCount",
    ],
    "ADVAPI32.dll": [
        "RegOpenKeyExW", "RegCreateKeyExW", "RegSetValueExW", "RegDeleteValueW",
        "RegQueryValueExW", "RegCloseKey", "OpenSCManagerW", "CreateServiceW",
        "StartServiceW", "OpenProcessToken", "AdjustTokenPrivileges",
        "LookupPrivilegeValueW", "CryptAcquireContextW", "CryptGenKey",
        "CryptEncrypt", "CryptDecrypt",
    ],
    "WS2_32.dll": [
        "WSAStartup", "socket", "connect", "send", "recv", "closesocket",
        "gethostbyname", "inet_addr", "htons",
    ],
    "WININET.dll": [
        "InternetOpenW", "InternetOpenUrlW", "InternetReadFile",
        "InternetCloseHandle", "HttpSendRequestW",
    ],
    "URLMON.dll": ["URLDownloadToFileW"],
    "SHELL32.dll": ["ShellExecuteW", "SHGetFolderPathW"],
}


def align_up(value: int, alignment: int) -> int:
    """Округляет значение вверх до границы выравнивания."""
    if alignment <= 0:
        return value
    return (value + alignment - 1) // alignment * alignment


def _pad_to(data: bytearray, offset: int, filler: bytes = b"\x00") -> None:
    """Дополняет буфер до нужного смещения."""
    while len(data) < offset:
        data += filler[: max(1, offset - len(data))]


# --------------------------------------------------------------------------- #
# Отдельные структуры
# --------------------------------------------------------------------------- #


def build_resource_directory(section_rva: int) -> bytes:
    """
    Собирает минимальное дерево ресурсов: type -> id -> language -> data.

    Смещения поддеревьев задаются относительно начала самой секции ресурсов
    (так требует IMAGE_RESOURCE_DIRECTORY), поэтому структура собирается
    послойно, а не «на глаз». Размеры взяты из pefile:
    ``IMAGE_RESOURCE_DIRECTORY`` = 16 байт, ``..._DIRECTORY_ENTRY`` = 8,
    ``IMAGE_RESOURCE_DATA_ENTRY`` = 16.
    """
    dir_header_size = 16
    dir_entry_size = 8
    data_entry_size = 16
    level_size = dir_header_size + dir_entry_size          # 24 (по одной записи)

    payload = b"AI-Antivirus sample resource" + b"\x00" * 20

    id_dir_offset = level_size                             # 24
    lang_dir_offset = level_size * 2                       # 48
    data_entry_offset = level_size * 3                     # 72
    payload_offset = data_entry_offset + data_entry_size   # 88

    def directory(num_id_entries: int = 1) -> bytes:
        """IMAGE_RESOURCE_DIRECTORY — ровно 16 байт."""
        packed = struct.pack(
            "<IIHHHH",
            0,                # Characteristics
            0,                # TimeDateStamp
            0, 0,             # MajorVersion, MinorVersion
            0,                # NumberOfNamedEntries
            num_id_entries,   # NumberOfIdEntries
        )
        assert len(packed) == dir_header_size, len(packed)
        return packed

    blob = bytearray()
    # Уровень 1: типы ресурсов (RT_VERSION = 16)
    blob += directory()
    blob += struct.pack("<II", 16, 0x80000000 | id_dir_offset)
    # Уровень 2: идентификаторы
    blob += directory()
    blob += struct.pack("<II", 1, 0x80000000 | lang_dir_offset)
    # Уровень 3: языки (0 = нейтральный)
    blob += directory()
    blob += struct.pack("<II", 0, data_entry_offset)
    # IMAGE_RESOURCE_DATA_ENTRY: RVA данных, размер, codepage, reserved
    blob += struct.pack("<IIII", section_rva + payload_offset, len(payload), 0, 0)

    assert len(blob) == payload_offset, f"сбой разметки ресурсов: {len(blob)} != {payload_offset}"
    blob += payload
    return bytes(blob)


def build_tls_directory(section_rva: int, text_rva: int, *, pe32_plus: bool = False) -> bytes:
    """
    Собирает IMAGE_TLS_DIRECTORY с двумя callback'ами (терминатор — 0).

    TLS-callback выполняется до точки входа — популярный приём антианализа,
    поэтому признак ``num_tls_callbacks`` должен на нём срабатывать.

    :param pe32_plus: для PE32+ (x64) указатели 8-байтовые
        (IMAGE_TLS_DIRECTORY64), структура занимает 40 байт вместо 24.
    """
    ptr = "Q" if pe32_plus else "I"
    ptr_fmt = f"<{ptr * 4}I"
    header_size = struct.calcsize(ptr_fmt)                 # 24 (PE32) / 40 (PE32+)
    callback_array_offset = header_size + 16               # отступ под TLS-индекс
    callbacks_rva = section_rva + callback_array_offset
    start_raw = section_rva + 0x100

    blob = bytearray()
    blob += struct.pack(
        ptr_fmt,
        start_raw,                                         # StartAddressOfRawData
        start_raw + 16,                                    # EndAddressOfRawData
        section_rva + header_size,                         # AddressOfIndex
        callbacks_rva,                                     # AddressOfCallBacks
        0x00100000,                                        # SizeOfZeroFill | характеристики
    )
    assert len(blob) == header_size, len(blob)
    blob += struct.pack(f"<{ptr}", 0)                      # TLS-индекс
    blob += b"\x00" * (callback_array_offset - len(blob))
    blob += struct.pack(f"<{ptr}{ptr}", text_rva + 0x10, text_rva + 0x20)
    blob += struct.pack(f"<{ptr}", 0)                      # терминатор массива
    return bytes(blob)


def build_import_table(
    imports_map: dict[str, list[str]], section_rva: int, *, pe32_plus: bool = False
) -> bytes:
    """
    Формирует секцию ``.rdata`` с каталогом импортов, ILT и IAT.

    Структура (все указатели — RVA):
        [IMAGE_IMPORT_DESCRIPTOR × (N+1)] [ILT×N] [IAT×N] [имена DLL] [Hint/Name]

    :param pe32_plus: в PE32+ элементы ILT/IAT занимают 8 байт.
    """
    dll_names = list(imports_map)
    num_dlls = len(dll_names)
    ptr = "Q" if pe32_plus else "I"
    ptr_size = struct.calcsize(f"<{ptr}")                  # 4 (PE32) / 8 (PE32+)

    descriptor_size = 20
    descriptors_block = (num_dlls + 1) * descriptor_size

    # Сначала считаем размеры блоков ILT/IAT, чтобы знать смещения строк.
    ilt_sizes = [(len(imports_map[name]) + 1) * ptr_size for name in dll_names]
    ilt_offsets: list[int] = []
    cursor = descriptors_block
    for size in ilt_sizes:
        ilt_offsets.append(cursor)
        cursor += size
    iat_offsets: list[int] = []
    for size in ilt_sizes:
        iat_offsets.append(cursor)
        cursor += size

    blob = bytearray(b"\x00" * cursor)

    # Имена DLL
    name_cursor = cursor
    dll_name_rvas: list[int] = []
    for name in dll_names:
        dll_name_rvas.append(section_rva + name_cursor)
        encoded = name.encode("ascii") + b"\x00"
        blob[name_cursor:name_cursor + len(encoded)] = encoded
        name_cursor += len(encoded)

    for dll_index, name in enumerate(dll_names):
        # Записи IMAGE_IMPORT_BY_NAME: Hint (WORD) + имя + \0, выравнивание до 2
        entry_offsets: list[int] = []
        for function in imports_map[name]:
            if name_cursor % 2:
                name_cursor += 1
            entry = struct.pack("<H", 0) + function.encode("ascii") + b"\x00"
            if len(entry) % 2:
                entry += b"\x00"
            blob[name_cursor:name_cursor + len(entry)] = entry
            entry_offsets.append(section_rva + name_cursor)
            name_cursor += len(entry)

        lookup = ilt_offsets[dll_index]
        thunk = iat_offsets[dll_index]
        for position, function_rva in enumerate(entry_offsets):
            struct.pack_into(f"<{ptr}", blob, lookup + position * ptr_size, function_rva)
            struct.pack_into(f"<{ptr}", blob, thunk + position * ptr_size, function_rva)
        # Терминаторы массивов
        struct.pack_into(f"<{ptr}", blob, lookup + len(entry_offsets) * ptr_size, 0)
        struct.pack_into(f"<{ptr}", blob, thunk + len(entry_offsets) * ptr_size, 0)

        struct.pack_into(
            "<IIIII",
            blob,
            dll_index * descriptor_size,
            section_rva + lookup,      # OriginalFirstThunk (ILT)
            0,                         # TimeDateStamp
            0,                         # ForwarderChain
            dll_name_rvas[dll_index],  # Name
            section_rva + thunk,       # FirstThunk (IAT)
        )

    return bytes(blob)


def build_optional_header(
    *,
    magic: int,
    entrypoint: int,
    size_of_code: int,
    size_of_init_data: int,
    size_of_image: int,
    size_of_headers: int,
    subsystem: int,
    data_directories: Sequence[tuple[int, int]],
) -> bytes:
    """
    Собирает PE32/PE32+ optional header вместе с Data Directory.

    Заголовок описан явной таблицей «формат -> значение», а не одной длинной
    строкой struct: так видно смещение каждого поля и невозможно сбиться в
    количестве аргументов. Критические смещения (SizeOfImage, CheckSum,
    Subsystem, NumberOfRvaAndSizes) и итоговый размер проверяются ассертами —
    именно так при разработке были пойманы ошибки разметки.

    Размер фиксированной части: 96 байт (PE32) / 112 байт (PE32+).
    """
    is_pe32_plus = magic == 0x20B
    ptr = "Q" if is_pe32_plus else "I"
    num_dirs = len(data_directories)

    # DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    dll_characteristics = 0x0160

    fields: list[tuple[str, object, str]] = [
        ("H", magic, "Magic"),
        ("B", 14, "MajorLinkerVersion"),
        ("B", 0, "MinorLinkerVersion"),
        ("I", size_of_code, "SizeOfCode"),
        ("I", size_of_init_data, "SizeOfInitializedData"),
        ("I", 0, "SizeOfUninitializedData"),
        ("I", entrypoint, "AddressOfEntryPoint"),
        ("I", 0x1000, "BaseOfCode"),
    ]
    if not is_pe32_plus:
        fields.append(("I", 0x2000, "BaseOfData"))   # есть только в PE32

    fields += [
        (ptr, IMAGE_BASE, "ImageBase"),
        ("I", SECTION_ALIGNMENT, "SectionAlignment"),
        ("I", FILE_ALIGNMENT, "FileAlignment"),
        ("H", 6, "MajorOperatingSystemVersion"),
        ("H", 0, "MinorOperatingSystemVersion"),
        ("H", 6, "MajorImageVersion"),
        ("H", 0, "MinorImageVersion"),
        ("H", 6, "MajorSubsystemVersion"),
        ("H", 0, "MinorSubsystemVersion"),
        ("I", 0, "Win32VersionValue"),
        ("I", size_of_image, "SizeOfImage"),
        ("I", size_of_headers, "SizeOfHeaders"),
        ("I", 0, "CheckSum"),
        ("H", subsystem, "Subsystem"),
        ("H", dll_characteristics, "DllCharacteristics"),
        (ptr, 0x100000, "SizeOfStackReserve"),
        (ptr, 0x1000, "SizeOfStackCommit"),
        (ptr, 0x100000, "SizeOfHeapReserve"),
        (ptr, 0x1000, "SizeOfHeapCommit"),
        ("I", 0, "LoaderFlags"),
        ("I", num_dirs, "NumberOfRvaAndSizes"),
    ]

    expected_offsets = {
        "SizeOfImage": 56,
        "CheckSum": 64,
        "Subsystem": 68,
        "NumberOfRvaAndSizes": 108 if is_pe32_plus else 92,
    }

    header = bytearray()
    for fmt, value, name in fields:
        offset = len(header)
        expected = expected_offsets.get(name)
        assert expected is None or offset == expected, (
            f"Смещение поля {name}: {offset} != {expected} (спецификация PE)"
        )
        header += struct.pack(f"<{fmt}", value)

    fixed_size = len(header)
    expected_fixed = 112 if is_pe32_plus else 96
    assert fixed_size == expected_fixed, (
        f"Размер фиксированной части: {fixed_size} != {expected_fixed}"
    )

    for rva, size in data_directories:
        header += struct.pack("<II", rva, size)

    assert len(header) == fixed_size + 8 * num_dirs
    return bytes(header)


# --------------------------------------------------------------------------- #
# Сборка образа
# --------------------------------------------------------------------------- #


def build_pe(
    *,
    profile: str,
    seed: int,
    machine: int = MACHINE_I386,
    extra_sections: int = 0,
) -> bytes:
    """
    Собирает валидный PE-образец.

    :param profile: ``"benign"`` или ``"malicious"`` — определяет энтропию,
        импорты, наличие упакованной секции, TLS и оверлея.
    :param seed: зерно ГСЧ — одинаковый seed даёт идентичный файл.
    :param machine: ``MACHINE_I386`` (PE32) или ``MACHINE_AMD64`` (PE32+).
    :param extra_sections: сколько дополнительных секций добавить.
    """
    rng = random.Random(seed)
    is_malicious = profile == "malicious"
    imports_map = MALICIOUS_IMPORTS if is_malicious else BENIGN_IMPORTS
    is_pe32_plus = machine == MACHINE_AMD64

    import_section_rva = 0x2000
    rdata = build_import_table(imports_map, import_section_rva, pe32_plus=is_pe32_plus)

    # --- Содержимое секций: «безопасное» — однородное, «вредоносное» — шумовое ---
    if is_malicious:
        text_data = bytes(rng.getrandbits(8) for _ in range(0x1000))
        data_data = bytes(rng.getrandbits(8) for _ in range(0x400))
        packed_data = zlib.compress(bytes(rng.getrandbits(8) for _ in range(0x2000)))[:0x200]
    else:
        text_data = b"\x90" * 0x800 + b"\xC3" + b"\xCC" * 0x7FF
        data_data = b"\x00" * 0x400
        packed_data = b""

    sections_spec: list[dict[str, object]] = [
        {"name": ".text", "rva": 0x1000, "data": text_data, "chars": 0x60000020},
        {"name": ".rdata", "rva": import_section_rva, "data": rdata, "chars": 0x40000040},
        {"name": ".data", "rva": 0x3000, "data": data_data, "chars": 0xC0000040},
    ]

    resource_blob = b""
    if not is_malicious or seed % 2 == 0:
        resource_blob = build_resource_directory(0x4000)
        sections_spec.append(
            {"name": ".rsrc", "rva": 0x4000, "data": resource_blob, "chars": 0x40000040}
        )

    tls_blob = b""
    if is_malicious:
        if packed_data:
            # Секция-«упаковщик»: огромный VirtualSize при крошечном raw-размере.
            sections_spec.append(
                {"name": "UPX1", "rva": 0x5000, "data": packed_data, "chars": 0xE0000020}
            )
        tls_blob = build_tls_directory(0x6000, 0x1000, pe32_plus=is_pe32_plus)
        sections_spec.append(
            {"name": ".tls", "rva": 0x6000, "data": tls_blob, "chars": 0xC0000040}
        )

    for index in range(extra_sections):
        sections_spec.append(
            {
                "name": f".x{index}",
                "rva": 0x8000 + index * 0x1000,
                "data": bytes(rng.getrandbits(8) for _ in range(0x200)),
                "chars": 0xC0000040,
            }
        )

    # --- Файловые смещения и выравнивание ---
    headers_size = 0x400
    file_offset = headers_size
    for spec in sections_spec:
        spec["raw_size"] = align_up(len(spec["data"]), FILE_ALIGNMENT)
        spec["virtual_size"] = (
            0x20000 if (is_malicious and spec["name"] == "UPX1") else len(spec["data"])
        )
        spec["file_offset"] = file_offset
        file_offset += int(spec["raw_size"])

    last = sections_spec[-1]
    size_of_image = align_up(int(last["rva"]) + int(last["virtual_size"]), SECTION_ALIGNMENT)

    # --- Data Directory ---
    num_dirs = 16
    data_directories = [(0, 0)] * num_dirs
    data_directories[1] = (import_section_rva, len(rdata))       # IMPORT
    if resource_blob:
        data_directories[2] = (0x4000, len(resource_blob))       # RESOURCE
    if tls_blob:
        data_directories[9] = (0x6000, len(tls_blob))            # TLS

    optional = build_optional_header(
        magic=0x20B if is_pe32_plus else 0x10B,
        entrypoint=0x1000,
        size_of_code=sum(int(s["raw_size"]) for s in sections_spec if s["name"] == ".text"),
        size_of_init_data=sum(int(s["raw_size"]) for s in sections_spec if s["name"] != ".text"),
        size_of_image=size_of_image,
        size_of_headers=headers_size,
        subsystem=SUBSYSTEM_WINDOWS_GUI,
        data_directories=data_directories,
    )

    # --- DOS + NT заголовки ---
    image = bytearray(b"\x00" * headers_size)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)                    # e_lfanew
    image[0x80:0x84] = b"PE\x00\x00"

    characteristics = 0x0022 if is_pe32_plus else 0x0102
    struct.pack_into(
        "<HHIIIHH",
        image,
        0x84,
        machine,
        len(sections_spec),
        0x65A1B2C3,                                              # TimeDateStamp
        0,                                                       # PointerToSymbolTable
        0,                                                       # NumberOfSymbols
        len(optional),                                           # SizeOfOptionalHeader
        characteristics,
    )
    image[0x98:0x98 + len(optional)] = optional

    # Таблица секций (по 40 байт на запись)
    offset = 0x98 + len(optional)
    for spec in sections_spec:
        name = str(spec["name"]).encode("ascii")[:8].ljust(8, b"\x00")
        image[offset:offset + 8] = name
        struct.pack_into(
            "<IIIIIIHHI",
            image,
            offset + 8,
            int(spec["virtual_size"]),
            int(spec["rva"]),
            int(spec["raw_size"]),
            int(spec["file_offset"]),
            0, 0, 0, 0,
            int(spec["chars"]),
        )
        offset += 40

    # --- Тело файла ---
    _pad_to(image, headers_size)
    for spec in sections_spec:
        _pad_to(image, int(spec["file_offset"]))
        image += spec["data"]
        _pad_to(image, int(spec["file_offset"]) + int(spec["raw_size"]))

    # --- Оверлей: данные после последней секции ---
    if is_malicious:
        image += bytes(rng.getrandbits(8) for _ in range(512))

    return bytes(image)


# --------------------------------------------------------------------------- #
# Массовая генерация датасета
# --------------------------------------------------------------------------- #


def write_samples(
    out_dir: Path, per_class: int = 50, *, seed_base: int = 1000, quiet: bool = False
) -> dict[str, int]:
    """
    Создаёт датасет ``out_dir/malware/*.exe`` и ``out_dir/benign/*.exe``.

    Разнообразие достигается за счёт вариации seed'а, числа секций и разрядности.
    """
    counts = {"malware": 0, "benign": 0}
    for label, profile in (("malware", "malicious"), ("benign", "benign")):
        folder = out_dir / label
        folder.mkdir(parents=True, exist_ok=True)
        for index in range(per_class):
            machine = MACHINE_AMD64 if index % 3 == 0 else MACHINE_I386
            blob = build_pe(
                profile=profile,
                seed=seed_base + index * 7 + (11 if profile == "malicious" else 0),
                machine=machine,
                extra_sections=index % 4,
            )
            target = folder / f"{label}_sample_{index:04d}.exe"
            target.write_bytes(blob)
            counts[label] += 1
            if not quiet and (index + 1) % 25 == 0:
                print(f"  {label}: {index + 1}/{per_class}")
    return counts


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Генератор синтетических PE-образцов (безопасные манекены для тестов)"
    )
    parser.add_argument("--out", default="data/samples", help="каталог датасета")
    parser.add_argument("--per-class", type=int, default=50, help="образцов на класс")
    parser.add_argument("--single", help="сгенерировать один файл по указанному пути")
    parser.add_argument("--profile", choices=("benign", "malicious"), default="benign")
    parser.add_argument("--machine", choices=("x86", "x64"), default="x86",
                        help="разрядность генерируемого образа")
    parser.add_argument("--seed", type=int, default=1234)
    args = parser.parse_args(argv)

    if args.single:
        path = Path(args.single).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        blob = build_pe(
            profile=args.profile,
            seed=args.seed,
            machine=MACHINE_AMD64 if args.machine == "x64" else MACHINE_I386,
        )
        path.write_bytes(blob)
        print(f"Создан {path} ({len(blob):,} байт, профиль={args.profile})")
        return 0

    out_dir = Path(args.out).expanduser().resolve()
    print(f"Генерация датасета в {out_dir} (по {args.per_class} на класс)…")
    counts = write_samples(out_dir, per_class=args.per_class)
    print(f"Готово: malware={counts['malware']}, benign={counts['benign']}")
    print(f"\nДальше: python main.py train --dataset {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
