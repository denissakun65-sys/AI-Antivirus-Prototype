# 🛡️ AI-Antivirus — прототип Next-Gen AV / EDR

Учебный прототип антивируса нового поколения: **статический анализ PE-файлов**
(`pefile`) + **ML-классификация** (Random Forest / LightGBM) + **автоматический
карантин** с шифрованием и контролем целостности.

```
     _    ___   ___         _          _
    / \  |_ _| / _ \  _ __ | |_  _   _(_)__  ___
   / _ \  | | | | | || '_ \| __|| | | | | \/ / / __|
  / ___ \ | | | |_| || | | | |_ | |_| | |   <  \__ \
 /_/   \_\___| \___/ |_| \_|\__| \__,_|_|_|\_\ |___/
```

> ⚠️ **Дисклеймер.** Проект создан **исключительно в образовательных и
> исследовательских целях**. Это *не* замена промышленному антивирусу или EDR:
> здесь нет драйвера ядра, поведенческого анализа, песочницы, проверки
> цифровых подписей и телеметрии. Не используйте его как единственное средство
> защиты и не запускайте реальные вредоносные образцы вне изолированной
> лаборатории.

---

## Содержание

- [Возможности](#-возможности)
- [Структура репозитория](#-структура-репозитория)
- [Быстрый старт](#-быстрый-старт)
- [CLI-справочник](#-cli-справочник)
- [Как это работает](#-как-это-работает)
- [Извлекаемые признаки](#-извлекаемые-признаки-46-штук)
- [Карантин](#-карантин)
- [Свой датасет](#-свой-датасет)
- [Тесты](#-тесты)
- [Ограничения прототипа](#-ограничения-прототипа)
- [Roadmap](#-roadmap)
- [Лицензия](#-лицензия)

---

## ✨ Возможности

| Компонент | Что делает |
|---|---|
| **`aiav.features`** | Разбирает PE и извлекает **46 статических признаков**: геометрия, энтропия секций, таблица импортов (с разбивкой по категориям «тревожных» API), флаги заголовков, TLS-callbacks, оверлей, ресурсы, аномалии. |
| **`aiav.model`** | Класс `MalwareClassifier` — единая обёртка над RandomForest и LightGBM. Обучение, метрики (accuracy / precision / recall / F1 / ROC-AUC / CV), сохранение модели с метаданными и **проверкой схемы признаков при загрузке**. |
| **`aiav.scanner`** | Конвейер «признаки → предсказание → действие». Пакетное предсказание, режимы `quarantine` / `report`, `--dry-run`, JSON + CSV отчёты, коды возврата в стиле антивирусов. |
| **`aiav.quarantine`** | Изоляция с **AES-256-GCM**, карточки в JSON, проверка **SHA-256** при восстановлении, защита от перезаписи, `list` / `restore` / `purge`. |
| **`tools/generate_samples.py`** | Генератор **валидных синтетических PE** (benign/malicious профили) — чтобы тестировать конвейер, не храня реальный malware в репозитории. |

---

## 📁 Структура репозитория

```
ai-antivirus/
├── main.py                     # Тонкая обёртка: python main.py … (без установки пакета)
├── requirements.txt            # Обязательные и опциональные зависимости
├── requirements-dev.txt        # pytest, ruff, mypy — для разработки и CI
├── pyproject.toml              # Метаданные проекта, конфиг ruff/pytest/mypy
├── README.md
├── LICENSE                     # MIT
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml              # GitHub Actions: линт + тесты на 3.10/3.11/3.12
│
├── src/
│   └── aiav/                   # Основной пакет
│       ├── __init__.py         # Версия + ленивые импорты публичного API
│       ├── cli.py              # argparse-CLI: scan / train / features / quarantine / model-info
│       ├── config.py           # Пути, пороги, лимиты (переопределяются env-переменными)
│       ├── logging_setup.py    # Цветное логирование в консоль + ротация файла
│       ├── features.py         # ⭐ Извлечение признаков из PE (pefile)
│       ├── model.py            # ⭐ MalwareClassifier: обучение, сохранение, инференс
│       ├── scanner.py          # Логика сканирования каталога и применение вердиктов
│       └── quarantine.py       # Изоляция, шифрование, восстановление
│
├── tests/                      # pytest: 62 теста (модульные + интеграционные)
│   ├── conftest.py             # Фикстуры: синтетические PE, датасет, карантин
│   ├── test_features.py
│   ├── test_model.py
│   ├── test_quarantine.py
│   └── test_scanner.py
│
├── tools/
│   └── generate_samples.py     # Генератор тестовых PE-образцов
│
├── models/                     # Обученные модели (*.joblib) — в .gitignore, .gitkeep
├── quarantine/                 # Изолированные объекты — в .gitignore, .gitkeep
├── reports/                    # JSON/CSV отчёты сканирования — в .gitignore, .gitkeep
└── data/
    ├── samples/                # Датасет malware/ + benign/ — в .gitignore
    └── README.md               # Описание ожидаемого формата данных
```

---

## 🚀 Быстрый старт

> 📁 Папка после клонирования называется так же, как репозиторий
> (например, `AI-Antivirus-Prototype`), — заходите в неё, а не в
> `ai-antivirus` из примеров ниже.

### Windows (PowerShell)

```powershell
git clone https://github.com/<ваш-аккаунт>/AI-Antivirus-Prototype.git
cd AI-Antivirus-Prototype

python -m venv .venv
.\.venv\Scripts\Activate.ps1        # в начале строки появится (.venv)
# Если PowerShell запрещает выполнение скриптов — один раз разрешите:
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

pip install -r requirements.txt

python tools\generate_samples.py --out data\samples --per-class 60
python main.py train --dataset data\samples
python main.py scan $env:USERPROFILE\Downloads --dry-run
```

> 💡 Не получается активировать venv? Работайте без активации, полными путями:
> `.\.venv\Scripts\python.exe main.py train --dataset data\samples`

### Linux / macOS (bash/zsh)

```bash
git clone https://github.com/<ваш-аккаунт>/AI-Antivirus-Prototype.git
cd AI-Antivirus-Prototype

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

python tools/generate_samples.py --out data/samples --per-class 60
python main.py train --dataset data/samples --backend random_forest
python main.py scan ~/Downloads --dry-run
```

Боевой режим — вредоносные файлы уходят в карантин:

```
python main.py scan <каталог> --action quarantine
```

> **Проверено:** Python 3.13.14, scikit-learn 1.6.1, pefile 2024.8.26,
> lightgbm 4.7.0, cryptography 50.0.1 — 59/59 тестов проходят.

---

## 🖥️ CLI-справочник

### `scan` — проверка файлов и каталогов

```bash
python main.py scan <путь> [<путь> ...] [опции]
```

| Опция | Описание |
|---|---|
| `--action {quarantine,report}` | Действие при обнаружении угрозы (по умолчанию `quarantine`) |
| `--dry-run` | Ничего не перемещать — только отчёт. **Рекомендуется для первого запуска** |
| `--model PATH` | Путь к модели (по умолчанию `models/malware_classifier.joblib`) |
| `--quarantine-dir PATH` | Каталог карантина (по умолчанию `quarantine/`) |
| `--malicious-threshold F` | Порог карантина (по умолчанию `0.80`) |
| `--suspicious-threshold F` | Порог «подозрительно» (по умолчанию `0.50`) |
| `--no-encrypt` | Хранить объекты карантина без шифрования |
| `--full-report` | Включить в JSON-отчёт весь вектор признаков |
| `--no-report` | Не сохранять отчёты |
| `-v / -q` | Подробный вывод / только предупреждения |

**Коды возврата:** `0` — угроз нет, `1` — найдены угрозы, `2` — ошибка
(нет модели, нет прав и т.п.), `130` — прервано пользователем.

### `train` — обучение модели

```bash
python main.py train --dataset data/samples --backend random_forest
python main.py train --csv my_dataset.csv --backend lightgbm --threshold 0.85
```

| Опция | Описание |
|---|---|
| `--dataset DIR` | Каталог с подкаталогами `malware/` и `benign/` |
| `--csv FILE` | Готовый CSV-датасет (EMBER/Kaggle) с колонкой `label` |
| `--backend {random_forest,lightgbm}` | Алгоритм классификации |
| `--output PATH` | Куда сохранить модель |
| `--threshold F` | Порог вердикта MALICIOUS |
| `--test-size F` | Доля отложенной выборки (по умолчанию `0.25`) |
| `--limit N` | Максимум образцов на класс (для быстрых прогонов) |

### `features` — дамп признаков одного файла

```bash
python main.py features suspicious.exe
```

### `quarantine` — управление изолированными объектами

```bash
python main.py quarantine list                     # список объектов
python main.py quarantine restore <ID>             # восстановить по исходному пути
python main.py quarantine restore <ID> --target ./analysis.exe
python main.py quarantine purge <ID>               # удалить безвозвратно
python main.py quarantine purge --all
```

### `model-info` — сведения о модели

```bash
python main.py model-info
```

---

## ⚙️ Как это работает

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌────────────┐
│  Каталог     │ --> │  Отбор PE-      │ --> │  Извлечение      │ --> │  ML-модель │
│  (рекурсивно)│     │  кандидатов     │     │  46 признаков    │     │  (RF/LGBM) │
└──────────────┘     │  MZ + расширение│     │  (pefile)        │     └─────┬──────┘
                     └─────────────────┘     └──────────────────┘           │
                                                                            v
                     ┌───────────────────────────────────────────────────────────┐
                     │  P(malware) >= 0.80  ->  MALICIOUS   ->  КАРАНТИН (AES)   │
                     │  P(malware) >= 0.50  ->  SUSPICIOUS  ->  только отчёт     │
                     │  иначе               ->  CLEAN                            │
                     └───────────────────────────────────────────────────────────┘
                                                        │
                                                        v
                                        reports/scan-<timestamp>.{json,csv}
```

**Ключевые инженерные решения**

- **Пакетное предсказание.** Признаки извлекаются пофайлово (это IO-bound),
  а модель вызывается **один раз** для всего набора — скан каталога ускоряется
  в разы.
- **Один битый файл ≠ упавший скан.** Любая ошибка разбора превращается в
  `PEFeatureError` и фиксируется в отчёте со статусом `ERROR`; обход продолжается.
- **Схема признаков — контракт.** Модель хранит `FEATURE_NAMES` в метаданных и
  сверяет его при загрузке. Изменили набор признаков — получите явную ошибку
  «переобучите модель», а не молча деградировавшее качество.
- **Кандидаты отбираются и по сигнатуре, и по расширению.** `payload.bin` с
  заголовком `MZ` попадёт в разбор, а `broken.exe` без PE-заголовка — тоже,
  но уже как ошибка, а не молчаливый пропуск.

---

## 🔍 Извлекаемые признаки (46 штук)

<details>
<summary><b>Геометрия и размеры (15)</b></summary>

`virtual_size`, `raw_size`, `header_size`, `num_sections`, `num_imports_dll`,
`num_imports_funcs`, `num_resources`, `num_data_directories`, `num_symbols`,
`size_of_optional_header`, `size_of_code`, `size_of_initialized_data`,
`size_of_uninitialized_data`, `entrypoint_offset`, `overlay_size`
</details>

<details>
<summary><b>Энтропия и признаки упаковщика (7)</b></summary>

`entropy_overall`, `entropy_min_section`, `entropy_max_section`,
`entropy_mean_section`, `entropy_std_section`, `ratio_raw_to_virtual`,
`max_section_virtual_raw_gap`

> Энтропия > 7.2 бит/байт и огромный `VirtualSize` при крошечном `SizeOfRawData`
> — классические маркеры упаковки (UPX, ASPack, VMProtect) и шифрования
> полезной нагрузки.
</details>

<details>
<summary><b>Флаги и аномалии заголовков (14)</b></summary>

`is_dll`, `is_driver`, `is_64bit`, `has_debug_directory`, `has_tls_callbacks`,
`num_tls_callbacks`, `has_relocations`, `has_signature`, `has_resources`,
`has_imports`, `has_exceptions`, `is_upx_packed`, `is_header_anomalous`,
`checksum_mismatch`

> TLS-callback выполняется **до** точки входа — популярный приём антианализа.
> Отсутствие Authenticode-подписи у «делового» ПО — отдельный сигнал риска.
</details>

<details>
<summary><b>«Тревожные» API по категориям (9)</b></summary>

| Признак | Примеры API |
|---|---|
| `imports_process_injection` | `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`, `SetThreadContext`, `VirtualAllocEx` |
| `imports_memory_ops` | `VirtualAlloc`, `VirtualProtect`, `LoadLibraryA/W`, `GetProcAddress`, `LdrLoadDll` |
| `imports_registry_ops` | `RegSetValueExW`, `RegCreateKeyExW`, `RegDeleteValueW` (персистентность) |
| `imports_process_execution` | `CreateProcessW`, `ShellExecuteW`, `WinExec`, `TerminateProcess` |
| `imports_network_ops` | `InternetOpenUrlW`, `URLDownloadToFileW`, `WSAStartup`, `connect`, `gethostbyname` |
| `imports_crypto_ops` | `CryptEncrypt`, `CryptGenKey`, `BCryptEncrypt` (шифровальщики) |
| `imports_file_ops` | `CreateFileW`, `DeleteFileW`, `MoveFileExW`, `FindFirstFileW` |
| `imports_service_ops` | `CreateServiceW`, `StartServiceW`, `IsDebuggerPresent`, `SetWindowsHookExW`, `AdjustTokenPrivileges` |
| `imports_suspicious_count` | Суммарный счётчик по всем категориям |
</details>

<details>
<summary><b>Ресурсы (1)</b></summary>

`resources_total_bytes` — суммарный объём ресурсов: в них часто «зашивают»
вторую ступень полезной нагрузки.
</details>

Полный список — константа `FEATURE_NAMES` в
[`src/aiav/features.py`](src/aiav/features.py).

---

## 🔐 Карантин

1. **Файл не исполняется.** Объект переименовывается в `<id>.quarantined`
   (Windows не запустит такой файл как PE) и лишается прав на запись.
2. **Шифрование.** По умолчанию **AES-256-GCM** (`cryptography`). Ключ создаётся
   один раз в `quarantine/.quarantine.key` с правами `0600`. Без
   `cryptography` включается XOR-обфускация — с явным предупреждением в лог,
   что это **не** криптостойкая защита.
3. **Карточка объекта** `<id>.json`: исходный путь, SHA-256, размер, вердикт,
   вероятность, модель, причина, время.
4. **Контроль целостности.** При восстановлении SHA-256 сверяется: подменили
   объект в карантине — восстановление прерывается.
5. **Никакой молчаливой перезаписи.** `restore` откажется затирать существующий
   файл без `--force`.
6. **Права каталога** — `0700` (только владелец). На Windows дополнительно
   рекомендуется ограничить ACL:
   ```powershell
   icacls "quarantine" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"
   ```

---

## 📊 Свой датасет

### Вариант A — каталог с образцами

```
data/samples/
├── malware/    # label = 1
│   ├── malware_sample_0000.exe
│   └── ...
└── benign/     # label = 0
    ├── benign_sample_0000.exe
    └── ...
```

```bash
python main.py train --dataset data/samples
```

### Вариант B — CSV (EMBER, Kaggle)

Нужны колонка `label` (0/1) и колонки-признаки с именами из `FEATURE_NAMES`.
Отсутствующие признаки заполнятся нулями (с предупреждением в лог).

```bash
python main.py train --csv ember_features.csv
```

### Где взять данные

| Источник | Что это |
|---|---|
| [EMBER 2018](https://github.com/elastic/ember) | 1.1M образцов, готовые признаковые векторы (Endgame) |
| [MalwareBazaar](https://bazaar.abuse.ch/) | Реальные malware-образцы (только для изолированной лаборатории) |
| [VirusTotal](https://www.virustotal.com/) | Вердикты и метаинформация по хешу |

> 🔒 **Правило безопасности:** работайте с реальным malware только в
> изолированной ВМ без сети. В репозиторий такие файлы **не коммитятся** —
> именно для этого в `.gitignore` закрыты `data/`, `quarantine/` и `models/`,
> а в `tools/` лежит генератор синтетических манекенов.

---

## 🧪 Тесты

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -v                 # 59 тестов
ruff check src tests      # линт
```

Тесты покрывают:

- извлечение признаков (валидные/битые/пустые файлы, маскировка расширения, симлинки);
- математику энтропии (однородные данные → 0, 256 значений → 8 бит);
- обучение, метрики, сохранение/загрузку модели, отклонение неверной схемы признаков;
- карантин: изоляция, AES-обратимость, **обнаружение подмены**, отказ перезаписи, purge;
- сквозной конвейер: скан каталога, `--dry-run`, режим `report`, отчёты JSON/CSV.

---

## 🚧 Ограничения прототипа

Честный список того, чего здесь **нет** — и что делает промышленный NGAV/EDR:

- **Только статика.** Нет поведенческого анализа, эмуляции, песочницы.
- **Нет проверки подписей.** Authenticode фиксируется как признак, но не валидируется.
- **Нет реалтайм-защиты.** Нет файлового фильтра/драйвера, перехвата создания процессов.
- **Нет обхода упаковки.** Упакованный образец анализируется «как есть».
- **Синтетическая обучающая выборка.** Метрики на `tools/generate_samples.py`
  близки к 1.0 **по построению** — это смоук-тест конвейера, а не оценка качества
  детекта. Для реальных цифр нужен EMBER или собственный размеченный корпус.
- **Нет защиты от adversary ML.** Признаки легко «зашумить», если злоумышленник
  знает набор (`FEATURE_NAMES` открыт в репозитории).
- **Карантин — пользовательского уровня.** Без ACL уровня SYSTEM объект можно
  удалить, имея права владельца.

---

## 🗺️ Roadmap

- [ ] YARA-правила как второй независимый слой детекта
- [ ] Проверка валидности Authenticode-подписи
- [ ] Интеграция с VirusTotal / MalwareBazaar по SHA-256
- [ ] Разпаковка UPX перед анализом
- [ ] Графовые признаки (CFG, граф вызовов API)
- [ ] Веб-интерфейс и REST API
- [ ] Пакетная обработка и инкрементальный скан (кэш по SHA-256)
- [ ] Экспорт IOC в SIEM (STIX/CSV)

---

## 📄 Лицензия

[MIT](LICENSE). Используйте ответственно: знание техник malware-анализа
применимо и для защиты, и для атаки.

---

<sub>Сделано как учебный проект по статическому анализу вредоносного ПО и
прикладному машинному обучению.</sub>
