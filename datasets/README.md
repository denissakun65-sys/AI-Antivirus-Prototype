# datasets/

## ember_2018_sample.csv.gz

Готовая обучающая выборка из датасета **EMBER 2018** (Elastic Malware
Benchmark for Empowering Researchers), сконвертированная в формат
этого проекта (46 признаков + метка).

| Параметр | Значение |
|---|---|
| Строк | 200 000 (100 000 malicious / 100 000 benign) |
| Источник | `ember_dataset_2018_2.tar.bz2`, sha256 `b6052eb8…97812` (официальный) |
| Метки | консенсус движков VirusTotal (из исходного датасета EMBER) |
| Формат | CSV gzip: `path,sha256,size,<46 признаков>,label` |
| Контрольные метрики | LightGBM: F1 ≈ 0.921, ROC-AUC ≈ 0.978 |

### Зачем он здесь

CDN `ember.elastic.co` блокирует скачивание полного архива из части
регионов (HTTP 403). Выборка в репозитории позволяет `autolearn`
обучаться на реальных данных **без обращения в интернет** — файл
приезжает вместе с `git pull`.

### Как используется

`python main.py autolearn` вливает выборку автоматически (один раз,
прогресс фиксируется в `data/nightly/state.json`). Ручное обучение:

```powershell
python main.py train --csv datasets\ember_2018_sample.csv.gz --backend lightgbm
```

### Происхождение и лицензия

- H. Anderson, P. Roth, «EMBER: An Open Dataset for Training Static PE
  Malware Machine Learning Models», arXiv:1804.04637 (2018).
- Датасет опубликован Elastic для исследовательских целей; зеркало —
  Academic Torrents (`34854ec5114020b33224cedc97fe78731d057df4`).
- Самих malware-файлов выборка **не содержит** — только извлечённые
  признаки (статистика заголовков, секций, импортов).
- Часть признаков, отсутствующих в EMBER (entry point, оверлей, чексумма,
  объём ресурсов), заполнена консервативными значениями — это осознанный
  компромисс дистилляции, см. `src/aiav/overnight.py`.
