# Data

Nothing in this folder is committed except this README, `.gitkeep` files and `lab/labels.csv`. Everything else is rebuilt from the steps below.

## Sources

| Dataset | Source | Version / date downloaded | Size | Used for |
|---|---|---|---|---|
| CIC-IDS2017 (corrected, WTMC 2021) | https://downloads.distrinet-research.be/WTMC2021 | YYYY-MM-DD | ~ GB | train / validation |
| CSE-CIC-IDS2018 | https://registry.opendata.aws/cse-cic-ids2018 | days: | ~ GB | cross-dataset test |
| UNSW-NB15 (optional) | UNSW Canberra | YYYY-MM-DD | ~ GB | second dataset |
| Lab captures | own isolated lab, see `lab/labels.csv` | ongoing | ~ MB | real-world test |

Citation for the corrected CIC-IDS2017: G. Engelen, V. Rimmer, W. Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study," IEEE SPW 2021.

## Layout

```
raw/           untouched downloads; never edit these files
  cicids2017/  corrected CSVs, one per capture day
  cicids2018/  only the days you use
  unsw-nb15/
lab/
  pcaps/       raw captures from the home lab
  flows/       pcaps converted with CICFlowMeter / Zeek
  labels.csv   attack log: when, who, what tool
interim/       cleaned data written by `make data` + clean_report.json
processed/     train / val / test parquet files (Phase 2)
```

## Rebuild

1. `bash scripts/download_data.sh`
2. `make data` (reads `configs/data.yaml`)

## Known issues and fixes

Keep this list current during EDA; it becomes the Phase 1 data-quality note.
`data/interim/clean_report.json` records the counts for each run.

- Infinite values in rate features (e.g. flow bytes/s) → replaced with NaN, rows dropped
- Header rows repeated inside CSVs → removed
- Leading/trailing spaces in column names → stripped, names converted to snake_case
- Corrected 2017 data marks some flows `... - Attempted` (attack launched but no effect) → handling set by `attempted_policy` in `configs/data.yaml`
- _add more as you find them_
