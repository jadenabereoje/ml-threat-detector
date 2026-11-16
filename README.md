# ML-Powered Network Threat Detector

A network intrusion detection system that scores traffic flows as benign or malicious, flags unseen attacks with an anomaly model, and explains every alert.

> **Status:** Phase 1 — data and lab setup. See the [roadmap](#roadmap).

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
make setup
bash scripts/download_data.sh      # follow its instructions for each dataset
make data                          # clean raw CSVs -> data/interim/
make test
```

## Repository layout

```
data/            datasets and lab captures (not committed; see data/README.md)
notebooks/       EDA and experiments, numbered in order
src/detector/    package code: data loading, features, splits, models, serving
configs/         YAML configs for every pipeline step
scripts/         download, pcap conversion, replay
lab/             home-lab setup and attack log
reports/         figures, results tables, model card
tests/           unit tests (run in CI)
```

## Roadmap

| Phase | Weeks | Goal | Status |
|---|---|---|---|
| 0 | 1–2 | Foundations: networking, Zeek, ML basics | ⬜ |
| 1 | 3–4 | Data cleaning, EDA, lab captures | 🟡 in progress |
| 2 | 5–7 | Features, time-based splits, LightGBM baseline | ⬜ |
| 3 | 8–10 | Anomaly detection, cross-dataset tests | ⬜ |
| 4 | 11–13 | Real-time pipeline: Zeek → FastAPI → dashboard | ⬜ |
| 5 | 14–15 | SHAP explanations, evasion tests, model card | ⬜ |

## Results

_Filled in from `reports/results.md` as phases complete._

## Data and ethics

Public datasets are cited in [data/README.md](data/README.md). All attack traffic in `lab/` was generated on an isolated network of machines I own.

## License

MIT
