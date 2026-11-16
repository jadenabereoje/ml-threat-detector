"""Load and clean raw CIC-style flow CSVs into one interim parquet file.

Usage:
    python -m detector.data --config configs/data.yaml

What it does, in order (every step is counted in clean_report.json):
    1. Read every *.csv in raw_dir (handles the latin-1 bytes in original CIC files)
    2. Normalize column names to snake_case and de-duplicate them
    3. Drop header rows repeated inside the data
    4. Normalize label strings and apply the "Attempted" policy
    5. Coerce feature columns to numeric, replace +/-inf with NaN, drop NaN rows
    6. Count (optionally drop) exact duplicate rows
    7. Downcast floats and write parquet

Identifier columns (IPs, ports, timestamp) are kept here on purpose: they are
needed for time-based splits and lab labeling, and are removed in features.py.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

BENIGN = "BENIGN"
ATTEMPTED_SUFFIX = re.compile(r"\s*-\s*attempted$", re.IGNORECASE)


@dataclass
class DataConfig:
    raw_dir: Path
    out_dir: Path
    out_name: str = "cicids2017_clean.parquet"
    label_column: str = "label"
    attempted_policy: str = "benign"  # benign | keep | drop
    drop_nan_rows: bool = True
    drop_duplicates: bool = False
    downcast_float32: bool = True
    identifier_columns: list[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> DataConfig:
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        raw["raw_dir"] = Path(raw["raw_dir"])
        raw["out_dir"] = Path(raw["out_dir"])
        cfg = cls(**raw)
        if cfg.attempted_policy not in {"benign", "keep", "drop"}:
            raise ValueError(
                f"attempted_policy must be benign|keep|drop, got {cfg.attempted_policy!r}"
            )
        return cfg


# ---------------------------------------------------------------------------
# Column names
# ---------------------------------------------------------------------------

def to_snake(name: str) -> str:
    """'Flow Bytes/s' -> 'flow_bytes_s', ' Destination Port' -> 'destination_port'."""
    name = re.sub(r"[^0-9a-zA-Z]+", "_", str(name).strip())
    return name.strip("_").lower()


def normalize_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Snake-case column names; suffix repeats (CIC 2017 has 'Fwd Header Length' twice)."""
    seen: dict[str, int] = {}
    new_cols, renamed_dupes = [], []
    for col in df.columns:
        base = to_snake(col)
        if base in seen:
            seen[base] += 1
            new = f"{base}_{seen[base]}"
            renamed_dupes.append(new)
        else:
            seen[base] = 0
            new = base
        new_cols.append(new)
    df = df.copy()
    df.columns = new_cols
    return df, renamed_dupes


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------

def normalize_label(label: object) -> str:
    """Clean one label string.

    Original CIC files contain mojibake dashes in web-attack labels
    (e.g. 'Web Attack � Brute Force'); these become ' - '.
    """
    s = str(label).strip()
    for bad in ("�", "\x96", "–"):
        s = s.replace(bad, " - ")
    # Only spaced dashes are separators; 'SSH-Patator' stays as is
    s = re.sub(r"\s+-\s+", " - ", s)
    s = re.sub(r"\s+", " ", s).strip()
    if s.upper() == BENIGN:
        return BENIGN
    return s


def apply_attempted_policy(labels: pd.Series, policy: str) -> tuple[pd.Series, pd.Series]:
    """Return (new_labels, keep_mask) for '<attack> - Attempted' rows."""
    is_attempted = labels.str.contains(ATTEMPTED_SUFFIX, na=False)
    keep = pd.Series(True, index=labels.index)
    if policy == "benign":
        labels = labels.where(~is_attempted, BENIGN)
    elif policy == "drop":
        keep = ~is_attempted
    return labels, keep


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def read_csv_robust(path: Path) -> pd.DataFrame:
    try:
        return pd.read_csv(path, low_memory=False, encoding="utf-8")
    except UnicodeDecodeError:
        return pd.read_csv(path, low_memory=False, encoding="latin-1")


def read_raw_csvs(raw_dir: Path) -> pd.DataFrame:
    files = sorted(Path(raw_dir).glob("*.csv"))
    if not files:
        raise FileNotFoundError(
            f"No CSV files in {raw_dir}. Download the dataset first "
            "(see data/README.md and scripts/download_data.sh)."
        )
    frames = []
    for f in files:
        df = read_csv_robust(f)
        # Normalize per file so columns line up even if files differ in spacing
        df, _ = normalize_columns(df)
        df["source_file"] = f.name
        frames.append(df)
        print(f"  read {f.name}: {len(df):,} rows", file=sys.stderr)
    return pd.concat(frames, ignore_index=True, sort=False)


# ---------------------------------------------------------------------------
# Cleaning
# ---------------------------------------------------------------------------

def clean(df: pd.DataFrame, cfg: DataConfig) -> tuple[pd.DataFrame, dict]:
    report: dict = {"rows_in": len(df)}

    df, dupes = normalize_columns(df)
    report["duplicate_column_names_renamed"] = dupes

    label = to_snake(cfg.label_column)
    if label not in df.columns:
        raise KeyError(f"Label column {label!r} not found. Columns: {list(df.columns)[:10]}...")

    # 1. Repeated header rows (the label cell literally says "Label")
    header_rows = df[label].astype(str).str.strip().str.lower() == label
    report["repeated_header_rows_dropped"] = int(header_rows.sum())
    df = df.loc[~header_rows]

    # 2. Labels
    df[label] = df[label].map(normalize_label)
    labels, keep = apply_attempted_policy(df[label], cfg.attempted_policy)
    report["attempted_rows"] = int(df[label].str.contains(ATTEMPTED_SUFFIX, na=False).sum())
    report["attempted_policy"] = cfg.attempted_policy
    df[label] = labels
    df = df.loc[keep]

    # 3. Numeric coercion for feature columns
    ids = [to_snake(c) for c in cfg.identifier_columns]
    non_features = set(ids) | {label, "source_file"}
    feature_cols = [c for c in df.columns if c not in non_features]
    report["identifier_columns_missing"] = [c for c in ids if c not in df.columns]

    coerced_nan_before = int(df[feature_cols].isna().sum().sum())
    df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    coerced_nan_after = int(df[feature_cols].isna().sum().sum())
    report["non_numeric_values_coerced"] = coerced_nan_after - coerced_nan_before

    # 4. Infinities -> NaN, then drop NaN rows
    arr = df[feature_cols].to_numpy(dtype="float64", na_value=np.nan)
    inf_mask = np.isinf(arr)
    report["inf_values_replaced"] = int(inf_mask.sum())
    report["inf_values_by_column"] = {
        c: int(n) for c, n in zip(feature_cols, inf_mask.sum(axis=0), strict=True) if n > 0
    }
    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)

    nan_rows = df[feature_cols].isna().any(axis=1)
    report["rows_with_nan"] = int(nan_rows.sum())
    if cfg.drop_nan_rows:
        df = df.loc[~nan_rows]

    # 5. Duplicates (ignore source_file so cross-file copies count too)
    dup = df.drop(columns=["source_file"]).duplicated()
    report["duplicate_rows"] = int(dup.sum())
    if cfg.drop_duplicates:
        df = df.loc[~dup]

    # 6. Timestamp parsing (kept, not dropped; failures only counted)
    if "timestamp" in df.columns:
        parsed = pd.to_datetime(df["timestamp"], errors="coerce", format="mixed")
        report["timestamp_parse_failures"] = int(parsed.isna().sum())
        df["timestamp"] = parsed

    # 7. Constant columns: reported, not dropped (that is a modeling decision)
    nunique = df[feature_cols].nunique(dropna=False)
    report["constant_columns"] = sorted(nunique[nunique <= 1].index.tolist())

    if cfg.downcast_float32:
        float_cols = df[feature_cols].select_dtypes("float64").columns
        df[float_cols] = df[float_cols].astype("float32")

    df = df.reset_index(drop=True)
    report["rows_out"] = len(df)
    report["n_feature_columns"] = len(feature_cols)
    report["label_counts"] = {k: int(v) for k, v in df[label].value_counts().items()}
    return df, report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run(cfg: DataConfig) -> dict:
    print(f"Reading CSVs from {cfg.raw_dir} ...", file=sys.stderr)
    raw = read_raw_csvs(cfg.raw_dir)
    df, report = clean(raw, cfg)

    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    out_path = cfg.out_dir / cfg.out_name
    df.to_parquet(out_path, index=False)
    report["output"] = str(out_path)

    report_path = cfg.out_dir / "clean_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    return report


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Clean raw flow CSVs into parquet.")
    parser.add_argument("--config", default="configs/data.yaml")
    args = parser.parse_args(argv)

    report = run(DataConfig.from_yaml(args.config))
    print(f"\nRows: {report['rows_in']:,} in -> {report['rows_out']:,} out")
    print(f"Inf values replaced: {report['inf_values_replaced']:,}  "
          f"NaN rows: {report['rows_with_nan']:,}  duplicates: {report['duplicate_rows']:,}")
    print("Label counts:")
    for name, n in report["label_counts"].items():
        print(f"  {name:<40} {n:>10,}")
    print(f"\nWrote {report['output']} and clean_report.json")


if __name__ == "__main__":
    main()
