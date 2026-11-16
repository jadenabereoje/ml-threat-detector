"""Tests for detector.data using a tiny synthetic CIC-style CSV."""

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from detector.data import (
    BENIGN,
    DataConfig,
    clean,
    normalize_columns,
    normalize_label,
    read_raw_csvs,
    run,
    to_snake,
)

RAW_CSV = """Flow ID, Source IP, Source Port, Destination IP, Destination Port, Timestamp, Flow Duration, Flow Bytes/s, Fwd Header Length, Fwd Header Length, Label
a,10.0.0.1,5000,10.0.0.2,80,2017-07-03 09:00:00,100,50.0,20,20,BENIGN
b,10.0.0.3,5001,10.0.0.2,22,2017-07-04 09:00:00,200,Infinity,20,20,SSH-Patator
c,10.0.0.3,5002,10.0.0.2,22,2017-07-04 09:01:00,300,10.0,20,20,SSH-Patator - Attempted
Flow ID, Source IP, Source Port, Destination IP, Destination Port, Timestamp, Flow Duration, Flow Bytes/s, Fwd Header Length, Fwd Header Length, Label
d,10.0.0.4,5003,10.0.0.2,80,2017-07-06 10:00:00,400,NaN,20,20,Web Attack � Brute Force
e,10.0.0.5,5004,10.0.0.2,80,2017-07-06 10:01:00,500,5.0,20,20,benign
e,10.0.0.5,5004,10.0.0.2,80,2017-07-06 10:01:00,500,5.0,20,20,benign
"""


@pytest.fixture
def raw_dir(tmp_path: Path) -> Path:
    d = tmp_path / "raw"
    d.mkdir()
    (d / "day1.csv").write_text(RAW_CSV, encoding="utf-8")
    return d


def make_cfg(raw_dir: Path, tmp_path: Path, **kw) -> DataConfig:
    base = {
        "raw_dir": raw_dir,
        "out_dir": tmp_path / "interim",
        "identifier_columns": ["Flow ID", "Source IP", "Source Port",
                            "Destination IP", "Destination Port", "Timestamp"],
    }
    base.update(kw)
    return DataConfig(**base)


def test_to_snake():
    assert to_snake(" Flow Bytes/s") == "flow_bytes_s"
    assert to_snake("Destination Port ") == "destination_port"


def test_duplicate_column_names_are_suffixed():
    df = pd.DataFrame([[1, 2]], columns=["Fwd Header Length", "Fwd Header Length"])
    out, dupes = normalize_columns(df)
    assert list(out.columns) == ["fwd_header_length", "fwd_header_length_1"]
    assert dupes == ["fwd_header_length_1"]


@pytest.mark.parametrize("raw, expected", [
    ("benign", BENIGN),
    ("  BENIGN ", BENIGN),
    ("Web Attack � Brute Force", "Web Attack - Brute Force"),
    ("Web Attack \x96 XSS", "Web Attack - XSS"),
    ("SSH-Patator", "SSH-Patator"),  # hyphen inside a name is untouched
])
def test_normalize_label(raw, expected):
    assert normalize_label(raw) == expected


def test_clean_end_to_end(raw_dir, tmp_path):
    df, report = clean(read_raw_csvs(raw_dir), make_cfg(raw_dir, tmp_path))

    assert report["repeated_header_rows_dropped"] == 1
    assert report["attempted_rows"] == 1
    assert report["inf_values_replaced"] == 1
    assert report["rows_with_nan"] == 2          # the inf row and the NaN row
    assert report["duplicate_rows"] == 1         # rows e and f
    assert report["identifier_columns_missing"] == []

    # Attempted row relabeled benign; inf and NaN rows dropped
    assert set(df["label"]) == {BENIGN}
    assert len(df) == 4                          # a, c, e, f
    assert not np.isinf(df.select_dtypes("number").to_numpy()).any()
    assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])
    assert df["flow_bytes_s"].dtype == np.float32


def test_attempted_policy_drop(raw_dir, tmp_path):
    df, _ = clean(read_raw_csvs(raw_dir), make_cfg(raw_dir, tmp_path, attempted_policy="drop"))
    assert len(df) == 3                          # a, e, f


def test_attempted_policy_keep(raw_dir, tmp_path):
    df, _ = clean(read_raw_csvs(raw_dir), make_cfg(raw_dir, tmp_path, attempted_policy="keep"))
    assert "SSH-Patator - Attempted" in set(df["label"])


def test_drop_duplicates(raw_dir, tmp_path):
    df, _ = clean(read_raw_csvs(raw_dir), make_cfg(raw_dir, tmp_path, drop_duplicates=True))
    assert len(df) == 3


def test_run_writes_parquet_and_report(raw_dir, tmp_path):
    pytest.importorskip("pyarrow")
    cfg = make_cfg(raw_dir, tmp_path)
    report = run(cfg)
    assert (cfg.out_dir / cfg.out_name).exists()
    assert (cfg.out_dir / "clean_report.json").exists()
    assert report["rows_out"] == 4


def test_missing_raw_dir_gives_helpful_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="Download the dataset"):
        read_raw_csvs(tmp_path / "nothing_here")


def test_latin1_file_is_readable(tmp_path):
    d = tmp_path / "raw"
    d.mkdir()
    content = "Flow Duration,Label\n1,Web Attack \x96 Sql Injection\n"
    (d / "old.csv").write_bytes(content.encode("latin-1"))
    df, _ = clean(read_raw_csvs(d), make_cfg(d, tmp_path, identifier_columns=[]))
    assert df["label"].iloc[0] == "Web Attack - Sql Injection"
