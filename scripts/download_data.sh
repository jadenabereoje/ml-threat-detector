#!/usr/bin/env bash
# Fetch or check the datasets used in this project.
#
#   bash scripts/download_data.sh            # check what is present, print instructions
#   bash scripts/download_data.sh 2018       # download selected CSE-CIC-IDS2018 days (needs AWS CLI)
#
# Record the download date and size of each dataset in data/README.md.

set -euo pipefail
cd "$(dirname "$0")/.."

RAW=data/raw
mkdir -p "$RAW/cicids2017" "$RAW/cicids2018" "$RAW/unsw-nb15"

count_csv() { find "$1" -maxdepth 1 -name '*.csv' | wc -l | tr -d ' '; }

echo "== CIC-IDS2017 (corrected, WTMC 2021) =="
n=$(count_csv "$RAW/cicids2017")
if [ "$n" -gt 0 ]; then
  echo "  found $n CSV file(s) in $RAW/cicids2017"
else
  cat <<EOF
  Not downloaded yet. Manual step:
    1. Open https://downloads.distrinet-research.be/WTMC2021 in a browser
    2. Download the regenerated CIC-IDS2017 CSV files (one per capture day)
    3. Unzip them into $RAW/cicids2017/
  Then run: make data
EOF
fi

echo
echo "== CSE-CIC-IDS2018 (cross-dataset test) =="
if [ "${1:-}" = "2018" ]; then
  if ! command -v aws >/dev/null 2>&1; then
    echo "  AWS CLI not found. Install it: https://aws.amazon.com/cli/" >&2
    exit 1
  fi
  # Public bucket; no AWS account needed. List first so you can pick days:
  #   aws s3 ls --no-sign-request "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/"
  # Days with brute force and DoS attacks that also appear in CIC-IDS2017:
  DAYS=(
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
    "Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv"
  )
  for f in "${DAYS[@]}"; do
    if [ -f "$RAW/cicids2018/$f" ]; then
      echo "  already have $f"
    else
      echo "  downloading $f ..."
      aws s3 cp --no-sign-request \
        "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/$f" \
        "$RAW/cicids2018/$f"
    fi
  done
else
  n=$(count_csv "$RAW/cicids2018")
  echo "  found $n CSV file(s). To download selected days: bash scripts/download_data.sh 2018"
  echo "  Not needed until Phase 3; it is large, so wait if disk space is tight."
fi

echo
echo "== UNSW-NB15 (optional) =="
n=$(count_csv "$RAW/unsw-nb15")
echo "  found $n CSV file(s). Optional; download from UNSW Canberra's research site after Phase 2."

echo
echo "Disk usage:"
du -sh "$RAW"/* 2>/dev/null || true
