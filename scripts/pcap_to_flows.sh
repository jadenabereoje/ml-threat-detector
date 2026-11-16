#!/usr/bin/env bash
# Convert every lab pcap into flow records with Zeek (and CICFlowMeter if installed).
#
#   bash scripts/pcap_to_flows.sh
#
# Output:
#   data/lab/flows/zeek/<pcap name>/conn.log ...   Zeek logs, JSON format
#   data/lab/flows/cic/<pcap name>_Flow.csv        CICFlowMeter CSV (same columns as CIC-IDS2017)
#
# Requirements: zeek on PATH. Optional: CICFlowMeter (set CICFLOWMETER to its `cfm` launcher).

set -euo pipefail
cd "$(dirname "$0")/.."

PCAPS=data/lab/pcaps
OUT=data/lab/flows
mkdir -p "$OUT/zeek" "$OUT/cic"

shopt -s nullglob
files=("$PCAPS"/*.pcap "$PCAPS"/*.pcapng)
if [ ${#files[@]} -eq 0 ]; then
  echo "No pcaps in $PCAPS. Capture some first (see lab/README.md)."
  exit 0
fi

for pcap in "${files[@]}"; do
  name=$(basename "${pcap%.*}")
  echo "== $name"

  if command -v zeek >/dev/null 2>&1; then
    dir="$OUT/zeek/$name"
    mkdir -p "$dir"
    abs=$(realpath "$pcap")
    (cd "$dir" && zeek -C -r "$abs" LogAscii::use_json=T)
    echo "  zeek -> $dir"
  else
    echo "  zeek not found; skipping (install: https://zeek.org/get-zeek/)"
  fi

  if [ -n "${CICFLOWMETER:-}" ]; then
    "$CICFLOWMETER" "$pcap" "$OUT/cic/"
    echo "  CICFlowMeter -> $OUT/cic/"
  fi
done

[ -z "${CICFLOWMETER:-}" ] && echo "Tip: set CICFLOWMETER=/path/to/cfm to also produce CIC-format CSVs."
exit 0
