.PHONY: setup data test lint clean

PY ?= python

setup:            ## Install dependencies (run inside an activated virtualenv)
	$(PY) -m pip install -r requirements.txt
	$(PY) -m pip install -e .

data:             ## Clean raw CIC-IDS2017 CSVs into data/interim/
	$(PY) -m detector.data --config configs/data.yaml

test:             ## Run unit tests
	$(PY) -m pytest -q

lint:             ## Lint with ruff
	ruff check src tests

clean:            ## Remove generated interim/processed data
	rm -f data/interim/*.parquet data/interim/*.json data/processed/*.parquet
