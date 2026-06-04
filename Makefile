# SIEM-Lite — convenience targets
# Usage: make <target>
# Requires: Python 3.9+, Docker, pip

PYTHON  := python3
VENV    := venv
PIP     := $(VENV)/bin/pip
PYTEST  := $(VENV)/bin/pytest

DATASET := data/auth_logs_labeled.csv
LINES   := 50000

# ── Environment ─────────────────────────────────────────────────────────────
.PHONY: venv install
venv:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip

install: venv
	$(PIP) install -r requirements.txt

# ── Data ────────────────────────────────────────────────────────────────────
.PHONY: dataset
dataset:
	$(PYTHON) data/generate_dataset.py --num-lines $(LINES) --output $(DATASET)

# ── ML pipeline ─────────────────────────────────────────────────────────────
.PHONY: train
train: $(DATASET)
	cd ml && $(PYTHON) train_and_evaluate.py --dataset ../$(DATASET)

$(DATASET):
	$(MAKE) dataset

# ── Tests ────────────────────────────────────────────────────────────────────
.PHONY: test test-unit test-integration
test: test-unit test-integration

test-unit:
	$(PYTEST) scripts/test_alert_scorer.py ml/test_ml_pipeline.py -v

test-integration:
	$(PYTEST) scripts/test_integration.py -v

test-ml-scorer:
	$(PYTEST) scripts/test_ml_scorer.py -v

# ── Docker stack ─────────────────────────────────────────────────────────────
.PHONY: up down logs
up:
	cp -n .env.example .env 2>/dev/null || true
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

# ── Scorers ──────────────────────────────────────────────────────────────────
.PHONY: score score-ml
score:
	$(PYTHON) scripts/alert_scorer.py

score-ml:
	$(PYTHON) scripts/ml_scorer.py

# ── Clean ────────────────────────────────────────────────────────────────────
.PHONY: clean
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true

.PHONY: help
help:
	@echo ""
	@echo "SIEM-Lite targets:"
	@echo "  make install        — create venv and install dependencies"
	@echo "  make dataset        — generate 50k synthetic auth-log lines"
	@echo "  make train          — train RF + Isolation Forest models"
	@echo "  make test           — run all tests (unit + integration)"
	@echo "  make test-unit      — alert_scorer + ML pipeline unit tests"
	@echo "  make test-integration — end-to-end + sliding-window tests"
	@echo "  make test-ml-scorer — ml_scorer unit tests"
	@echo "  make up             — start Docker stack (PLG)"
	@echo "  make down           — stop Docker stack"
	@echo "  make score          — run rule-based alert scorer"
	@echo "  make score-ml       — run ML-enhanced scorer"
	@echo "  make clean          — remove cache files"
	@echo ""