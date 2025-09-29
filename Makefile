.PHONY: help run

# Python and module settings
PYTHON ?= python3
MODULE := packages.code_score_lib.run

# Directory containing one or more benchmark JSON configs
# Override with: make run CONFIG_DIR=sample_models_config
CONFIG_DIR ?= sample_models_config

help:
	@echo "Targets:"
	@echo "  run           Run benchmarks from a config directory"
	@echo ""
	@echo "Usage:"
	@echo "  make run CONFIG_DIR=path/to/configs"
	@echo ""
	@echo "Defaults:"
	@echo "  CONFIG_DIR=$(CONFIG_DIR)"

run:
	$(PYTHON) -m $(MODULE) "$(CONFIG_DIR)"

