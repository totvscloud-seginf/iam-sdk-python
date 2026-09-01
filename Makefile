.PHONY: setup_env

setup_env:
	@poetry env use 3.10
	@echo 'Execute: eval "$$(poetry env activate)"'

deps:
	poetry install

build:
	poetry build

test:
	poetry run python -m unittest tests/test_*.py