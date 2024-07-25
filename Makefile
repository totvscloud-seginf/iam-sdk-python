setup_env:
	poetry env use 3.9
	poetry shell

deps:
	poetry install

build:
	poetry build

test:
	poetry run python -m unittest tests/test_*.py