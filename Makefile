.PHONY: check test

check:
	python3 -m py_compile gateway/*.py
	python3 -m unittest discover -s tests

test:
	python3 -m unittest discover -s tests
