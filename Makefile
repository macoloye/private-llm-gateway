.PHONY: check test

check:
	python3 -m py_compile gateway/config.py gateway/logging.py gateway/server.py gateway/__main__.py
	python3 -m unittest discover -s tests

test:
	python3 -m unittest discover -s tests
