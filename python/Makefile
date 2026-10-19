PWD=$(shell pwd)
PYTHON?=`pwd`/python-wrapper
PYTHON_VERSION?=`${PYTHON} --version 2>&1 | cut -d ' ' -f 2 | cut -d . -f 1,2`
PYTHON_PKGDIR=$(shell ${PYTHON} ../../mp.py)
PYTHON_INSTALL_DIR=${DESTDIR}/${PYTHON_PKGDIR}/r2pipe

PYTHON2=python
PYTHON3?=python3

RELEASE_VENV?=.venv-release
RELEASE_PYTHON=$(RELEASE_VENV)/bin/python
BUILD?=$(RELEASE_PYTHON) -m build
TWINE?=$(RELEASE_PYTHON) -m twine

all: release-tools
	$(BUILD) --sdist --wheel

release-tools: $(RELEASE_VENV)/.ready

$(RELEASE_VENV)/.ready: requirements-release.txt
	$(PYTHON3) -m venv "$(RELEASE_VENV)"
	"$(RELEASE_PYTHON)" -m pip install --upgrade -r requirements-release.txt
	touch "$@"

install: uninstall
	$(PYTHON) setup.py install

clean:
	$(PYTHON) setup.py clean
	rm -rf dist

symstall: uninstall
	ln -fs $(PWD)/r2pipe "$(PYTHON_INSTALL_DIR)"

twine: release-tools
	"$(RELEASE_PYTHON)" -m pip install --upgrade -r requirements-release.txt

test: testpy2 test-examples

# TODO: fix all the failing tests one by one
test2: testpy3

testpy2:
	@echo "Testing $(PYTHON)"
	PYTHONPATH=$$PWD $(PYTHON) -m pytest --version >/dev/null 2>&1 && \
		PYTHONPATH=$$PWD $(PYTHON) -m coverage --version >/dev/null 2>&1 || \
		PYTHONPATH=$$PWD $(PYTHON) -m pip install --user coverage pytest pylint
	PYTHONPATH=$$PWD $(PYTHON) -m coverage run --omit="*.local*" -m pytest -k "test_" test
	PYTHONPATH=$$PWD $(PYTHON) -m coverage report

lint:
	-pylint r2pipe/*.py

test-examples:
	PYTHONPATH=$$PWD $(PYTHON) examples/test.py
	PYTHONPATH=$$PWD $(PYTHON) examples/test2.py

testpy3:
	@$(MAKE) testpy2 PYTHON=$(PYTHON3)

uninstall:
	rm -rf "$(PYTHON_INSTALL_DIR)"

.PHONY: all release-tools twine check pub publish

check: all
	$(TWINE) check --strict dist/*

pub publish: check
	$(TWINE) upload -u __token__ --repository-url https://upload.pypi.org/legacy/ --skip-existing --verbose dist/*
