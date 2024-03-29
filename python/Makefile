PWD=$(shell pwd)
PYTHON?=`pwd`/python-wrapper
PYTHON_VERSION?=`${PYTHON} --version 2>&1 | cut -d ' ' -f 2 | cut -d . -f 1,2`
PYTHON_PKGDIR=$(shell ${PYTHON} ../../mp.py)
PYTHON_INSTALL_DIR=${DESTDIR}/${PYTHON_PKGDIR}/r2pipe

PYTHON2=python
PYTHON3=python3

all:
	$(PYTHON) setup.py build sdist

install: uninstall
	$(PYTHON) setup.py install

clean:
	$(PYTHON) setup.py clean
	rm -rf dist

symstall: uninstall
	ln -fs $(PWD)/r2pipe "$(PYTHON_INSTALL_DIR)"

twine:
	sudo pip install -U twine

test: testpy2 testpy3 test-examples

testpy2:
	@echo "Testing $(PYTHON)"
	PYTHONPATH=$$PWD $(PYTHON) -m pip install coverage pytest
	PYTHONPATH=$$PWD $(PYTHON) -m coverage run --omit="*.local*" -m pytest -k "test_" test
	PYTHONPATH=$$PWD $(PYTHON) -m coverage report
	-pylint r2pipe/*.py

test-examples:
	$(PYTHON) examples/test.py
	$(PYTHON) examples/test2.py

testpy3:
	@$(MAKE) testpy2 PYTHON=$(PYTHON3)

uninstall:
	rm -rf "$(PYTHON_INSTALL_DIR)"

.PHONY: twine

pub publish: all
	twine upload -u __token__ --repository-url https://upload.pypi.org/legacy/ --verbose dist/*
