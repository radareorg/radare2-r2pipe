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
	sudo pip install twine

test: test2 test3

test2:
	@echo "Testing $(PYTHON)"
	-PYTHONPATH=$$PWD $(PYTHON) examples/bug.py
	-PYTHONPATH=$$PWD $(PYTHON) examples/test.py

test3:
	@$(MAKE) test2 PYTHON=$(PYTHON3)

uninstall:
	rm -rf "$(PYTHON_INSTALL_DIR)"

pub publish:
	#LC_CTYPE=C python3 setup.py sdist upload -r pypi
	#LC_CTYPE=C python setup.py sdist upload -r https://upload.pypi.org/pypi/
	twine upload --repository-url https://upload.pypi.org/legacy/ --verbose dist/*
