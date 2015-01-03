PWD=$(shell pwd)
PYTHON?=`pwd`/../../python-wrapper
PYTHON_VERSION?=`${PYTHON} --version 2>&1 | cut -d ' ' -f 2 | cut -d . -f 1,2`
PYTHON_PKGDIR=$(shell ${PYTHON} ../../mp.py)
PYTHON_INSTALL_DIR=${DESTDIR}/${PYTHON_PKGDIR}/r2pipe

all:

install: uninstall
	cp -rf r2pipe "$(PYTHON_INSTALL_DIR)"

symstall: uninstall
	ln -fs $(PWD)/r2pipe "$(PYTHON_INSTALL_DIR)"

uninstall:
	rm -rf "$(PYTHON_INSTALL_DIR)"
