include $(shell ocamlc -where)/Makefile.config

VERSION = 0.0.1

FLAGS = -bin-annot -dtypes -g
CMO = r2pipe.cmo
CMX = r2pipe.cmx

ifeq ($(NATDYNLINK),true)
CMXS = r2pipe.cmxs
endif
PACKS = yojson

.PHONY: default all opt install uninstall install-lib uninstall-lib

default: META all opt
all: $(CMO)
opt: $(CMX) 

ifndef PREFIX
  PREFIX = $(shell dirname $$(dirname $$(which ocamlfind)))
  export PREFIX
endif

ifndef BINDIR
  BINDIR = $(PREFIX)/bin
  export BINDIR
endif

META: META.in Makefile
	sed -e 's:@@VERSION@@:$(VERSION):' META.in > META

install-lib:
	ocamlfind install r2pipe META \
	  $(wildcard *.cmt) $(wildcard *.cmti) $(wildcard *.mli) \
	  $(wildcard *.cmi) $(wildcard *$(EXT_LIB)) $(wildcard *.cmo) \
	  $(wildcard *$(EXT_OBJ)) $(wildcard *.cmx)

uninstall-lib:
	ocamlfind remove r2pipe

reinstall:
	$(MAKE) BINDIR=$(BINDIR) uninstall
	$(MAKE) BINDIR=$(BINDIR) install

r2pipe.cmo:
	ocamlfind ocamlc -c $(FLAGS) -package $(PACKS) r2pipe.ml

r2pipe.cmx:
	ocamlfind ocamlopt -c $(FLAGS) -package $(PACKS) r2pipe.ml

.PHONY: clean

clean:
	rm -f *.o *.a *.cm* *~ *.annot META
