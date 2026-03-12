PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
VERSION ?= 6.1.0
VALAC ?= valac
AR ?= ar

.SUFFIXES:

PKGS = --pkg gio-2.0 --pkg gio-unix-2.0 --pkg json-glib-1.0 --pkg posix
VALAFLAGS = -g -X -O3 $(PKGS)
ASANFLAGS = -g -X -O0 -X -fsanitize=address -X -fno-omit-frame-pointer $(PKGS)
LIBRARY = r2pipe
STATIC_LIB = libr2pipe.a
PKGCONFIG = r2pipe.pc
TEST_BIN = test-vala
ASAN_BIN = test-vala-asan

all: main $(STATIC_LIB) $(PKGCONFIG)

main: main.vala r2pipe.vala
	$(VALAC) $(VALAFLAGS) -o $@ main.vala r2pipe.vala

$(STATIC_LIB): r2pipe.vala
	$(VALAC) $(VALAFLAGS) --library=$(LIBRARY) --header=r2pipe.h --vapi=r2pipe.vapi -X -fPIC -c r2pipe.vala
	rm -f $(STATIC_LIB)
	$(AR) rcs $(STATIC_LIB) r2pipe.vala.o

$(PKGCONFIG): r2pipe.pc.acr
	sed \
		-e 's|@PREFIX@|$(PREFIX)|g' \
		-e 's|@LIBDIR@|$(LIBDIR)|g' \
		-e 's|@VERSION@|$(VERSION)|g' \
		$< > $@

$(TEST_BIN): tests.vala r2pipe.vala
	$(VALAC) $(VALAFLAGS) -o $@ tests.vala r2pipe.vala

$(ASAN_BIN): tests.vala r2pipe.vala
	$(VALAC) $(ASANFLAGS) -o $@ tests.vala r2pipe.vala

test: $(TEST_BIN)
	./$(TEST_BIN)

asan: $(ASAN_BIN)

install: $(STATIC_LIB) $(PKGCONFIG)
	mkdir -p $(DESTDIR)$(PREFIX)/lib/pkgconfig
	cp -f $(PKGCONFIG) $(DESTDIR)$(PREFIX)/lib/pkgconfig/$(PKGCONFIG)
	mkdir -p $(DESTDIR)$(PREFIX)/share/vala/vapi
	cp -f r2pipe.vapi $(DESTDIR)$(PREFIX)/share/vala/vapi/r2pipe.vapi
	mkdir -p $(DESTDIR)$(PREFIX)/include/r2pipe
	cp -f r2pipe.h $(DESTDIR)$(PREFIX)/include/r2pipe/r2pipe.h
	mkdir -p $(DESTDIR)$(LIBDIR)
	cp -f $(STATIC_LIB) $(DESTDIR)$(LIBDIR)/$(STATIC_LIB)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/pkgconfig/$(PKGCONFIG)
	rm -f $(DESTDIR)$(PREFIX)/share/vala/vapi/r2pipe.vapi
	rm -rf $(DESTDIR)$(PREFIX)/include/r2pipe
	rm -f $(DESTDIR)$(LIBDIR)/$(STATIC_LIB)

clean:
	rm -f main
	rm -f $(TEST_BIN)
	rm -f $(ASAN_BIN)
	rm -f $(STATIC_LIB)
	rm -f $(PKGCONFIG)
	rm -f r2pipe.h
	rm -f r2pipe.vapi
	rm -f r2pipe.c
	rm -f r2pipe.vala.c
	rm -f r2pipe.vala.o
	rm -f tests.c
	rm -rf main.dSYM
	rm -rf test-vala.dSYM
	rm -rf test-vala-asan.dSYM

.PHONY: all test asan install uninstall clean
