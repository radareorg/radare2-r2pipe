PERL ?= perl
BUILD_MAKEFILE := Makefile.perl

ifeq ($(origin INSTALL_BASE), undefined)
ifeq ($(origin PREFIX), undefined)
INSTALL_BASE := $(CURDIR)/.install
endif
endif

CONFIGURE_ARGS :=
ifdef INSTALL_BASE
CONFIGURE_ARGS += INSTALL_BASE=$(INSTALL_BASE)
endif
ifdef PREFIX
CONFIGURE_ARGS += PREFIX=$(PREFIX)
endif
ifdef INSTALLDIRS
CONFIGURE_ARGS += INSTALLDIRS=$(INSTALLDIRS)
endif

.PHONY: all install uninstall test clean configure

configure:
	$(PERL) Makefile.PL $(CONFIGURE_ARGS)

all: configure
	$(MAKE) -f $(BUILD_MAKEFILE) all

install: configure
	$(MAKE) -f $(BUILD_MAKEFILE) install $(if $(DESTDIR),DESTDIR=$(DESTDIR))

uninstall:
	@if [ -n "$(INSTALL_BASE)" ]; then \
		packlist=$$(find "$(INSTALL_BASE)" -name .packlist -print -quit 2>/dev/null); \
		if [ -z "$$packlist" ]; then \
			echo "Nothing installed under $(INSTALL_BASE)"; \
			exit 0; \
		fi; \
		$(PERL) -e 'use strict; use warnings; my $$packlist = shift @ARGV; open my $$fh, q{<}, $$packlist or die "Cannot open $$packlist: $$!\\n"; while (my $$path = <$$fh>) { chomp $$path; next if $$path eq q{}; if (-e $$path && !unlink $$path) { warn "Failed to remove $$path: $$!\\n"; } } close $$fh; unlink $$packlist if -e $$packlist;' "$$packlist"; \
		find "$(INSTALL_BASE)" -name perllocal.pod -type f -exec rm -f {} \; 2>/dev/null || true; \
		find "$(INSTALL_BASE)" -depth -type d -empty -exec rmdir {} \; 2>/dev/null || true; \
	else \
		$(PERL) Makefile.PL $(CONFIGURE_ARGS); \
		$(MAKE) -f $(BUILD_MAKEFILE) uninstall $(if $(DESTDIR),DESTDIR=$(DESTDIR)); \
	fi

test: configure
	$(MAKE) -f $(BUILD_MAKEFILE) test

clean:
	@if [ -f $(BUILD_MAKEFILE) ]; then \
		$(MAKE) -f $(BUILD_MAKEFILE) realclean; \
	else \
		rm -rf blib; \
		rm -f MYMETA.json MYMETA.yml pm_to_blib $(BUILD_MAKEFILE); \
	fi
