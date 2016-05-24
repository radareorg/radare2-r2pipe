include ../../config.mk

all:
	valac main.vala r2pipe.vala
	valac --library=r2pipe -H r2pipe.h r2pipe.vala -X -fPIC -c
	rm -f libr2pipe.a
	ar q libr2pipe.a r2pipe.vala.o

install:
	mkdir -p $(DESTDIR)/${PREFIX}/lib/pkgconfig
	cp -f r2pipe.pc $(DESTDIR)/${PREFIX}/lib/pkgconfig/r2pipe.pc
	mkdir -p $(DESTDIR)/${PREFIX}/share/vala/vapi
	cp -f r2pipe.vapi $(DESTDIR)/${PREFIX}/share/vala/vapi/r2pipe.vapi

uninstall:
	rm -f $(DESTDIR)/${PREFIX}/lib/pkgconfig/r2pipe.pc
	rm -f $(DESTDIR)/${PREFIX}/share/vala/vapi/r2pipe.vapi
