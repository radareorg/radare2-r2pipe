include ../../config.mk

all:
	valac -g -X -O3 main.vala r2pipe.vala
	valac -g -X -O3 --library=r2pipe -H r2pipe.h r2pipe.vala -X -fPIC -c
	rm -f libr2pipe.a
	ar q libr2pipe.a r2pipe.vala.o

install:
	mkdir -p $(DESTDIR)/${PREFIX}/lib/pkgconfig
	cp -f r2pipe.pc $(DESTDIR)/${PREFIX}/lib/pkgconfig/r2pipe.pc
	mkdir -p $(DESTDIR)/${PREFIX}/share/vala/vapi
	cp -f r2pipe.vapi $(DESTDIR)/${PREFIX}/share/vala/vapi/r2pipe.vapi
	mkdir -p $(DESTDIR)/${PREFIX}/include/r2pipe
	cp -f r2pipe.h $(DESTDIR)/${PREFIX}/include/r2pipe/r2pipe.h
	mkdir -p $(DESTDIR)/${PREFIX}/lib
	cp -f libr2pipe.a $(DESTDIR)/${PREFIX}/lib/libr2pipe.a

uninstall:
	rm -f $(DESTDIR)/${PREFIX}/lib/pkgconfig/r2pipe.pc
	rm -f $(DESTDIR)/${PREFIX}/share/vala/vapi/r2pipe.vapi
	rm -rf $(DESTDIR)/${PREFIX}/include/r2pipe
	rm -f $(DESTDIR)/${PREFIX}/lib/libr2pipe.a
