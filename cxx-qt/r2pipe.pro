CONFIG += qt
SOURCES += r2pipe.cxx \
    r2pipe-api.cxx
SOURCES += test.cxx

QT += network
QT += core

QMAKE_CXXFLAGS_RELEASE += -g
QMAKE_CFLAGS += -g
QMAKE_LFLAGS_RELEASE += -g

HEADERS += \
    r2pipe.h

INCLUDEPATH += /usr/local/radare2/include/libr
LIBS += -L/usr/local/radare2/lib -lr_core -lr_util
