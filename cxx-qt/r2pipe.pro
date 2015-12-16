CONFIG += qt
SOURCES += r2pipe.cxx
SOURCES += test.cxx

QT += network
QT += core

QMAKE_CXXFLAGS_RELEASE += -g
QMAKE_CFLAGS += -g
QMAKE_LFLAGS_RELEASE += -g
