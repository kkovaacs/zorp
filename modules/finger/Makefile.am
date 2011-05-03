pkgdatadir = @datadir@/zorp/pylib/Zorp
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Finger.py

pkglib_LTLIBRARIES = libfinger.la

libfinger_la_SOURCES = finger.c

EXTRA_DIST = $(pkgdata_DATA)
