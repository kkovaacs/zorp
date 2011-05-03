pkgdatadir = @datadir@/zorp/pylib/Zorp
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = AnyPy.py

pkglib_LTLIBRARIES = libanypy.la

libanypy_la_SOURCES = anypy.c

EXTRA_DIST = $(pkgdata_DATA)
