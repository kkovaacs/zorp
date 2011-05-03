pkgdatadir = @datadir@/zorp/pylib/Zorp
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Plug.py

pkglib_LTLIBRARIES = libplug.la

libplug_la_SOURCES = plug.c

EXTRA_DIST = $(pkgdata_DATA)
