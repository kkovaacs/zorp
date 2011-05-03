pkgdatadir = @datadir@/zorp/pylib/Zorp
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Whois.py

pkglib_LTLIBRARIES = libwhois.la

libwhois_la_SOURCES = whois.c

EXTRA_DIST = $(pkgdata_DATA)
