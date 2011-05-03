SUBDIRS = . messages  tests

pkgdatadir = @datadir@/zorp/pylib/Zorp
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@
AM_CFLAGS = @CFLAGS@ -W

pkgdata_DATA = Http.py

pkglib_LTLIBRARIES = libhttp.la

libhttp_la_SOURCES = http.c httpproto.c httpfltr.c httpmisc.c httphdr.c httpftp.c http.h

EXTRA_DIST =  $(pkgdata_DATA)
