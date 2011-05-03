pkgdatadir = @datadir@/zorp/pylib/Zorp
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Telnet.py

pkglib_LTLIBRARIES = libtelnet.la

libtelnet_la_SOURCES = telnet.c telnetpolicy.c telnetoption.c telnet.h telnetpolicy.h telnetoption.h

EXTRA_DIST = $(pkgdata_DATA) 
