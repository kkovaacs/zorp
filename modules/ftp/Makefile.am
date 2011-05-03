SUBDIRS = tests

pkgdatadir = @datadir@/zorp/pylib/Zorp
pkglibdir = @libdir@/zorp
LIBS = @MODULES_LIBS@
CPPFLAGS = @MODULES_CPPFLAGS@

pkgdata_DATA = Ftp.py

pkglib_LTLIBRARIES = libftp.la

libftp_la_SOURCES = ftp.c ftphash.c ftpmsg.c ftpcmd.c ftpolicy.c ftpdata.c ftp.h ftpcmd.h ftphash.h ftpolicy.h ftpmsg.h 

EXTRA_DIST = $(pkgdata_DATA) 
