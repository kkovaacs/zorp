pkglibdir=$(libdir)/zorp
LIBS=@ZORP_LIBS@

sbin_PROGRAMS = zorpaddr

zorpaddr_SOURCES = main.c ifcfg.c cfg.c zshmem.c stats.c cfg.h  ifcfg.h  stats.h  zorpaddr.h  zshmem.h ping.h ping.c

sysconf_DATA = zorpaddr.cfg.sample

EXTRA_DIST = $(sysconf_DATA)
