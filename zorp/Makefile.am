pkglibdir=$(libdir)/zorp
LIBS=@ZORP_LIBS@

if PRO
SUBDIRS = urlfilter
endif

pkglib_PROGRAMS = zorp

zorp_SOURCES = main.c 

sysconf_DATA = policy.py.sample

EXTRA_DIST = policy.py.sample logtags.txt logtags_gperf.c logtags_gperf.h logtags.gperf

install-exec-local:
	mkdir -p $(DESTDIR)/$(sysconfdir)
	mkdir -p $(DESTDIR)/$(sysconfdir)/urlfilter
	chmod 0700 $(DESTDIR)/$(sysconfdir)
	mkdir -p $(DESTDIR)/$(pidfiledir)
	mkdir -p $(DESTDIR)/$(localstatedir)/quarantine
	mkdir -p $(DESTDIR)/$(localstatedir)/tmp
	mkdir -p $(DESTDIR)/$(localstatedir)/audit
	mkdir -p $(DESTDIR)/$(localstatedir)/urlfilter

main.c: logtags_gperf.c

BUILT_SOURCES = logtags_gperf.c logtags_gperf.h logtags.gperf

logtags_gperf.c: logtags.gperf logtags_gperf.h
	$(GPERF) -e ";" -t -N z_logtag_lookup_gperf $< > $@.T && mv $@.T $@

logtags_gperf.h: logtags.txt
	$(top_srcdir)/scripts/genlutable.sh header LOGTAG $< >$@.tmp && mv $@.tmp $@

logtags.gperf: logtags.txt
	$(top_srcdir)/scripts/genlutable.sh gperf LOGTAG $< >$@.tmp && mv $@.tmp $@
