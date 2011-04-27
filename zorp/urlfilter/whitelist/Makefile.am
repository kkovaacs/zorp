EXTRA_DIST = urls domains

install-exec-local:
	install -m 0755 -d $(DESTDIR)/$(sysconfdir)/urlfilter/whitelist
	install -m 0644 -t $(DESTDIR)/$(sysconfdir)/urlfilter/whitelist $(srcdir)/urls $(srcdir)/domains
