EXTRA_DIST = setup.py
SUBDIRS = kznf

clean:
	$(PYTHON) $(top_srcdir)/pylib/kznf/setup.py clean --all

distclean: clean

install-exec-local:
	$(PYTHON) $(top_srcdir)/pylib/kznf/setup.py install --prefix $(DESTDIR)/$(prefix) --install-layout=deb

