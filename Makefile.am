if PRO
PRODIRS = zorpaddr
else
PRODIRS =
endif

SUBDIRS = lib libproxy modules zorp pylib doc debian zorpctl zorpblgen scripts tests solbuild $(PRODIRS)


EXTRA_DIST = dist.conf BUGS module.list WHATIS.TXT VERSION

bin_SCRIPTS = zorp-config

zorp-config: zorp-config.in


pkgincludedir=$(includedir)/zorp
pkginclude_HEADERS = zorpconfig.h

COPYING: COPYING.in@PACKAGE_SUFFIX@
	cp $< $@

# distdir=$(PACKAGE)-$(VERSION)

MAINTAINERCLEANFILES=dist.conf COPYING

dist.conf: dist.conf.in
	$(top_builddir)/config.status --file $@:$<
