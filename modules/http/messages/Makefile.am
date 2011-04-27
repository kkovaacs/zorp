
ERROR_FILES = clientsyntax.html connecterror.html internal.html \
	invalidurl.html ioerror.html policysyntax.html policyviolation.html \
	serversyntax.html auth.html servertimeout.html clienttimeout.html badcontent.html ftperror.html \
	redirect.html

LANGUAGES = en hu de
EXTRA_DIST = $(addprefix en/,$(ERROR_FILES)) $(addprefix hu/,$(ERROR_FILES)) $(addprefix de/,$(ERROR_FILES))

pkgdatadir = @datadir@/zorp/http

install-data-hook:
	for lang in $(LANGUAGES); do \
		test -d $(DESTDIR)$(pkgdatadir)/$$lang || mkdir -p $(DESTDIR)$(pkgdatadir)/$$lang; \
		$(INSTALL) -c -m 644 $(addprefix $(srcdir)/$${lang}/,$(ERROR_FILES)) $(DESTDIR)$(pkgdatadir)/$${lang}; \
	done

#pkgdata_DATA = $(EXTRA_DIST)
