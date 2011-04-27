if PRO
EXTRA_DIST = rules rules.conf pkginfo.run pkginfo.run.in \
 pkgmaker.sh prototype-maker.sh admin depend space preinstall \
 postinstall preremove postremove pkginfo.dev pkginfo.dev.in

pkginfo.dev: pkginfo.dev.in
	$(top_builddir)/config.status --file $@:$<

pkginfo.run: pkginfo.run.in
	$(top_builddir)/config.status --file $@:$<

endif

MAINTAINERCLEANFILES = pkginfo.dev pkginfo.run
