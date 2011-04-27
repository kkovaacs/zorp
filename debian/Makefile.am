EXTRA_DIST = changelog compat control copyright rules instances.conf \
	libzorp@PACKAGE_SUFFIX@@LIBZORP_LT_COMPAT_BRANCH@.files \
	libzorp@PACKAGE_SUFFIX@@LIBZORP_LT_RELEASE@-dev.files \
	python-kzorp.files \
	zorp@PACKAGE_SUFFIX@.docs \
	zorp@PACKAGE_SUFFIX@.files \
	zorp@PACKAGE_SUFFIX@.init \
	zorp@PACKAGE_SUFFIX@.postinst \
	zorp@PACKAGE_SUFFIX@-modules.postrm \
	zorp@PACKAGE_SUFFIX@-doc.files \
	zorp@PACKAGE_SUFFIX@-doc.doc-base.reference \
	zorp@PACKAGE_SUFFIX@-doc.doc-base.tutorial

libzorp@PACKAGE_SUFFIX@@LIBZORP_LT_COMPAT_BRANCH@.files: libzorp.files.in
	cp $< $@

libzorp@PACKAGE_SUFFIX@@LIBZORP_LT_RELEASE@-dev.files: libzorp-dev.files.in
	cp $< $@

zorp@PACKAGE_SUFFIX@-doc.files: zorp-doc.files.in
	cp $< $@

zorp@PACKAGE_SUFFIX@.docs: zorp.docs.in
	cp $< $@

zorp@PACKAGE_SUFFIX@.init: zorp.init.in
	cp $< $@

zorp@PACKAGE_SUFFIX@-modules.postrm: zorp-modules.postrm.in
	cp $< $@

zorp@PACKAGE_SUFFIX@-doc.files: zorp-doc.files.in
	cp $< $@

zorp@PACKAGE_SUFFIX@-doc.doc-base.reference: zorp-doc.doc-base.reference.in
	cp $< $@

zorp@PACKAGE_SUFFIX@-doc.doc-base.tutorial: zorp-doc.doc-base.tutorial.in
	cp $< $@

changelog: changelog.in
	$(top_builddir)/config.status --file $@:$<

control: control.in@PACKAGE_SUFFIX@
	$(top_builddir)/config.status --file $@:$<

copyright: copyright.in@PACKAGE_SUFFIX@
	$(top_builddir)/config.status --file $@:$<

python-kzorp.files: python-kzorp.files.in
	$(top_builddir)/config.status --file $@:$<

rules: rules.in@PACKAGE_SUFFIX@
	$(top_builddir)/config.status --file $@:$<
	chmod 755 $@

MAINTAINERCLEANFILES=control changelog rules
