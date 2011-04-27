SUBDIRS = . zorp

LIBS = @LIBZORP_LIBS@

lib_LTLIBRARIES = libzorp.la

libzorp_la_LDFLAGS = \
	-version-info $(LIBZORP_LT_CURRENT):0:$(LIBZORP_LT_AGE) \
	-release $(LIBZORP_LT_RELEASE) \
	-export-dynamic

libzorp_la_SOURCES = \
	satyr.c pysatyr.c \
	pyzasauth.c zasauth.c \
	proxy.c proxystack.c modules.c  \
	pycore.c pysockaddr.c pypolicy.c \
	pyproxy.c pystream.c \
	zorp.c \
	authprovider.c \
	sysdep.c tpsocket.c dimhash.c \
	szig.c \
	pydispatch.c dispatch.c \
	attach.c connection.c pyattach.c \
	plugsession.c  zpython.c \
	dgram.c \
	pydict.c pystruct.c audit.c \
	ifmonitor.c proxygroup.c pyproxygroup.c \
	coredump.c notification.c pybalance.c \
	pyaudit.c timestamp.c idsconn.c \
	proxyssl.c pyx509.c proxysslhostiface.c \
	bllookup.c \
	kzorp.c

