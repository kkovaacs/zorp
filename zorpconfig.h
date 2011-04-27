/* zorpconfig.h.  Generated from zorpconfig.h.in by configure.  */
/* zorpconfig.h.in.  Generated from configure.in by autoheader.  */

/* Enable debugging */
#define ENABLE_DEBUG 0

/* Enable ipf based tproxy */
#define ENABLE_IPFILTER_TPROXY 0

/* Enable IP option processing */
#define ENABLE_IPOPTIONS 0

/* Enable IPv6 support */
#define ENABLE_IPV6 0

/* Enable Linux 2.2 tproxy behaviour */
#define ENABLE_LINUX22_TPROXY 0

/* Enable netfilter tproxy */
#define ENABLE_NETFILTER_TPROXY 1

/* Enable prefork support */
#define ENABLE_PREFORK 0

/* Enable trace messages */
#define ENABLE_TRACE 0

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the `gethostbyname_r' function. */
#define HAVE_GETHOSTBYNAME_R 1

/* Define to 1 if you have the <google/coredumper.h> header file. */
/* #undef HAVE_GOOGLE_COREDUMPER_H */

/* Define to 1 if you have the `inet_aton' function. */
#define HAVE_INET_ATON 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Have MSG_PROXY flag (Linux 2.2) */
#define HAVE_MSG_PROXY 1

/* Define to 1 if you have the `prctl' function. */
#define HAVE_PRCTL 1

/* Zorp may enable core_dumping Linux 2.4- */
#define HAVE_PR_SET_DUMPABLE 1

/* Define to 1 if you have the <Python.h> header file. */
#define HAVE_PYTHON_H 1

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the `snprintf' function. */
#define HAVE_SNPRINTF 1

/* Define to 1 if you have the `socket' function. */
#define HAVE_SOCKET 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* We have a Solaris style gethostbyname_r; */
/* #undef HAVE_SUN_GETHOSTBYNAME_R */

/* Define to 1 if you have the <sys/capability.h> header file. */
#define HAVE_SYS_CAPABILITY_H 1

/* Define to 1 if you have the <sys/prctl.h> header file. */
#define HAVE_SYS_PRCTL_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vsnprintf' function. */
#define HAVE_VSNPRINTF 1

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* The size of `void *', as computed by sizeof. */
#define SIZEOF_VOID_P 8

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Zorp package version */
#define VERSION "3.9.0"

/* Configuration date */
#define ZORP_CONFIG_DATE "2011/02/16"

/* datadir */
#define ZORP_DATADIR "/home/coroner/zwa/install/zorp-mainline-4.0/share/zorp"

/* libdir */
#define ZORP_LIBDIR "/home/coroner/zwa/install/zorp-mainline-4.0/lib/zorp"

/* Required license version */
#define ZORP_LICENSE_VERSION "3.3"

/* pidfiledir */
#define ZORP_PIDFILEDIR "/home/coroner/zwa/install/zorp-mainline-4.0/var/run/zorp/"

/* Required product name in license */
#define ZORP_PRODUCT_NAME "Zorp Professional"

/* Zorp source revision number */
#define ZORP_SOURCE_REVISION "ssh+git://coroner@git.balabit//var/scm/git/zorp/zorp-core--mainline--4.0#master#fcb59dd06e0805ce995b8d94cc8c12096e385365"

/* localstatedir */
#define ZORP_STATEDIR "/home/coroner/zwa/install/zorp-mainline-4.0/var"

/* sysconfdir */
#define ZORP_SYSCONFDIR "/home/coroner/zwa/install/zorp-mainline-4.0/etc/zorp"

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */
