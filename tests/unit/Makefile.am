LIBS = @ZORP_LIBS@ @MODULES_LIBS@

check_PROGRAMS = pystruct test_audit test_szig test_bllookup
check_SCRIPTS = test_bllookup.sh

pystruct_SOURCES = pystruct.c
test_audit_SOURCES = test_audit.c
test_szig_SOURCES = test_szig.c
test_bllookup_SOURCES = test_bllookup.c

TESTS = pystruct test_audit test_szig test_bllookup.sh

EXTRA_DIST = pystruct.py
