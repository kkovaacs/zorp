LIBS=@MODULETESTS_LIBS@

check_PROGRAMS = http_parse_url http_canon_url

http_parse_url_SOURCES = http_parse_url.c 
http_parse_url_LDADD = ../httpmisc.lo

http_canon_url_SOURCES = http_canon_url.c 
http_canon_url_LDADD = ../httpmisc.lo

TESTS = http_parse_url http_canon_url
