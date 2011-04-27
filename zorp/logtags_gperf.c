/* C code produced by gperf version 3.0.3 */
/* Command-line: /usr/bin/gperf -e ';' -t -N z_logtag_lookup_gperf logtags.gperf  */
/* Computed positions: -k'1-2,6,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gnu-gperf@gnu.org>."
#endif

#line 4 "logtags.gperf"
struct tagid { char *name; int id; };

#define TOTAL_KEYWORDS 141
#define MIN_WORD_LENGTH 8
#define MAX_WORD_LENGTH 17
#define MIN_HASH_VALUE 9
#define MAX_HASH_VALUE 318
/* maximum key range = 310, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (str, len)
     register const char *str;
     register unsigned int len;
{
  static const unsigned short asso_values[] =
    {
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319,  65, 319, 319, 319,
      115, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319,  85, 145,  80,
      100,   5,  90,   5,  70,  60,  45, 319, 110, 115,
       15,  35,  10,  50,   0,  25,   0, 115,  15,  15,
      110,   0, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319, 319, 319, 319,
      319, 319, 319, 319, 319, 319, 319
    };
  return len + asso_values[(unsigned char)str[5]] + asso_values[(unsigned char)str[1]+1] + asso_values[(unsigned char)str[0]] + asso_values[(unsigned char)str[len - 1]];
}

#ifdef __GNUC__
__inline
#ifdef __GNUC_STDC_INLINE__
__attribute__ ((__gnu_inline__))
#endif
#endif
const struct tagid *
z_logtag_lookup_gperf (str, len)
     register const char *str;
     register unsigned int len;
{
  static const struct tagid wordlist[] =
    {
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0},
#line 95 "logtags.gperf"
      {"rsh.error", 89},
      {"",0}, {"",0}, {"",0}, {"",0},
#line 88 "logtags.gperf"
      {"rdp.error", 82},
      {"",0}, {"",0},
#line 131 "logtags.gperf"
      {"tftp.request", 125},
      {"",0},
#line 94 "logtags.gperf"
      {"rsh.debug", 88},
#line 129 "logtags.gperf"
      {"tftp.error", 123},
      {"",0}, {"",0}, {"",0},
#line 87 "logtags.gperf"
      {"rdp.debug", 81},
#line 79 "logtags.gperf"
      {"pssl.error", 73},
#line 130 "logtags.gperf"
      {"tftp.policy", 124},
      {"",0}, {"",0}, {"",0},
#line 75 "logtags.gperf"
      {"pop3.reply", 69},
#line 80 "logtags.gperf"
      {"pssl.policy", 74},
#line 76 "logtags.gperf"
      {"pop3.request", 70},
      {"",0},
#line 118 "logtags.gperf"
      {"ssh.error", 112},
#line 73 "logtags.gperf"
      {"pop3.error", 67},
#line 91 "logtags.gperf"
      {"rdp.session", 85},
#line 114 "logtags.gperf"
      {"sqlnet.error", 108},
      {"",0},
#line 115 "logtags.gperf"
      {"sqlnet.request", 109},
      {"",0},
#line 74 "logtags.gperf"
      {"pop3.policy", 68},
      {"",0}, {"",0},
#line 117 "logtags.gperf"
      {"ssh.debug", 111},
#line 96 "logtags.gperf"
      {"rsh.policy", 90},
      {"",0}, {"",0}, {"",0},
#line 132 "logtags.gperf"
      {"tftp.violation", 126},
#line 90 "logtags.gperf"
      {"rdp.policy", 84},
      {"",0},
#line 111 "logtags.gperf"
      {"smtp.request", 105},
      {"",0}, {"",0},
#line 108 "logtags.gperf"
      {"smtp.error", 102},
#line 116 "logtags.gperf"
      {"sqlnet.violation", 110},
      {"",0},
#line 112 "logtags.gperf"
      {"smtp.response", 106},
#line 134 "logtags.gperf"
      {"vnc.error", 128},
#line 65 "logtags.gperf"
      {"nntp.reply", 59},
#line 110 "logtags.gperf"
      {"smtp.policy", 104},
#line 66 "logtags.gperf"
      {"nntp.request", 60},
#line 89 "logtags.gperf"
      {"rdp.info", 83},
#line 77 "logtags.gperf"
      {"pop3.violation", 71},
#line 67 "logtags.gperf"
      {"nntp.trace", 61},
      {"",0}, {"",0}, {"",0},
#line 133 "logtags.gperf"
      {"vnc.debug", 127},
#line 119 "logtags.gperf"
      {"ssh.policy", 113},
#line 64 "logtags.gperf"
      {"nntp.policy", 58},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
#line 104 "logtags.gperf"
      {"sip.error", 98},
      {"",0},
#line 137 "logtags.gperf"
      {"vnc.session", 131},
      {"",0},
#line 122 "logtags.gperf"
      {"ssh.info", 116},
#line 113 "logtags.gperf"
      {"smtp.violation", 107},
#line 41 "logtags.gperf"
      {"imap.reply", 35},
#line 100 "logtags.gperf"
      {"sip.request", 94},
#line 42 "logtags.gperf"
      {"imap.request", 36},
#line 97 "logtags.gperf"
      {"rsh.violation", 91},
#line 103 "logtags.gperf"
      {"sip.debug", 97},
#line 38 "logtags.gperf"
      {"imap.error", 32},
      {"",0},
#line 101 "logtags.gperf"
      {"sip.response", 95},
#line 92 "logtags.gperf"
      {"rdp.violation", 86},
      {"",0},
#line 136 "logtags.gperf"
      {"vnc.policy", 130},
#line 40 "logtags.gperf"
      {"imap.policy", 34},
      {"",0}, {"",0},
#line 93 "logtags.gperf"
      {"rsh.accounting", 87},
      {"",0}, {"",0},
#line 124 "logtags.gperf"
      {"telnet.error", 118},
#line 125 "logtags.gperf"
      {"telnet.policy", 119},
      {"",0},
#line 11 "logtags.gperf"
      {"core.error", 5},
      {"",0},
#line 123 "logtags.gperf"
      {"telnet.debug", 117},
#line 135 "logtags.gperf"
      {"vnc.info", 129},
      {"",0}, {"",0},
#line 15 "logtags.gperf"
      {"core.policy", 9},
      {"",0},
#line 120 "logtags.gperf"
      {"ssh.violation", 114},
      {"",0},
#line 102 "logtags.gperf"
      {"sip.policy", 96},
      {"",0}, {"",0}, {"",0},
#line 43 "logtags.gperf"
      {"imap.violation", 37},
#line 128 "logtags.gperf"
      {"tftp.debug", 122},
#line 126 "logtags.gperf"
      {"telnet.violation", 120},
      {"",0}, {"",0},
#line 121 "logtags.gperf"
      {"ssh.accounting", 115},
#line 78 "logtags.gperf"
      {"pssl.debug", 72},
#line 17 "logtags.gperf"
      {"core.stderr", 11},
#line 47 "logtags.gperf"
      {"ldap.request", 41},
      {"",0}, {"",0},
#line 45 "logtags.gperf"
      {"ldap.error", 39},
      {"",0},
#line 127 "logtags.gperf"
      {"telnet.violations", 121},
#line 48 "logtags.gperf"
      {"ldap.response", 42},
      {"",0},
#line 72 "logtags.gperf"
      {"pop3.debug", 66},
#line 46 "logtags.gperf"
      {"ldap.policy", 40},
      {"",0},
#line 138 "logtags.gperf"
      {"vnc.violation", 132},
      {"",0},
#line 69 "logtags.gperf"
      {"plug.error", 63},
      {"",0},
#line 16 "logtags.gperf"
      {"core.session", 10},
      {"",0},
#line 109 "logtags.gperf"
      {"smtp.info", 103},
#line 106 "logtags.gperf"
      {"smtp.accounting", 100},
#line 70 "logtags.gperf"
      {"plug.policy", 64},
#line 19 "logtags.gperf"
      {"finger.error", 13},
#line 20 "logtags.gperf"
      {"finger.policy", 14},
#line 21 "logtags.gperf"
      {"finger.request", 15},
      {"",0},
#line 140 "logtags.gperf"
      {"whois.error", 134},
#line 18 "logtags.gperf"
      {"finger.debug", 12},
#line 141 "logtags.gperf"
      {"whois.request", 135},
      {"",0},
#line 107 "logtags.gperf"
      {"smtp.debug", 101},
#line 139 "logtags.gperf"
      {"whois.debug", 133},
      {"",0},
#line 99 "logtags.gperf"
      {"sip.violation", 93},
#line 49 "logtags.gperf"
      {"ldap.violation", 43},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
#line 63 "logtags.gperf"
      {"nntp.debug", 57},
#line 22 "logtags.gperf"
      {"finger.violation", 16},
      {"",0},
#line 51 "logtags.gperf"
      {"lp.error", 45},
#line 105 "logtags.gperf"
      {"sip.accounting", 99},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
#line 54 "logtags.gperf"
      {"mime.error", 48},
      {"",0},
#line 71 "logtags.gperf"
      {"plug.session", 65},
      {"",0},
#line 39 "logtags.gperf"
      {"imap.info", 33},
      {"",0},
#line 55 "logtags.gperf"
      {"mime.policy", 49},
#line 82 "logtags.gperf"
      {"radius.error", 76},
#line 83 "logtags.gperf"
      {"radius.policy", 77},
#line 84 "logtags.gperf"
      {"radius.request", 78},
      {"",0}, {"",0},
#line 81 "logtags.gperf"
      {"radius.debug", 75},
      {"",0}, {"",0},
#line 37 "logtags.gperf"
      {"imap.debug", 31},
#line 58 "logtags.gperf"
      {"msrpc.error", 52},
#line 60 "logtags.gperf"
      {"msrpc.policy", 54},
      {"",0},
#line 12 "logtags.gperf"
      {"core.info", 6},
#line 7 "logtags.gperf"
      {"core.accounting", 1},
#line 57 "logtags.gperf"
      {"msrpc.debug", 51},
#line 34 "logtags.gperf"
      {"http.request", 28},
      {"",0},
#line 85 "logtags.gperf"
      {"radius.session", 79},
#line 32 "logtags.gperf"
      {"http.error", 26},
#line 86 "logtags.gperf"
      {"radius.violation", 80},
      {"",0},
#line 35 "logtags.gperf"
      {"http.response", 29},
#line 56 "logtags.gperf"
      {"mime.violation", 50},
#line 9 "logtags.gperf"
      {"core.debug", 3},
#line 33 "logtags.gperf"
      {"http.policy", 27},
      {"",0},
#line 61 "logtags.gperf"
      {"msrpc.session", 55},
#line 10 "logtags.gperf"
      {"core.dump", 4},
#line 62 "logtags.gperf"
      {"msrpc.violation", 56},
      {"",0}, {"",0}, {"",0},
#line 24 "logtags.gperf"
      {"ftp.error", 18},
      {"",0}, {"",0},
#line 13 "logtags.gperf"
      {"core.license", 7},
      {"",0},
#line 26 "logtags.gperf"
      {"ftp.reply", 20},
#line 53 "logtags.gperf"
      {"lp.request", 47},
#line 27 "logtags.gperf"
      {"ftp.request", 21},
#line 14 "logtags.gperf"
      {"core.message", 8},
      {"",0},
#line 23 "logtags.gperf"
      {"ftp.debug", 17},
#line 59 "logtags.gperf"
      {"msrpc.info", 53},
      {"",0}, {"",0}, {"",0},
#line 36 "logtags.gperf"
      {"http.violation", 30},
#line 44 "logtags.gperf"
      {"ldap.debug", 38},
      {"",0}, {"",0}, {"",0},
#line 143 "logtags.gperf"
      {"x11.error", 137},
      {"",0},
#line 28 "logtags.gperf"
      {"ftp.session", 22},
      {"",0}, {"",0}, {"",0},
#line 68 "logtags.gperf"
      {"plug.debug", 62},
      {"",0}, {"",0}, {"",0},
#line 142 "logtags.gperf"
      {"x11.debug", 136},
      {"",0},
#line 98 "logtags.gperf"
      {"satyr.error", 92},
      {"",0}, {"",0}, {"",0},
#line 25 "logtags.gperf"
      {"ftp.policy", 19},
      {"",0}, {"",0}, {"",0},
#line 8 "logtags.gperf"
      {"core.auth", 2},
      {"",0},
#line 146 "logtags.gperf"
      {"x11.session", 140},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
#line 145 "logtags.gperf"
      {"x11.policy", 139},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0},
#line 52 "logtags.gperf"
      {"lp.policy", 46},
      {"",0}, {"",0}, {"",0},
#line 144 "logtags.gperf"
      {"x11.info", 138},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
#line 30 "logtags.gperf"
      {"http.accounting", 24},
      {"",0}, {"",0},
#line 29 "logtags.gperf"
      {"ftp.violation", 23},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
#line 31 "logtags.gperf"
      {"http.debug", 25},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
#line 147 "logtags.gperf"
      {"x11.violation", 141},
      {"",0}, {"",0}, {"",0}, {"",0},
#line 50 "logtags.gperf"
      {"lp.debug", 44}
    };

  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register const char *s = wordlist[key].name;

          if (*str == *s && !strcmp (str + 1, s + 1))
            return &wordlist[key];
        }
    }
  return 0;
}
