#include "../http.h"
  
#define BOOL_STR(x) ((x) ? "TRUE" : "FALSE")

#define TEST_STR(field) \
  do 											\
    {											\
      if (ok && 									\
          ((field && memcmp(field, url. field->str, url. field->len) != 0) ||		\
           (!field && url. field->len)))    						\
        { 										\
          fail_reason = g_strdup_printf("Returned and expected value for " #field " mismatch: %s <> %s", url. field->str, field);		\
          ok = FALSE;									\
        }										\
    }											\
  while (0)

gboolean
test_case(gint id, gchar *url_str, gboolean unicode, gboolean invalid_escape, gboolean expected_valid, gchar *scheme, gchar *user, gchar *passwd, gchar *host, guint port, gchar *file, gchar *query, gchar *fragment)
{
  HttpURL url;
  gchar *fail_reason = NULL;
  const gchar *error_reason = NULL;
  gboolean ok = TRUE, valid;
  
  http_init_url(&url);
  valid = http_parse_url(&url, unicode, invalid_escape, FALSE, url_str, &error_reason);
  
  if (ok && valid != expected_valid)
    {
      fail_reason = g_strdup_printf("Parse result different than expected: %s", !valid ? error_reason : "No error");
      ok = FALSE;
    }
  if (valid)
    {
      TEST_STR(scheme);
      TEST_STR(user);
      TEST_STR(passwd);
      TEST_STR(host);
      if (ok && port && port != url.port)
        {
          fail_reason = g_strdup("Return and expected value for port mismatch");
          ok = FALSE;
        }
      TEST_STR(file);
      TEST_STR(query);
      TEST_STR(fragment);
    }

  if (ok)
    {      
      printf("test success, id=%d, url=%s\n", id, url_str);
      return TRUE;
    }
  else
    {
      printf("test failure, id=%d, url=%s, reason=%s\n", id, url_str, fail_reason);
      g_free(fail_reason);
      return FALSE;
    }
}

struct
{
  gchar *url_str;
  gboolean invalid_escape;
  gboolean unicode;
  gboolean valid;
  gchar *scheme;
  gchar *user;
  gchar *passwd;
  gchar *host;
  guint port;
  gchar *file;
  gchar *query;
  gchar *fragment;
} test_table[] =

{
  { "http://user:pass@test.host:8080/file",    FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 8080, "/file",        NULL, NULL },
  { "http://user:pass@test.host/file",         FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        NULL, NULL },
  { "http://user:pass@test.host",              FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/",            NULL, NULL },
  { "http://user:pass@test.host?",             FALSE, FALSE, FALSE },
  { "http://user:pass@test.host#",             FALSE, FALSE, FALSE },
  { "http://user:pass@test.host/file?query#fragment",         
                                               FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        "query", "fragment" },
  { "http://user:pass@test.host/file#fragment?start",
                                               FALSE, FALSE, FALSE, },
  { "http://user:pass@test.host/file#fragment",
                                               FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        NULL, "fragment" },
  { "http://user:pass@test.host/file?query",         
                                               FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        "query", NULL },
  { "http://user@test.host:8080/file",         FALSE, FALSE, TRUE, "http", "user", NULL,   "test.host", 8080, "/file",        NULL, NULL },
  { "http://user:pass@test.host/file",         FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        NULL, NULL },
  { "http://user@test.host/file",              FALSE, FALSE, TRUE, "http", "user", NULL,   "test.host", 0,    "/file",        NULL, NULL },
  { "http://test.host:8080/file",              FALSE, FALSE, TRUE, "http", NULL,   NULL,   "test.host", 8080, "/file",        NULL, NULL },
  { "http://test.host/file",                   FALSE, FALSE, TRUE, "http", NULL,   NULL,   "test.host", 0,    "/file",        NULL, NULL },
  { "http://user:pass:test.host:54/file",      FALSE, FALSE, FALSE  },
  { "http://www.korridor.hu/default.ida?NNNN%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531b%u53ff%u0078%u0000%u0090=a", 
                                               FALSE, FALSE, FALSE },
  { "http://test.host/default.idaNNNN%u9090%u6858%ucbd3",
                                               FALSE, TRUE,  TRUE,  "http",  NULL,   NULL,  "test.host", 0,    "/default.ida\x4e\x4e\x4e\x4e\xe9\x82\x90\xe6\xa1\x98\xec\xaf\x93",
                                                                                                                              NULL, NULL },
  { "http://test.host/ad/N2558.travelport.telnet/B36496;sz=468x60;ord=%5B%25GMTTIME%25%5D?", 
                                               FALSE, FALSE, TRUE, "http", NULL,   NULL,   "test.host", 0,    "/ad/N2558.travelport.telnet/B36496;sz=468x60;ord=[%GMTTIME%]", 
                                                                                                                              NULL, NULL },
  { "http://user:pass@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26",  
                                               FALSE, TRUE,  TRUE, "http", "user", "pass", "test.host", 0,    "/fi/../le",        "%3Fa&%26", NULL },
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%40",  
                                               FALSE, TRUE,  TRUE, "http", "user", "pass@", "test.host", 0,    "/fi/../le",        "%3Fa&%26", "%40" },
  /* invalid escaping, invalid_escape disabled */
  { "http://use%72:p%61ss%40@test.host/fi%2g%2e%2e%2fle?%u003f%61&%26#%40",  
                                               FALSE, TRUE,  FALSE, },
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003g%61&%26#%40",  
                                               FALSE, TRUE,  FALSE, },
  { "http://use%72:p%61ss%40@test.host/fi%2g%2e%2e%2fle?%u003f%61&%26#%40",  
                                               FALSE, FALSE, FALSE, },
  { "http://use%72:p%61ss%40@test.host/fi%2g%2e%2e%2fle?%u003f%61&%26#%40",  
                                               FALSE, FALSE, FALSE, },
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%4",  
                                               FALSE, FALSE, FALSE, },
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%u434",  
                                               FALSE, TRUE,  FALSE, },
  { "http//userpass@test.host/file",           FALSE, FALSE, FALSE },
  { "http:userpass@test.host/file",            FALSE, FALSE, FALSE },
  { "http://user:pass@test.host/file?\x1b",    FALSE, FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/file",        "%1B", NULL },

  /* invalid escaping, invalid_escape, enabled */
  { "http://user:pass@test.host/f%2gile",      TRUE,  FALSE, TRUE, "http", "user", "pass", "test.host", 0,    "/f%2gile",        NULL, NULL },
  { "http://user:pass@test.host/f%u123gile",   TRUE,  TRUE,  TRUE, "http", "user", "pass", "test.host", 0,    "/f%u123gile",        NULL, NULL },
  
  { NULL, }
};

int
main(int argc, char *argv[])
{
  gint i, testcase_id = -1;
  gint fail_count = 0, success_count = 0;
  
  if (argc == 2)
    testcase_id = atoi(argv[1]);
  
  if (testcase_id == -1)
    {
      for (i = 0; test_table[i].url_str; i++)
        {
          if (test_case(i, test_table[i].url_str, test_table[i].unicode, test_table[i].invalid_escape, test_table[i].valid, 
                        test_table[i].scheme, test_table[i].user,  test_table[i].passwd,
                        test_table[i].host, test_table[i].port,  test_table[i].file,
                        test_table[i].query, test_table[i].fragment))
            {
              success_count++;
            }
          else
            {
              fail_count++;
            }
        }
    
      printf("Report: %d success, %d failed\n", success_count, fail_count);
    }
  else
    {
      i = testcase_id;
      test_case(i, test_table[i].url_str, test_table[i].unicode, test_table[i].invalid_escape, test_table[i].valid, 
                          test_table[i].scheme, test_table[i].user,  test_table[i].passwd,
                          test_table[i].host, test_table[i].port,  test_table[i].file,
                          test_table[i].query, test_table[i].fragment);
    }
  
  return !(fail_count == 0);
  
}
