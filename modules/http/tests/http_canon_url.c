#include "../http.h"

#define BOOL_STR(x) ((x) ? "TRUE" : "FALSE")

gboolean
test_case(gint id, gchar *url_str, gboolean unicode, gboolean invalid_escape, gboolean format_absolute, gboolean canonicalize, gchar *expected_url_str)
{
  HttpURL url;
  gchar *fail_reason = NULL;
  const gchar *error_reason = NULL;
  gboolean ok = TRUE, valid;
  GString *formatted_url = g_string_sized_new(0);
  
  http_init_url(&url);
  valid = http_parse_url(&url, unicode, invalid_escape, FALSE, url_str, &error_reason);
  if (ok && !valid)
    {
      fail_reason = g_strdup_printf("Error parsing URL: %s", !valid ? error_reason : "No error");
      ok = FALSE;
    }
  if (ok && !http_format_url(&url, formatted_url, format_absolute, unicode, canonicalize, &error_reason))
    {
      fail_reason = g_strdup_printf("Error reformatting URL: %s", error_reason);
      ok = FALSE;
    }
  if (ok && strcmp(formatted_url->str, expected_url_str) != 0)
    {
      fail_reason = g_strdup_printf("Canonicalized URL not matching: %s <> %s", formatted_url->str, expected_url_str);
      ok = FALSE;
    }

  g_string_free(formatted_url, TRUE);
  
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
  gboolean format_absolute;
  gboolean canonicalize;
  gchar *expected_url_str;
} test_table[] =

{
  { "http://user:pass@test.host:8080/file",    FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host:8080/file" },
  { "http://user:pass@test.host:8080/file?é",  FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host:8080/file?%E9" },
  { "http://user:pass@test.host:8080/file?é",  FALSE, TRUE,  TRUE,  TRUE, "http://user:pass@test.host:8080/file?%E9" },
  { "http://user:pass@test.host:8080/fileé",   FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host:8080/file%E9" },
  { "http://user:pass@test.host:8080/fileé",   FALSE, TRUE,  TRUE,  TRUE, "http://user:pass@test.host:8080/file%E9" },
  { "http://user:pass@test.host:8080/file",    FALSE, FALSE, FALSE, TRUE, "/file" },
  { "http://user:pass@test.host/file",         FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/file" },
  { "http://user:pass@test.host",              FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/" },
  { "http://user:pass@test.host/file?query#fragment",         
                                               FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/file?query#fragment" },
  { "http://user:pass@test.host/file#fragment",
                                               FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/file#fragment" },
  { "http://user:pass@test.host/file?query",         
                                               FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/file?query" },
  { "http://user@test.host:8080/file",         FALSE, FALSE, TRUE,  TRUE, "http://user@test.host:8080/file" },
  { "http://user:pass@test.host/file",         FALSE, FALSE, TRUE,  TRUE, "http://user:pass@test.host/file" },
  { "http://user@test.host/file",              FALSE, FALSE, TRUE,  TRUE, "http://user@test.host/file" },
  { "http://test.host:8080/file",              FALSE, FALSE, TRUE,  TRUE, "http://test.host:8080/file" },
  { "http://test.host/file",                   FALSE, FALSE, TRUE,  TRUE, "http://test.host/file" },
  { "http://test.host/default.idaNNNN%u9090%u6858%ucbd3",
                                               FALSE, TRUE,  TRUE,  TRUE, "http://test.host/default.idaNNNN%u9090%u6858%uCBD3" },
  { "http://test.host/ad/N2558.travelport.telnet/B36496;sz=468x60;ord=%5B%25GMTTIME%25%5D?", 
                                               FALSE, FALSE, TRUE,  TRUE, "http://test.host/ad/N2558.travelport.telnet/B36496;sz=468x60;ord=[%25GMTTIME%25]" },
  { "http://test.host/ad/N2558.travelport.telnet/B36496?sz=468x60;ord=%5B%25GMTTIME%25%5D", 
                                               FALSE, FALSE, TRUE,  TRUE, "http://test.host/ad/N2558.travelport.telnet/B36496?sz=468x60;ord=%5B%25GMTTIME%25%5D" },
  { "http://user:pass@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26",  
                                               FALSE, TRUE,  TRUE,  TRUE, "http://user:pass@test.host/fi/../le?%3Fa&%26" },
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%40",  
                                               FALSE, TRUE,  TRUE,  TRUE, "http://user:pass%40@test.host/fi/../le?%3Fa&%26#%40" },
/* Not implemented yet.
  { "http://use%72:p%61ss%40@test.host/fi%%le",  
                                               FALSE, FALSE, TRUE,  TRUE, "http://user:pass%40@test.host/fi%%le" }, */
  /* invalid escaping, invalid_escape disabled */
  { "http://use%72:p%61ss%40@test.host/fi%2g%2e%2e%2fle?%u003f%61&%26#%40",  
                                               TRUE,  TRUE,  TRUE,  TRUE, "http://user:pass%40@test.host/fi%252g../le?%3Fa&%26#%40" },
  /* no canonicalization, URL must remain the same, except the username/password part */
  { "http://use%72:p%61ss%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%40",  
                                               FALSE, TRUE,  TRUE,  FALSE, "http://user:pass%40@test.host/fi%2f%2e%2e%2fle?%u003f%61&%26#%40" },
  { NULL }
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
          if (test_case(i, test_table[i].url_str, test_table[i].unicode, test_table[i].invalid_escape, test_table[i].format_absolute, test_table[i].canonicalize,
                        test_table[i].expected_url_str))
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
      test_case(i, test_table[i].url_str, test_table[i].unicode, test_table[i].invalid_escape, test_table[i].format_absolute, test_table[i].canonicalize, test_table[i].expected_url_str);
    }
  
  return !(fail_count == 0);
  
}
