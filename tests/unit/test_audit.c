#include <zorp/zorp.h>
#include <zorp/ssl.h>
#include <zorp/audit.h>

#include <time.h>

gchar recvd[256];
gchar sent[2];
gboolean ids_setup = FALSE;
int exit_code = 0;

#define TC_INDEX_AUDIT(x) ((x) & 1)
#define TC_INDEX_ENCRYPT(x) ((x) & 2)
#define TC_INDEX_COMPRESS(x) ((x) & 4)
#define TC_INDEX_SIGN(x) ((x) & 8)
#define TC_INDEX_TIMESTAMP(x) ((x) & 16)
#define TC_INDEX_IDS(x) (((x) & 32) && ids_setup)
#define TC_INDEX_LOCAL_PARAMS(x) ((x) & 64)

glong
diff_time(struct timeval *start, struct timeval *stop)
{
  glong usecs, secs = 0;

  usecs = stop->tv_usec - start->tv_usec;
  if (usecs < 0)
    {
      usecs += 1000000;
      secs = -1;
    }
  return (secs + stop->tv_sec - start->tv_sec) * 1000000 + usecs;
}

gboolean
at_test(int index)
{
  ZAuditSession session;
  ZAuditSessionParams *session_params, local_session_params;
  gint i, j;
  gboolean success = FALSE;
  
  z_audit_session_init(&session, "test");

  if (!TC_INDEX_AUDIT(index) && (!TC_INDEX_IDS(index)))
    return TRUE;
    
  if (TC_INDEX_LOCAL_PARAMS(index))
    session_params = &local_session_params;
  else
    session_params = &audit_params.defaults;
  
  session_params->audit = TC_INDEX_AUDIT(index);
  session_params->encrypt = TC_INDEX_ENCRYPT(index);
  session_params->compress = TC_INDEX_COMPRESS(index);
  session_params->sign = TC_INDEX_SIGN(index);
/*  session_params->timestamp = TC_INDEX_TIMESTAMP(index);*/
  session_params->ids = TC_INDEX_IDS(index);

  if (session_params->audit)
    {
      session_params->audit_dir = ".";
    }
  if (session_params->encrypt)
    {
      /* private keys can be found in libzaudit/tests directory */

      /* crypt.crt */
      z_audit_session_params_add_cert(session_params, 0, 0, "-----BEGIN CERTIFICATE-----\n"
                                      "MIICkjCCAfugAwIBAgIBATANBgkqhkiG9w0BAQUFADBGMQswCQYDVQQGEwJIVTET\n"
                                      "MBEGA1UECBMKU29tZS1TdGF0ZTEQMA4GA1UEChMHQmFsYWJpdDEQMA4GA1UEAxMH\n"
                                      "Q0EgY2VydDAeFw0wNzA3MTYxMTI4MTdaFw0wODA3MTUxMTI4MTdaMFsxCzAJBgNV\n"
                                      "BAYTAkhVMRMwEQYDVQQIEwpTb21lLVN0YXRlMREwDwYDVQQHEwhidWRhcGVzdDEQ\n"
                                      "MA4GA1UEChMHYmFsYWJpdDESMBAGA1UEAxMJc3plcnZlci0xMIGfMA0GCSqGSIb3\n"
                                      "DQEBAQUAA4GNADCBiQKBgQCzWf2b3XM4PeOfY7e7K6jL9D58LqC0K6uFxTTvJYnS\n"
                                      "9OcE0ASp63XZILGoxFo52tSvychmGfWpJYQHTEi44jpU+tH5oLIFl4p4IC9Ve+lw\n"
                                      "b77zBfK690a3nRLDLDwSyVB7/UUom1MnrsdUZhrgReeBcTK1pUy92CgvY7fvtjIx\n"
                                      "PQIDAQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdl\n"
                                      "bmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUbnnt81QIwnORFbICZCCL5mqB\n"
                                      "F8EwHwYDVR0jBBgwFoAU0Syv/mmYl00etpycN5VyAeqdc3EwDQYJKoZIhvcNAQEF\n"
                                      "BQADgYEAZ4MeBDNzW1JmLmM+yh2SWu1HSzjcwrN8W3qsmm26zOPzcFLNXT0BQKW5\n"
                                      "Es4UT+qffpq0VDdFyS88QFS2WNcRZkDYQmmthzGuaNnLpS4/esVXuJ5xQJeUN0Kx\n"
                                      "V1hS/v3yYp4GKyMjq3Is+8k525fXkalEMxM2dMG1nbH+EJ0kjpA=\n"
                                      "-----END CERTIFICATE-----\n");
      /* 4eyes.crt */
      z_audit_session_params_add_cert(session_params, 0, 0, "-----BEGIN CERTIFICATE-----\n"
                                      "MIICNTCCAZ4CAQIwDQYJKoZIhvcNAQEEBQAwYjELMAkGA1UEBhMCSFUxETAPBgNV\n"
                                      "BAcTCEJ1ZGFwZXN0MRgwFgYDVQQKEw9CYWxhQml0IElUIEx0ZC4xJjAkBgNVBAMT\n"
                                      "HVRydXN0ZWQgSW50ZXJuZXQgQ2VydGlmaWNhdGVzMB4XDTA0MDkxNjEyMjcyM1oX\n"
                                      "DTA0MDkxODEyMjcyM1owZDELMAkGA1UEBhMCSFUxETAPBgNVBAcTCEJ1ZGFwZXN0\n"
                                      "MRcwFQYDVQQKEw5CYWxhQml0IElUIEx0ZDERMA8GA1UECxMIaW50cmFuZXQxFjAU\n"
                                      "BgNVBAMTDXd3d2h1LmJhbGFiaXQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB\n"
                                      "AK62iH4tQ6wsaUPHpFuJTpD4v4OaNH0EUpfch8qpbUB9SiZE7qFYMzOKQ5jfRVs3\n"
                                      "0NS+dXghwSraxAfoZkXxWMXlyJANPqXMXzpGCcwbf0/pwL81//yYe8YkC27Le+2z\n"
                                      "T4AyFVZy7RCj4G4Cwsx0Vnmife47gGevSrdiGEgLLQ+7AgMBAAEwDQYJKoZIhvcN\n"
                                      "AQEEBQADgYEALBYONWgvOLg0WGtbKg4C/E2wJQcd9flBnc+zfHoGeIdqnT45gxah\n"
                                      "oko00oEfSmtefnixE8onysKUFX6F/sFbn4xSj0LDq4FjSmPvOWEJrGaOBRmNtvjs\n"
                                      "33zFKFUaB/iN6SUrUB/zEqkSxAB5FIyRXPaHwvxDH6Xl+7T2E5dYi1I=\n"
                                      "-----END CERTIFICATE-----\n");

    }
  if (session_params->sign)
    {
      /* crypt.crt & crypt.key */
      session_params->sign_private_key = "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIICXQIBAAKBgQCzWf2b3XM4PeOfY7e7K6jL9D58LqC0K6uFxTTvJYnS9OcE0ASp\n"
        "63XZILGoxFo52tSvychmGfWpJYQHTEi44jpU+tH5oLIFl4p4IC9Ve+lwb77zBfK6\n"
        "90a3nRLDLDwSyVB7/UUom1MnrsdUZhrgReeBcTK1pUy92CgvY7fvtjIxPQIDAQAB\n"
        "AoGBALL8HN7+mizHfrCjOEl/IZ4gqncNpW0Io80E6HW81ZWEuEQSQIU+qUY9nW7a\n"
        "PVy9aUHhMq/KOmJKQT9zPqPbiO93P9ZkESdkJG5iG3uPyEpFUp66AC07B7kAaTjW\n"
        "g1W28i0lBPGcLqECSL0SgY6TNOv2fyO3B0fAtkBT+kLjpDuBAkEA49PeY/7aZyry\n"
        "6Rx8Cu/i9TE2r2UxM1BXSiYPUlHarrrjvtNvOB3Xqmn6GYrK7gELlE9Y8/O/YCor\n"
        "OZdOY8HSYQJBAMmHjwHxGOeT4OQp6MCqGiYF7buYIQlYeEE5SGNZcqm6EhqO/fa1\n"
        "tIer0rXgKt5RzHV1hmrbYGzkPrxT/yRHRF0CQE3DBhg5Z5BpH2ojl88f2+Z2usSZ\n"
        "FHcASBr97KLbX3nePlfm0QJlZTQ8YeoP7n3YC3y+rIzvuHV5TzGkDFSOVmECQQCx\n"
        "p6OktZIby1vMJzm8ZfeJH17UKaat42SXMtUiZ57SCmqdKQKucr4Df6/Pjx6bP4a6\n"
        "4PCu0FcvhwHa6T0ZEQ4tAkBVcPTi9lvLeYnVfGaO/Y75DVX/ezhwYI+zMR//w982\n"
        "gtVuxJkxB0mbNhTDDABcMzgWsxHhyXsSvdj24Z1JRp0c\n"
        "-----END RSA PRIVATE KEY-----\n";

      session_params->sign_certificate = "-----BEGIN CERTIFICATE-----\n"
        "MIICkjCCAfugAwIBAgIBATANBgkqhkiG9w0BAQUFADBGMQswCQYDVQQGEwJIVTET\n"
        "MBEGA1UECBMKU29tZS1TdGF0ZTEQMA4GA1UEChMHQmFsYWJpdDEQMA4GA1UEAxMH\n"
        "Q0EgY2VydDAeFw0wNzA3MTYxMTI4MTdaFw0wODA3MTUxMTI4MTdaMFsxCzAJBgNV\n"
        "BAYTAkhVMRMwEQYDVQQIEwpTb21lLVN0YXRlMREwDwYDVQQHEwhidWRhcGVzdDEQ\n"
        "MA4GA1UEChMHYmFsYWJpdDESMBAGA1UEAxMJc3plcnZlci0xMIGfMA0GCSqGSIb3\n"
        "DQEBAQUAA4GNADCBiQKBgQCzWf2b3XM4PeOfY7e7K6jL9D58LqC0K6uFxTTvJYnS\n"
        "9OcE0ASp63XZILGoxFo52tSvychmGfWpJYQHTEi44jpU+tH5oLIFl4p4IC9Ve+lw\n"
        "b77zBfK690a3nRLDLDwSyVB7/UUom1MnrsdUZhrgReeBcTK1pUy92CgvY7fvtjIx\n"
        "PQIDAQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdl\n"
        "bmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUbnnt81QIwnORFbICZCCL5mqB\n"
        "F8EwHwYDVR0jBBgwFoAU0Syv/mmYl00etpycN5VyAeqdc3EwDQYJKoZIhvcNAQEF\n"
        "BQADgYEAZ4MeBDNzW1JmLmM+yh2SWu1HSzjcwrN8W3qsmm26zOPzcFLNXT0BQKW5\n"
        "Es4UT+qffpq0VDdFyS88QFS2WNcRZkDYQmmthzGuaNnLpS4/esVXuJ5xQJeUN0Kx\n"
        "V1hS/v3yYp4GKyMjq3Is+8k525fXkalEMxM2dMG1nbH+EJ0kjpA=\n"
        "-----END CERTIFICATE-----\n";
    }
  if (session_params->ids)
    {
      static gint dst_port = 33333;

      session_params->ids_src = z_sockaddr_inet_new("192.168.0.1", 55555);
      session_params->ids_dst = z_sockaddr_inet_new("192.168.0.2", dst_port++);

    }

  if (!TC_INDEX_LOCAL_PARAMS(index))
    {
      memset(&local_session_params, 0, sizeof(local_session_params));
      session_params = &local_session_params;
    }
  z_audit_session_params_init(session_params);
  for (i = 0; i < 10; i++)
    {
      ZAuditStream stream;

      if (!z_audit_stream_init(&stream, &session, ZA_SOURCE_STREAM, session_params, "test", "test1", NULL))
        {
          fprintf(stderr, "error initializing audit stream\n");
          goto error;
        }
      fprintf(stderr, "Starting stream, stream count=%d\n", i);
      /* now feed some data */
      for (j = 0; j < 1000; j++)
        {
          if (!z_audit_stream_data_sent(&stream, sent, sizeof(sent)) ||
              !z_audit_stream_data_sent(&stream, sent, sizeof(sent)) ||
              !z_audit_stream_data_recvd(&stream, recvd, sizeof(recvd)))
            {
              fprintf(stderr, "error adding data to audit stream\n");
              goto error;
            }
        }
      z_audit_stream_deinit(&stream);
    }
  success = TRUE;
 error:
  z_audit_session_deinit(&session);
  return success;
}

extern gboolean audit_trail_test;

void
testcase(int index)
{
  struct timeval start, end;
  gboolean success;

  audit_params.per_session = TRUE;
  gettimeofday(&start, NULL);
  success = at_test(index);
  gettimeofday(&end, NULL);
  fprintf(stdout, "%s: Testing audit=%d, encrypt=%d, compress=%d, sign=%d, timestamp: %d, ids: %d, time: %ld\n", success ? "PASS" : "FAIL", 
          TC_INDEX_AUDIT(index),
          TC_INDEX_ENCRYPT(index),
          TC_INDEX_COMPRESS(index),
          TC_INDEX_SIGN(index),
          0 && TC_INDEX_TIMESTAMP(index),
          TC_INDEX_IDS(index),
          diff_time(&start, &end));
  
  if (!success)
    exit_code = 1;
}

static int
init_audit()
{
  audit_trail_test = TRUE;
  audit_params.rate_limit = 100*1024*1024;
  audit_params.write_size_max = 1024*1024*1024;
  audit_params.sign_interval = 1;

  if (getuid() == 0)
    {
      system("modprobe dummy; ifconfig dummy0 up");
      audit_params.ids_interface = "dummy0";
      audit_params.ids_src_mac = "f2:ba:23:27:c9:26";
      audit_params.ids_dst_mac = "f2:ba:23:27:c9:27";
      ids_setup = TRUE;
    }
  
  g_thread_init(NULL);
  z_ssl_init();
  if (!z_audit_init("test"))
    {
      fprintf(stderr, "error initializing audit subsystem\n");
      return 0;
    }
  return 1;
}

int 
main(void)
{
  gint i;
  
  for (i = 0; i < sizeof(recvd); i++)
    recvd[i] = i % 26 + 'A';
  for (i = 0; i < sizeof(sent); i++)
    sent[i] = i % 26 + 'a';
    
  if (!init_audit())
    return 1;
    
  for (i = 0; i < 128; i++)
    testcase(i);
  z_audit_destroy();
  return exit_code;
}
