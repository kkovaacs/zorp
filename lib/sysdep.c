/***************************************************************************
 *
 * Copyright (c) 2000, 2001 BalaBit IT Ltd, Budapest, Hungary
 * All rights reserved.
 *
 * $Id: sysdep.c,v 1.24 2004/04/15 11:41:49 bazsi Exp $
 *
 * Author  : Bazsi
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/sysdep.h>
#include <zorp/log.h>

#include <zorp/dgram.h>
#include <zorp/tpsocket.h>


#include <stdlib.h>

#if ENABLE_NETFILTER_TPROXY

#define in_tproxy in_tproxy_v12
#include <zorp/nfiptproxy-kernel.h>
#undef in_tproxy

#include <zorp/nfiptproxy-kernelv2.h>
#endif

/**
 * z_sysdep_parse_tproxy_arg:
 * @sysdep_tproxy_arg: --tproxy argument passed to Zorp
 *
 * This function converts the --tproxy argument to an internal Z_SD_TPROXY_*
 * representation.
 *
 * Returns: one of the Z_SD_TPROXY_* values
 **/
static gint
z_sysdep_parse_tproxy_arg(const gchar *sysdep_tproxy_arg)
{
  if (sysdep_tproxy_arg)
    {
      if (strcasecmp(sysdep_tproxy_arg, "tproxy40") == 0)
        {
          return Z_SD_TPROXY_NETFILTER_V40;
        }
      else if (strcasecmp(sysdep_tproxy_arg, "tproxy30") == 0)
        {
          return Z_SD_TPROXY_NETFILTER_V30;
        }
      else if (strcasecmp(sysdep_tproxy_arg, "netfilterv2") == 0 || strcasecmp(sysdep_tproxy_arg, "tproxy20") == 0)
        {
          return Z_SD_TPROXY_NETFILTER_V20;
        }
      else if (strcasecmp(sysdep_tproxy_arg, "netfilter") == 0 || strcasecmp(sysdep_tproxy_arg, "tproxy12") == 0)
        {
          return Z_SD_TPROXY_NETFILTER_V12;
        }
      else if (strcasecmp(sysdep_tproxy_arg, "linux22") == 0)
        {
          return Z_SD_TPROXY_LINUX22;
        }
      else if (strcasecmp(sysdep_tproxy_arg, "ipf") == 0)
        {
          return Z_SD_TPROXY_IPF;
        }
    }
  return 0;
}

/**
 * z_sysdep_init:
 * @sysdep_tproxy_arg: --tproxy argument passed to Zorp
 *
 * Initialize runtime system detection, currently it boils down to detecting
 * kernel support for transparent proxying.
 *
 * Returns: TRUE to indicate success
 **/
gboolean
z_sysdep_init(const gchar *sysdep_tproxy_arg)
{
  const gchar *sysdep_tproxy_str[] = 
  {
    [0]                            NULL,
    [Z_SD_TPROXY_LINUX22]          "linux22",
    [Z_SD_TPROXY_NETFILTER_V12]    "tproxy12",
    [Z_SD_TPROXY_IPF]              "ipf",
    [Z_SD_TPROXY_NETFILTER_V20]    "tproxy20",
    [Z_SD_TPROXY_NETFILTER_V30]    "tproxy30",
    [Z_SD_TPROXY_NETFILTER_V40]    "tproxy40"
  };
  gint sysdep_tproxy = z_sysdep_parse_tproxy_arg(sysdep_tproxy_arg);
  

  if (system("/sbin/modprobe iptable_tproxy >/dev/null 2>&1") == -1)
    return FALSE;
  if (sysdep_tproxy == 0)
    {
#if ENABLE_NETFILTER_TPROXY
      
      /* FIXME: we'd need a way to discover tproxy 4.0 is indeed there, as
       * it currently is tproxy below 4.0 will never be detected */
      sysdep_tproxy = Z_SD_TPROXY_NETFILTER_V40;
      
      if (sysdep_tproxy == 0)
        {
          struct in_tproxy itp;
          socklen_t size = sizeof(itp);
          gint sock;

          sysdep_tproxy = Z_SD_TPROXY_LINUX22;
          
          sock = socket(PF_INET, SOCK_STREAM, 0);
          if (sock != -1)
            {
              memset(&itp, 0, sizeof(itp));
              itp.op = TPROXY_VERSION;
              itp.v.version = 0x03000000;
              if (setsockopt(sock, SOL_IP, IP_TPROXY, &itp, size) == 0)
                {
                  sysdep_tproxy = Z_SD_TPROXY_NETFILTER_V30;
                }
              else
                {
                  /* not TProxy 3.0 */
                  itp.op = TPROXY_VERSION;
                  itp.v.version = 0x02000000;
                  if (setsockopt(sock, SOL_IP, IP_TPROXY, &itp, size) == -1)
                    {
                      /* not TProxy 2.0 */
                      guint flags;
                      socklen_t flagslen = sizeof(flags);
                      if (getsockopt(sock, SOL_IP, IP_TPROXY_FLAGS, &flags, &flagslen) == -1)
                        {
                          if (errno != ENOPROTOOPT)
                            sysdep_tproxy = Z_SD_TPROXY_NETFILTER_V12;
                        }
                      else
                        sysdep_tproxy = Z_SD_TPROXY_NETFILTER_V12;
                    }
                  else
                    {
                      sysdep_tproxy = Z_SD_TPROXY_NETFILTER_V30;
                    }
                }
              close(sock);
            }
        }
#elif ENABLE_LINUX22_TPROXY
      sysdep_tproxy = Z_SD_TPROXY_LINUX22;
#else
      #error "No known tproxy support"
#endif
    }
  /*LOG
    This message reports that system dependant was successful, tproxy support was set.
   */
  z_log(NULL, CORE_DEBUG, 6, "System dependant init; sysdep_tproxy='%s'", sysdep_tproxy_str[sysdep_tproxy]);
  if (!z_dgram_init(sysdep_tproxy))
    return FALSE;
  if (!z_tp_socket_init(sysdep_tproxy))
    return FALSE;
    
  return TRUE;
}

void
z_sysdep_destroy(void)
{
}
