/***************************************************************************
 *
 * Copyright (c) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009,
 * 2010, 2011 BalaBit IT Ltd, Budapest, Hungary
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * Note that this permission is granted for only version 2 of the GPL.
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Author  : Mincer
 *
 ***************************************************************************/

#include <zorp/zorp.h>
#include <zorp/proxy.h>
#include <zorp/proxysslhostiface.h>

#include <openssl/x509v3.h>

typedef struct _ZProxySslHostIface
{
  ZProxyHostIface super;
  X509 *server_cert;
  gboolean hostname_checked;
  gboolean hostname_check_result;
} ZProxySslHostIface;

static gboolean
z_proxy_ssl_host_iface_check_wildcard(ZProxy *s, const gchar *host_name, const gchar *pattern)
{
  gchar **pattern_parts, **hostname_parts;
  gboolean success = FALSE;
  gint i;

  z_proxy_log(s, CORE_DEBUG, 6, "Checking certificate subject; host='%s', pattern='%s'", host_name, pattern);
  pattern_parts = g_strsplit(pattern, ".", 0);
  hostname_parts = g_strsplit(host_name, ".", 0);
  for (i = 0; pattern_parts[i]; i++)
    {
      if (!hostname_parts[i])
        {
          /* number of dot separated entries is not the same in the hostname and the pattern spec */
          goto exit;
        }
      if (!g_pattern_match_simple(pattern_parts[i], hostname_parts[i]))
        goto exit;
    }
  if (!hostname_parts[i])       /* if hostname_parts doesn't continue beyond pattern_parts */
    success = TRUE;
 exit:
  g_strfreev(pattern_parts);
  g_strfreev(hostname_parts);
  if (!success)
    {
      z_proxy_log(s, CORE_VIOLATION, 2, "Certificate subject does not match; host='%s', pattern='%s'",
                  host_name, pattern);
    }
  return success;
}

gboolean
z_proxy_ssl_host_iface_check_name_method(ZProxyHostIface *s,
                                         const gchar *host_name,
                                         gchar *reason_buf, gsize reason_len)
{
  ZProxySslHostIface *self = Z_CAST(s, ZProxySslHostIface);
  gint ext_ndx;
  gboolean found = FALSE, result = FALSE;
  gchar pattern_buf[256];

  if (self->hostname_checked)
    return self->hostname_check_result;

  pattern_buf[0] = 0;
  ext_ndx = X509_get_ext_by_NID(self->server_cert, NID_subject_alt_name, -1);
  if (ext_ndx >= 0)
    {
      /* ok, there's a subjectAltName extension, check that */
      X509_EXTENSION *ext;
      STACK_OF(GENERAL_NAME) *alt_names;
      GENERAL_NAME *gen_name;

      ext = X509_get_ext(self->server_cert, ext_ndx);
      alt_names = X509V3_EXT_d2i(ext);
      if (alt_names)
        {
          gint num, i;

          num = sk_GENERAL_NAME_num(alt_names);

          for (i = 0; i < num; i++)
            {
              gen_name = sk_GENERAL_NAME_value(alt_names, i);
              if (gen_name->type == GEN_DNS)
                {
                  guchar *dnsname = ASN1_STRING_data(gen_name->d.dNSName);
                  guint dnsname_len = ASN1_STRING_length(gen_name->d.dNSName);

                  if (dnsname_len > sizeof(pattern_buf) - 1)
                    {
                      found = TRUE;
                      result = FALSE;
                      break;
                    }

                  memcpy(pattern_buf, dnsname, dnsname_len);
                  pattern_buf[dnsname_len] = 0;
                  /* we have found a DNS name as alternative subject name */
                  found = TRUE;
                  result = z_proxy_ssl_host_iface_check_wildcard(s->owner, host_name, pattern_buf);
                  break;
                }
              else if (gen_name->type == GEN_IPADD)
                {
                  z_inet_ntoa(pattern_buf, sizeof(pattern_buf), *(struct in_addr *) gen_name->d.iPAddress->data);

                  found = TRUE;
                  result = strcmp(host_name, pattern_buf) == 0;
                  break;
                }
            }
          sk_GENERAL_NAME_free(alt_names);
        }
    }

  if (!found)
    {
      /* hmm. there was no subjectAltName (this is deprecated, but still
       * widely used), look up the Subject, most specific CN */
      X509_NAME *name;

      name = X509_get_subject_name(self->server_cert);
      if (X509_NAME_get_text_by_NID(name, NID_commonName, pattern_buf, sizeof(pattern_buf)) != -1)
        {
          result = z_proxy_ssl_host_iface_check_wildcard(s->owner, host_name, pattern_buf);
        }
    }

  if (!result && reason_buf)
    {
      g_snprintf(reason_buf, reason_len, "Certificate does not belong to target host (certificate: %s, host %s)",
                 pattern_buf, host_name);
    }
  self->hostname_checked = TRUE;
  self->hostname_check_result = result;
  return result;

}

ZProxyIface *
z_proxy_ssl_host_iface_new(ZProxy *owner)
{
  ZProxySslHostIface *self;

  self = Z_CAST(z_proxy_iface_new(Z_CLASS(ZProxySslHostIface), owner), ZProxySslHostIface);
  self->server_cert = owner->ssl_opts.peer_cert[EP_SERVER];

  CRYPTO_add(&self->server_cert->references, 1, CRYPTO_LOCK_X509);
  return &self->super;
}

void
z_proxy_ssl_host_iface_free_method(ZObject *s)
{
  ZProxySslHostIface *self = Z_CAST(s, ZProxySslHostIface);

  X509_free(self->server_cert);
  z_object_free_method(s);
}

ZProxyHostIfaceFuncs z_proxy_ssl_host_iface_funcs =
{
  {
    Z_FUNCS_COUNT(ZProxyHostIface),
    z_proxy_ssl_host_iface_free_method,
  },
  .check_name = z_proxy_ssl_host_iface_check_name_method,
};

ZClass ZProxySslHostIface__class =
{
  Z_CLASS_HEADER,
  Z_CLASS(ZProxyHostIface),
  "ZProxySslHostIface",
  sizeof(ZProxySslHostIface),
  &z_proxy_ssl_host_iface_funcs.super,
};

