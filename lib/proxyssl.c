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
 * Author  : Panther
 *
 ***************************************************************************/

#include <zorp/zorp.h>
#include <zorp/proxy.h>
#include <zorp/pyx509.h>
#include <zorp/streamssl.h>
#include <zorp/pydict.h>
#include <zorp/pystruct.h>
#include <zorp/proxysslhostiface.h>
#include <zorp/proxygroup.h>
#include <zorp/source.h>
#include <zorp/error.h>

ZProxySSLHandshake *
z_proxy_ssl_handshake_new(ZProxy * proxy, ZStream *stream, gint side)
{
  ZProxySSLHandshake *self;

  g_assert(proxy != NULL);
  g_assert(stream != NULL);

  z_proxy_enter(proxy);

  self = g_new0(ZProxySSLHandshake, 1);
  z_refcount_set(&self->ref_cnt, 1);
  self->proxy = z_proxy_ref(proxy);
  self->stream = z_stream_ref(stream);
  self->side = side;
  self->session = NULL;
  self->timeout = NULL;

  z_proxy_return(proxy, self);
}

static void
z_proxy_ssl_handshake_destroy(ZProxySSLHandshake *self)
{
  ZProxy *p = self->proxy;

  z_proxy_enter(p);

  if (self->timeout)
    {
      g_source_destroy(self->timeout);
      g_source_unref(self->timeout);
    }

  if (self->session)
    z_ssl_session_unref(self->session);

  z_stream_unref(self->stream);
  g_free(self);

  z_proxy_leave(p);

  z_proxy_unref(p);
}

ZProxySSLHandshake *
z_proxy_ssl_handshake_ref(ZProxySSLHandshake *self)
{
  z_refcount_inc(&self->ref_cnt);
  return self;
}

gboolean
z_proxy_ssl_handshake_unref(ZProxySSLHandshake *self)
{
  if (self && z_refcount_dec(&self->ref_cnt))
    {
      z_proxy_ssl_handshake_destroy(self);
      return TRUE;
    }

  return FALSE;
}

static void
z_proxy_ssl_handshake_set_callback(ZProxySSLHandshake *self, ZProxySSLCallbackFunc cb,
                                   gpointer user_data, GDestroyNotify user_data_notify)
{
  self->completion_cb = cb;
  self->completion_user_data = user_data;
  self->completion_user_data_notify = user_data_notify;
}

static void
z_proxy_ssl_handshake_call_callback(ZProxySSLHandshake *self)
{
  if (self->completion_cb)
    (self->completion_cb)(self, self->completion_user_data);

  if (self->completion_user_data && self->completion_user_data_notify)
    (self->completion_user_data_notify)(self->completion_user_data);
}

static void
z_proxy_ssl_handshake_set_error(ZProxySSLHandshake *self, gint ssl_err)
{
  self->ssl_err = ssl_err;
  z_ssl_get_error_str(self->ssl_err_str, sizeof(self->ssl_err_str));
}

static gint
z_proxy_ssl_handshake_get_error(ZProxySSLHandshake *self)
{
  return self->ssl_err;
}

static const gchar *
z_proxy_ssl_handshake_get_error_str(ZProxySSLHandshake *self)
{
  return self->ssl_err_str;
}

/**
 * Set default values of SSL attributes.
 *
 * @param self          the proxy being initialized
 *
 * The function initializes all SSL related members of the proxy instance.
 */
void
z_proxy_ssl_config_defaults(ZProxy *self)
{
  int i;

  self->ssl_opts.handshake_timeout = 30000;
  self->ssl_opts.handshake_seq = PROXY_SSL_HS_CLIENT_SERVER;
  self->ssl_opts.permit_invalid_certificates = FALSE;
  self->ssl_opts.verify_type[EP_SERVER] = PROXY_SSL_VERIFY_REQUIRED_TRUSTED;
  self->ssl_opts.verify_type[EP_CLIENT] = PROXY_SSL_VERIFY_REQUIRED_TRUSTED;
  self->ssl_opts.verify_depth[EP_SERVER] = 4;
  self->ssl_opts.verify_depth[EP_CLIENT] = 4;

  for (i = 0; i < EP_MAX; i++)
    {
      self->ssl_opts.local_ca_list[i] = sk_X509_new_null();
      self->ssl_opts.local_crl_list[i] = sk_X509_CRL_new_null();
      self->ssl_opts.handshake_hash[i] = g_hash_table_new(g_str_hash, g_str_equal);
    }

  self->ssl_opts.server_peer_ca_list = sk_X509_NAME_new_null();
  self->ssl_opts.ssl_method[EP_CLIENT] = g_string_new("SSLv23");
  self->ssl_opts.ssl_method[EP_SERVER] = g_string_new("SSLv23");
  self->ssl_opts.ssl_cipher[EP_CLIENT] = g_string_new("ALL:!aNULL:@STRENGTH");
  self->ssl_opts.ssl_cipher[EP_SERVER] = g_string_new("ALL:!aNULL:@STRENGTH");
  self->ssl_opts.disable_proto_sslv2[EP_CLIENT] = self->ssl_opts.disable_proto_sslv2[EP_SERVER] = TRUE;
  self->ssl_opts.local_privkey_passphrase[EP_CLIENT] = g_string_new("");
  self->ssl_opts.local_privkey_passphrase[EP_SERVER] = g_string_new("");
  self->ssl_opts.server_check_subject = TRUE;

  self->ssl_opts.dict = z_policy_dict_new();

  z_python_lock();

  z_policy_dict_ref(self->ssl_opts.dict);
  self->ssl_opts.ssl_struct = z_policy_struct_new(self->ssl_opts.dict, Z_PST_SHARED);

  z_python_unlock();

  g_assert(self->ssl_opts.ssl_struct != NULL);

  z_policy_var_ref(self->ssl_opts.ssl_struct);
  z_policy_dict_register(self->dict, Z_VT_OBJECT, "ssl",
                         Z_VF_READ | Z_VF_CFG_READ | Z_VF_LITERAL | Z_VF_CONSUME,
                         self->ssl_opts.ssl_struct);
}

/**
 * Export SSL related attributes to Python.
 *
 * @param self          the proxy being initialized
 *
 * This function registers all exported SSL attributes with the Python
 * interpreter.
 */
void
z_proxy_ssl_register_vars(ZProxy *self)
{
  ZPolicyDict *dict = self->ssl_opts.dict;

  /* enable ssl */
  z_policy_dict_register(dict, Z_VT_INT, "client_connection_security", Z_VF_READ | Z_VF_CFG_RW,
                         &self->ssl_opts.security[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "server_connection_security", Z_VF_READ | Z_VF_CFG_RW,
                         &self->ssl_opts.security[EP_SERVER]);

  /* common members */
  z_policy_dict_register(dict, Z_VT_INT, "handshake_timeout", Z_VF_READ | Z_VF_CFG_RW,
                         &self->ssl_opts.handshake_timeout);
  z_policy_dict_register(dict, Z_VT_INT, "handshake_seq", Z_VF_READ | Z_VF_CFG_RW,
                         &self->ssl_opts.handshake_seq);
  z_policy_dict_register(dict, Z_VT_INT, "permit_invalid_certificates", Z_VF_RW | Z_VF_CFG_RW,
                         &self->ssl_opts.permit_invalid_certificates);

  /* client side */
  z_policy_dict_register(dict, Z_VT_HASH, "client_handshake", Z_VF_READ | Z_VF_CFG_READ | Z_VF_CONSUME,
                         self->ssl_opts.handshake_hash[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_verify_type", Z_VF_READ | Z_VF_CFG_WRITE,
                         &self->ssl_opts.verify_type[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_max_verify_depth", Z_VF_READ | Z_VF_CFG_RW,
                         &self->ssl_opts.verify_depth[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_ALIAS, "client_verify_depth", Z_VF_READ | Z_VF_CFG_RW,
                         "client_max_verify_depth");
  z_policy_dict_register(dict, Z_VT_CUSTOM, "client_local_privatekey", Z_VF_RW | Z_VF_CFG_RW,
                         &self->ssl_opts.local_privkey[EP_CLIENT],
                         z_py_ssl_privkey_get, z_py_ssl_privkey_set, z_py_ssl_privkey_free,
                         self, NULL,              /* user_data, user_data_free */
                         NULL,                    /* end of CUSTOM args */
                         NULL);
  z_policy_dict_register(dict, Z_VT_STRING, "client_local_privatekey_passphrase",
                         Z_VF_RW | Z_VF_CFG_RW | Z_VF_CONSUME,
                         self->ssl_opts.local_privkey_passphrase[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_CUSTOM, "client_local_certificate", Z_VF_RW | Z_VF_CFG_RW,
                         &self->ssl_opts.local_cert[EP_CLIENT],
                         z_py_ssl_certificate_get, z_py_ssl_certificate_set, z_py_ssl_certificate_free,
                         self, NULL,              /* user_data, user_data_free */
                         NULL,                    /* end of CUSTOM args */
                         NULL);
  z_policy_dict_register(dict, Z_VT_CUSTOM, "client_peer_certificate", Z_VF_READ | Z_VF_CFG_READ,
                         &self->ssl_opts.peer_cert[EP_CLIENT],
                         z_py_ssl_certificate_get, NULL, z_py_ssl_certificate_free,
                         self, NULL,              /* user_data, user_data_free */
                         NULL,                    /* end of CUSTOM args */
                         NULL);
  z_policy_dict_register(dict, Z_VT_CUSTOM, "client_local_ca_list", Z_VF_READ | Z_VF_CFG_READ,
                         &self->ssl_opts.local_ca_list[EP_CLIENT],
                         z_py_ssl_cert_list_get, NULL, z_py_ssl_cert_list_free,
                         self, NULL,              /* user_data, user_data_free */
                         NULL,                    /* end of CUSTOM args */
                         NULL);
  z_policy_dict_register(dict, Z_VT_CUSTOM, "client_local_crl_list", Z_VF_READ | Z_VF_CFG_READ,
                         &self->ssl_opts.local_crl_list[EP_CLIENT],
                         z_py_ssl_crl_list_get, NULL, z_py_ssl_crl_list_free,
                         self, NULL,              /* user_data, user_data_free */
                         NULL,                    /* end of CUSTOM args */
                         NULL);
  z_policy_dict_register(dict, Z_VT_STRING, "client_ssl_method",
                         Z_VF_READ | Z_VF_CFG_WRITE | Z_VF_CONSUME,
                         self->ssl_opts.ssl_method[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_disable_proto_sslv2", Z_VF_READ | Z_VF_CFG_WRITE,
                         &self->ssl_opts.disable_proto_sslv2[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_disable_proto_sslv3", Z_VF_READ | Z_VF_CFG_WRITE,
                         &self->ssl_opts.disable_proto_sslv3[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_INT, "client_disable_proto_tlsv1", Z_VF_READ | Z_VF_CFG_WRITE,
                         &self->ssl_opts.disable_proto_tlsv1[EP_CLIENT]);
  z_policy_dict_register(dict, Z_VT_STRING, "client_ssl_cipher",
                         Z_VF_READ | Z_VF_CFG_WRITE | Z_VF_CONSUME,
                         self->ssl_opts.ssl_cipher[EP_CLIENT]);

  /* server side */
  z_policy_dict_register(dict, Z_VT_HASH, "server_handshake", Z_VF_READ | Z_VF_CFG_READ | Z_VF_CONSUME,
                         self->ssl_opts.handshake_hash[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_verify_type", Z_VF_READ | Z_VF_CFG_WRITE,
                         &self->ssl_opts.verify_type[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_max_verify_depth", Z_VF_READ | Z_VF_CFG_RW,
                         &self->ssl_opts.verify_depth[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_ALIAS, "server_verify_depth", Z_VF_READ | Z_VF_CFG_RW,
                         "server_max_verify_depth");
  z_policy_dict_register(dict, Z_VT_CUSTOM, "server_local_privatekey", Z_VF_RW | Z_VF_CFG_RW,
                         &self->ssl_opts.local_privkey[EP_SERVER],
                         z_py_ssl_privkey_get, z_py_ssl_privkey_set, z_py_ssl_privkey_free,
                         self, NULL,              /* user_data, user_data_free */
                         NULL,                    /* end of CUSTOM args */
                         NULL);
  z_policy_dict_register(dict, Z_VT_STRING, "server_local_privatekey_passphrase",
                         Z_VF_RW | Z_VF_CFG_RW | Z_VF_CONSUME,
                         self->ssl_opts.local_privkey_passphrase[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_CUSTOM, "server_local_certificate", Z_VF_RW | Z_VF_CFG_RW,
                         &self->ssl_opts.local_cert[EP_SERVER],
                         z_py_ssl_certificate_get, z_py_ssl_certificate_set, z_py_ssl_certificate_free,
                         self, NULL,              /* user_data, user_data_free */
                         NULL,                    /* end of CUSTOM args */
                         NULL);
  z_policy_dict_register(dict, Z_VT_CUSTOM, "server_peer_certificate", Z_VF_READ | Z_VF_CFG_READ,
                         &self->ssl_opts.peer_cert[EP_SERVER],
                         z_py_ssl_certificate_get, NULL, z_py_ssl_certificate_free,
                         self, NULL,              /* user_data, user_data_free */
                         NULL,                    /* end of CUSTOM args */
                         NULL);
  z_policy_dict_register(dict, Z_VT_CUSTOM, "server_local_ca_list", Z_VF_READ | Z_VF_CFG_READ,
                         &self->ssl_opts.local_ca_list[EP_SERVER],
                         z_py_ssl_cert_list_get, NULL, z_py_ssl_cert_list_free,
                         self, NULL,              /* user_data, user_data_free */
                         NULL,                    /* end of CUSTOM args */
                         NULL);
  z_policy_dict_register(dict, Z_VT_CUSTOM, "server_peer_ca_list", Z_VF_READ | Z_VF_CFG_READ,
                         &self->ssl_opts.server_peer_ca_list,
                         z_py_ssl_cert_name_list_get, NULL, z_py_ssl_cert_name_list_free,
                         self, NULL,              /* user_data, user_data_free */
                         NULL,                    /* end of CUSTOM args */
                         NULL);
  z_policy_dict_register(dict, Z_VT_CUSTOM, "server_local_crl_list", Z_VF_READ | Z_VF_CFG_READ,
                         &self->ssl_opts.local_crl_list[EP_SERVER],
                         z_py_ssl_crl_list_get, NULL, z_py_ssl_crl_list_free,
                         self, NULL,              /* user_data, user_data_free */
                         NULL,                    /* end of CUSTOM args */
                         NULL);
  z_policy_dict_register(dict, Z_VT_STRING, "server_ssl_method",
                         Z_VF_READ | Z_VF_CFG_WRITE | Z_VF_CONSUME,
                         self->ssl_opts.ssl_method[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_disable_proto_sslv2", Z_VF_READ | Z_VF_CFG_WRITE,
                         &self->ssl_opts.disable_proto_sslv2[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_disable_proto_sslv3", Z_VF_READ | Z_VF_CFG_WRITE,
                         &self->ssl_opts.disable_proto_sslv3[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_disable_proto_tlsv1", Z_VF_READ | Z_VF_CFG_WRITE,
                         &self->ssl_opts.disable_proto_tlsv1[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_STRING, "server_ssl_cipher",
                         Z_VF_READ | Z_VF_CFG_WRITE | Z_VF_CONSUME,
                         self->ssl_opts.ssl_cipher[EP_SERVER]);
  z_policy_dict_register(dict, Z_VT_INT, "server_check_subject", Z_VF_READ | Z_VF_CFG_WRITE,
                         &self->ssl_opts.server_check_subject);
}

/**
 * Free SSL related attributes of the Proxy instance.
 *
 * @param self          the proxy instance being destroyed
 *
 * Drop all references to other objects, this is being called when the proxy is
 * being shut down.
 */
void
z_proxy_ssl_free_vars(ZProxy *self)
{
  gint ep;

  z_enter();

  g_assert(self->ssl_opts.dict != NULL);
  g_assert(self->ssl_opts.ssl_struct != NULL);

  z_policy_var_unref(self->ssl_opts.ssl_struct);
  self->ssl_opts.ssl_struct = NULL;

  z_policy_dict_unref(self->ssl_opts.dict);
  self->ssl_opts.dict = NULL;

  for (ep = EP_CLIENT; ep < EP_MAX; ep++)
    {
      if (self->ssl_opts.ssl_sessions[ep])
        {
          z_ssl_session_unref(self->ssl_opts.ssl_sessions[ep]);
          self->ssl_opts.ssl_sessions[ep] = NULL;
        }
    }

  z_leave();
}

/**
 * Register SSL host interface if necessary.
 *
 * @param self          the proxy instance for which the SSL host interface is to be registered
 *
 * This functions checks the policy settings and registers the SSL host
 * interface used for certificate subject verification if necessary.
 */
static void
z_proxy_ssl_register_host_iface(ZProxy *self)
{
  z_proxy_enter(self);

  if (self->ssl_opts.security[EP_SERVER] > PROXY_SSL_SEC_NONE
      && self->ssl_opts.ssl_sessions[EP_SERVER]
      && self->ssl_opts.server_check_subject
      && (self->ssl_opts.verify_type[EP_SERVER] == PROXY_SSL_VERIFY_OPTIONAL_TRUSTED
          || self->ssl_opts.verify_type[EP_SERVER] == PROXY_SSL_VERIFY_REQUIRED_TRUSTED))
    {
      ZProxyIface *iface;

      iface = z_proxy_ssl_host_iface_new(self);
      z_proxy_add_iface(self, iface);
      z_object_unref(&iface->super);
    }

  z_proxy_leave(self);
}

/**
 * Check if an SSL policy callback function exists.
 *
 * @param self          the proxy instance
 * @param ndx           the side we're doing the SSL handshake on
 * @param name          name of the callback
 *
 * This function checks if an SSL callback function exists with the given name.
 *
 * @return TRUE if a callback called "name" exists, FALSE otherwise
 */
static inline gboolean
z_proxy_ssl_callback_exists(ZProxy *self, gint ndx, gchar *name)
{
  return !!g_hash_table_lookup(self->ssl_opts.handshake_hash[ndx], name);
}

/**
 * Call an SSL policy callback function.
 *
 * @param self          the proxy instance
 * @param ndx           the side we're doing the SSL handshake on
 * @param name          name of the callback
 * @param args          arguments to be passed to the callback
 * @param[out] retval   the return value of the callback
 *
 * This function evaluates the policy settings for the named callback.
 * In case a Python callback function is configured in the policy,
 * it calls the function with the arguments passed in args.
 *
 * @return TRUE if evaluating the policy settings was successful, FALSE otherwise
 */
static gboolean
z_proxy_ssl_callback(ZProxy *self, gint ndx, gchar *name, ZPolicyObj *args, guint *retval)
{
  ZPolicyObj *tuple, *cb, *res;
  gboolean rc = FALSE;
  guint type;

  z_proxy_enter(self);
  tuple = g_hash_table_lookup(self->ssl_opts.handshake_hash[ndx], name);
  if (!tuple)
    {
      *retval = PROXY_SSL_HS_ACCEPT;
      z_policy_var_unref(args);
      z_proxy_return(self, TRUE);
    }
  if (!z_policy_var_parse(tuple, "(iO)", &type, &cb))
    {
      z_policy_var_unref(args);
      z_proxy_log(self, CORE_POLICY, 1, "Handshake hash item is not a tuple of (int, func);");
      z_proxy_return(self, FALSE);
    }
  if (type != PROXY_SSL_HS_POLICY)
    {
      z_policy_var_unref(args);
      z_proxy_log(self, CORE_POLICY, 1,
                  "Invalid handshake hash item, only PROXY_SSL_HS_POLICY is supported; type='%d'", type);
      z_proxy_return(self, FALSE);
    }

  /* NOTE: z_policy_call_object consumes args */
  res = z_policy_call_object(cb, args, self->session_id);
  if (res)
    {
      if (!z_policy_var_parse(res, "i", retval))
        z_proxy_log(self, CORE_POLICY, 1, "Handshake callback returned non-int;");
      else
        rc = TRUE;
    }
  z_policy_var_unref(res);
  z_proxy_return(self, rc);
}

static gboolean
z_proxy_ssl_load_local_key(ZProxySSLHandshake *handshake)
{
  ZProxy *self = handshake->proxy;
  guint ndx = handshake->side;
  ZSSLSession *session = handshake->session;
  SSL *ssl;
  guint policy_type;

  z_proxy_enter(self);
  ssl = session->ssl;

  z_policy_lock(self->thread);
  if (!z_proxy_ssl_callback(self, ndx, "setup_key", z_policy_var_build("(i)", ndx), &policy_type) ||
      policy_type != PROXY_SSL_HS_ACCEPT)
    {
      z_policy_unlock(self->thread);
      z_proxy_log(self, CORE_POLICY, 1, "Error fetching local key/certificate pair; side='%s'", EP_STR(ndx));
      z_proxy_return(self, FALSE);
    }
  z_policy_unlock(self->thread);

  if (self->ssl_opts.local_privkey[ndx] && self->ssl_opts.local_cert[ndx])
    {
      SSL_use_PrivateKey(ssl, self->ssl_opts.local_privkey[ndx]);
      SSL_use_certificate(ssl, self->ssl_opts.local_cert[ndx]);
    }
  else if (ndx == EP_CLIENT)
    {
      z_proxy_log(self, CORE_ERROR, 3,
                  "No local key is set for the client side, either missing keys "
                  "or misconfigured keybridge, the SSL handshake will probably fail.");
    }
  z_proxy_return(self, TRUE);
}

static gboolean
z_proxy_ssl_load_local_ca_list(ZProxySSLHandshake *handshake)
{
  ZProxy *self = handshake->proxy;
  guint ndx = handshake->side;
  ZSSLSession *session = handshake->session;
  int i, n;
  X509_STORE *ctx;
  guint policy_type;

  z_proxy_enter(self);

  z_policy_lock(self->thread);

  if (!z_proxy_ssl_callback(self, ndx, "setup_ca_list", z_policy_var_build("(i)", ndx), &policy_type) ||
      policy_type != PROXY_SSL_HS_ACCEPT)
    {
      z_policy_unlock(self->thread);
      z_proxy_log(self, CORE_POLICY, 1, "Error fetching local trusted CA list; side='%s'", EP_STR(ndx));
      z_proxy_return(self, FALSE);
    }
  z_policy_unlock(self->thread);

  if (ndx == EP_CLIENT)
    {
      STACK_OF(X509_NAME) *sk;

      sk = sk_X509_NAME_new_null();
      if (!sk)
        z_proxy_return(self, FALSE);

      n = sk_X509_NAME_num(self->ssl_opts.local_ca_list[ndx]);
      for (i = 0; i < n; i++)
        sk_X509_NAME_push(sk, X509_NAME_dup(X509_get_subject_name(sk_X509_value(self->ssl_opts.local_ca_list[ndx],
                                                                                i))));
      SSL_set_client_CA_list(session->ssl, sk);
    }

  ctx = session->ssl->ctx->cert_store;
  n = sk_X509_num(self->ssl_opts.local_ca_list[ndx]);
  for (i = 0; i < n; i++)
    X509_STORE_add_cert(ctx, sk_X509_value(self->ssl_opts.local_ca_list[ndx], i));
  z_proxy_return(self, TRUE);
}

static gboolean
z_proxy_ssl_load_local_crl_list(ZProxySSLHandshake *handshake, gchar *name)
{
  guint ndx = handshake->side;
  ZSSLSession *session = handshake->session;
  ZProxy *self = handshake->proxy;
  X509_STORE *ctx = session->ssl->ctx->cert_store;
  guint policy_type;
  int i;

  z_proxy_enter(self);
  z_policy_lock(self->thread);
  if (!z_proxy_ssl_callback(self, ndx, "setup_crl_list", z_policy_var_build("(si)", name, ndx), &policy_type) ||
      policy_type != PROXY_SSL_HS_ACCEPT)
    {
      z_policy_unlock(self->thread);
      z_proxy_log(self, CORE_POLICY, 1, "Error fetching CRL list for CA; side='%s', ca='%s'", EP_STR(ndx), name);
      z_proxy_return(self, FALSE);
    }
  z_policy_unlock(self->thread);

  for (i = 0; i < sk_X509_CRL_num(self->ssl_opts.local_crl_list[ndx]); i++)
    {
      X509_CRL *crl;
      char buf[512];

      crl = sk_X509_CRL_value(self->ssl_opts.local_crl_list[ndx], i);
      X509_NAME_oneline(X509_CRL_get_issuer(crl), buf, sizeof(buf));
      if (strcmp(buf, name) == 0)
        X509_STORE_add_crl(ctx, crl);
    }
  z_proxy_return(self, TRUE);
}

/* this function is called to verify the whole chain as provided by
   the peer. The SSL lib takes care about setting up the context,
   we only need to call X509_verify_cert. */
static int
z_proxy_ssl_app_verify_cb(X509_STORE_CTX *ctx, void *user_data)
{
  ZProxySSLHandshake *handshake = (ZProxySSLHandshake *) user_data;
  ZProxy *self = handshake->proxy;
  gint side = handshake->side;

  gboolean new_verify_callback, success;
  guint verdict;
  gboolean ok, verify_valid;
  gint verify_error, verify_type;

  z_proxy_enter(self);
  /* publish the peer's certificate to python, and fetch the calist
     required to verify the certificate */

  if (self->ssl_opts.peer_cert[side])
    X509_free(self->ssl_opts.peer_cert[side]);

  self->ssl_opts.peer_cert[side] = ctx->cert;
  CRYPTO_add(&ctx->cert->references, 1, CRYPTO_LOCK_X509);

  verify_type = self->ssl_opts.verify_type[side];
  new_verify_callback = z_proxy_ssl_callback_exists(self, side, "verify_cert_ext");
  if (side == EP_SERVER)
    z_proxy_ssl_load_local_ca_list(handshake);

  verify_valid = X509_verify_cert(ctx);
  verify_error = X509_STORE_CTX_get_error(ctx);
  z_policy_lock(self->thread);
  if (new_verify_callback)
    success = z_proxy_ssl_callback(self, side, "verify_cert_ext",
                                   z_policy_var_build("(i(ii))", side, verify_valid, verify_error), &verdict);
  else
    success = z_proxy_ssl_callback(self, side, "verify_cert", z_policy_var_build("(i)", side), &verdict);

  if (!success)
    {
      z_policy_unlock(self->thread);
      z_proxy_return(self, FALSE);
    }
  z_policy_unlock(self->thread);

  if (verdict == PROXY_SSL_HS_ACCEPT)
    {
      if (verify_type == PROXY_SSL_VERIFY_REQUIRED_TRUSTED ||
          verify_type == PROXY_SSL_VERIFY_OPTIONAL_TRUSTED)
        {
          ok = verify_valid;
        }
      else if (verify_type == PROXY_SSL_VERIFY_REQUIRED_UNTRUSTED ||
               verify_type == PROXY_SSL_VERIFY_OPTIONAL_UNTRUSTED)
        {
          if (!verify_valid &&
              (self->ssl_opts.permit_invalid_certificates ||
               (verify_error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
                verify_error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
                verify_error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
                verify_error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ||
                verify_error == X509_V_ERR_CERT_UNTRUSTED ||
                verify_error == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)))
            {
              z_proxy_log(self, CORE_POLICY, 3,
                          "Accepting untrusted certificate as directed by the policy; verify_error='%s'",
                          X509_verify_cert_error_string(verify_error));
              ok = 1;
            }
          else
            {
              ok = verify_valid;
            }
        }
      else
        {
          ok = 1;
        }
    }
  else if (verdict == PROXY_SSL_HS_VERIFIED)
    {
      if (!verify_valid)
        z_proxy_log(self, CORE_POLICY, 3,
                    "Accepting untrusted certificate as directed by the policy; verify_error='%s'",
                    X509_verify_cert_error_string(verify_error));
      ok = 1;
    }
  else
    {
      ok = 0;
    }

  z_proxy_return(self, ok);
}

/* verify callback of the X509_STORE we set up when verifying
   the peer's certificate. We are checking the CRLs here */
static int
z_proxy_ssl_verify_peer_cert_cb(int ok, X509_STORE_CTX *ctx)
{
  SSL *ssl = (SSL *) X509_STORE_CTX_get_app_data(ctx);
  ZProxySSLHandshake *handshake = (ZProxySSLHandshake *) SSL_get_app_data(ssl);
  ZProxy *self = handshake->proxy;
  gint side = handshake->side;
  X509_OBJECT obj;
  X509_CRL *crl;
  X509_NAME *subject, *issuer;
  int rc;
  char subject_name[512], issuer_name[512];
  int depth;

  z_proxy_enter(self);
  /* if self->current_cert is a CA certificate, it should have
     a CRL list referenced by its "subject". We check the validity of
     the CRL when the CA certificate is verified.

     if self->current_cert is either a subordinate CA or a simple X509
     certificate, we must check whether the issuer's CRL has revoked
     our cert. As openssl calls us in the chain order, verification
     of the CRL had already been performed at this time.
  */
  depth = X509_STORE_CTX_get_error_depth(ctx);
  subject = X509_get_subject_name(ctx->current_cert);
  X509_NAME_oneline(subject, subject_name, sizeof(subject_name));
  issuer = X509_get_issuer_name(ctx->current_cert);
  X509_NAME_oneline(issuer, issuer_name, sizeof(issuer_name));

  if (!ok)
    z_proxy_log(self, CORE_POLICY, 1, "Certificate verification failed; error='%s'",
                X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));

  z_proxy_log(self, CORE_DEBUG, 6, "Verifying certificate; issuer='%s', subject='%s'", issuer_name, subject_name);

  if (self->ssl_opts.verify_depth[side] < depth)
    {
      ok = 0;
      z_proxy_log(self, CORE_POLICY, 1, "Certificate verification failed; error='%s', "
                  "side='%s', max_depth='%d', depth='%d'",
                  X509_verify_cert_error_string(X509_V_ERR_CERT_CHAIN_TOO_LONG),
                  EP_STR(side), self->ssl_opts.verify_depth[side], depth);
    }

  z_proxy_ssl_load_local_crl_list(handshake, subject_name);
  rc = X509_STORE_get_by_subject(ctx, X509_LU_CRL, subject, &obj);
  if (rc == 1 && obj.type == X509_LU_CRL)
    {
      EVP_PKEY *pkey;

      /* we are checking a CA certificate, and it has an associated CRL */
      crl = obj.data.crl;
      z_proxy_log(self, CORE_DEBUG, 6, "Verifying CRL integrity; issuer='%s'", subject_name);
      pkey = X509_get_pubkey(ctx->current_cert);
      if (X509_CRL_verify(crl, pkey) <= 0)
        {
          EVP_PKEY_free(pkey);
          X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_SIGNATURE_FAILURE);
          z_proxy_log(self, CORE_ERROR, 1, "Invalid signature on CRL; issuer='%s'", issuer_name);
          goto error_free;
        }
      EVP_PKEY_free(pkey);
      rc = X509_cmp_current_time(X509_CRL_get_nextUpdate(crl));
      if (rc == 0)
        {
          /*LOG
            This message indicates an invalid Certificate Revocation List (CRL),
            because it has an invalid nextUpdate field.
           */
          z_proxy_log(self, CORE_ERROR, 1, "CRL has invalid nextUpdate field; issuer='%s'", subject_name);
          X509_STORE_CTX_set_error(ctx, X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
          goto error_free;
        }

      if (rc <= 0)
        {
          /*LOG
            This message indicates an invalid Certificate Revocation List (CRL),
            because it is expired.
           */
          z_proxy_log(self, CORE_ERROR, 1, "CRL is expired; issuer='%s'", subject_name);
          X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_HAS_EXPIRED);
          goto error_free;
        }
      X509_OBJECT_free_contents(&obj);
    }

  /* verify whether the issuer has revoked this certificate */
  rc = X509_STORE_get_by_subject(ctx, X509_LU_CRL, issuer, &obj);

  if (rc == 1 && obj.type == X509_LU_CRL)
    {
      STACK_OF(X509_REVOKED) *revoked_list;
      X509_REVOKED *revoked;
      ASN1_INTEGER *cert_serial;
      int n, i;

      cert_serial = X509_get_serialNumber(ctx->current_cert);
      z_proxy_log(self, CORE_DEBUG, 6,
                  "Verifying certificate against CRL; cert='%s', serial='%ld', issuer='%s'",
                  subject_name, ASN1_INTEGER_get(cert_serial), issuer_name);

      crl = obj.data.crl;
      revoked_list = X509_CRL_get_REVOKED(crl);
      n = sk_X509_REVOKED_num(revoked_list);
      for (i = 0; i < n; i++)
        {
          revoked = sk_X509_REVOKED_value(revoked_list, i);
          if (ASN1_INTEGER_cmp(revoked->serialNumber, cert_serial) == 0)
            {
              BIO *bio;
              char serial_str[128];
              char *ptr;

              X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
              bio = BIO_new(BIO_s_mem());
              if (bio)
                {
                  unsigned long len;
                  i2a_ASN1_INTEGER(bio, revoked->serialNumber);

                  len = BIO_get_mem_data(bio, &ptr);
                  len = MIN(len, sizeof(serial_str) - 1);

                  memcpy(serial_str, ptr, len);
                  serial_str[len] = 0;

                  z_proxy_log(self, CORE_ERROR, 1, "Certificate revoked by CRL; issuer='%s', serial='%s'",
                              issuer_name, serial_str);

                  BIO_free_all(bio);
                }
              goto error_free;
            }
        }
      X509_OBJECT_free_contents(&obj);
    }
  z_proxy_return(self, ok);

 error_free:
  X509_OBJECT_free_contents(&obj);
  z_proxy_return(self, 0);
}

static int
z_proxy_ssl_client_cert_cb(SSL *ssl, X509 **cert, EVP_PKEY **pkey)
{
  ZProxySSLHandshake *handshake = (ZProxySSLHandshake *) SSL_get_app_data(ssl);
  ZProxy *self = handshake->proxy;;
  gint side = handshake->side;
  gint res;

  z_proxy_enter(self);
  /* publish peer's idea of its trusted certificate authorities */
  if (ssl->s3 && ssl->s3->tmp.ca_names)
    {
      int i, n;

      n = sk_X509_NAME_num(ssl->s3->tmp.ca_names);
      for (i = 0; i < n; i++)
        {
          X509_NAME *v;

          v = sk_X509_NAME_value(ssl->s3->tmp.ca_names, i);
          sk_X509_NAME_push(self->ssl_opts.server_peer_ca_list, X509_NAME_dup(v));
        }
    }

  if (!z_proxy_ssl_load_local_key(handshake))
    z_proxy_return(self, 0);

  if (self->ssl_opts.local_cert[side] && self->ssl_opts.local_privkey[side])
    {
      *cert = self->ssl_opts.local_cert[side];
      *pkey = self->ssl_opts.local_privkey[side];

      CRYPTO_add(&(*cert)->references, 1, CRYPTO_LOCK_X509);
      CRYPTO_add(&(*pkey)->references, 1, CRYPTO_LOCK_EVP_PKEY);
      res = 1;
    }
  else
    {
      *cert = NULL;
      *pkey = NULL;
      res = 0;
    }
  z_proxy_return(self, res);
}

static gboolean
z_proxy_ssl_handshake_timeout(gpointer user_data)
{
  ZProxySSLHandshake *handshake = (ZProxySSLHandshake *) user_data;

  z_proxy_enter(handshake->proxy);

  z_proxy_log(handshake->proxy, CORE_ERROR, 1, "SSL handshake timed out; side='%s'",
              EP_STR(handshake->side));
  z_proxy_ssl_handshake_set_error(handshake, SSL_ERROR_ZERO_RETURN);

  /* call completion callback */
  z_proxy_leave(handshake->proxy);

  z_proxy_ssl_handshake_call_callback(handshake);

  return FALSE;
}

/**
 * Callback function set up as read and write callback on the stream we are doing
 * the SSL handshake on.
 *
 * @param stream        the stream instance
 * @param poll_cond     the condition that caused this callback to be called
 * @param s             user data used by the callback (the handshake object in our case)
 *
 * This function is used to repeatedly call either SSL_accept() or SSL_connect() until
 * OpenSSL reports that the handshake is either finished or failed.
 *
 * The function sets the G_IO_IN / G_IO_OUT conditions of the underlying stream to
 * comply with the requests of OpenSSL.
 *
 * Upon termination of the handshake the callback function set in the handshake object
 * is called with the handshake structure and the user data pointer passed as arguments.
 * This callback function can be used to signal the called that the handshake has been
 * finished.
 *
 * Upon exiting, the 'ssl_err' member of the handshake object is set to zero on successful
 * handshake, otherwise it contains the OpenSSL error code, and the string representation
 * of the error is in 'ssl_err_str'. Use z_proxy_ssl_handshake_get_error() and
 * z_proxy_ssl_handshake_get_error_str() to query the error code / description.
 *
 * @return TRUE if needs to be called again
 */
static gboolean
z_proxy_ssl_handshake_cb(ZStream *stream, GIOCondition poll_cond G_GNUC_UNUSED, gpointer s)
{
  ZProxySSLHandshake *handshake = (ZProxySSLHandshake *) s;
  X509 *peercert = NULL;
  gint result;

  z_proxy_enter(handshake->proxy);

  if (handshake->side == EP_CLIENT)
    result = SSL_accept(handshake->session->ssl);
  else
    result = SSL_connect(handshake->session->ssl);

  if (result <= 0)
    {
      gint ssl_err = SSL_get_error(handshake->session->ssl, result);

      switch (ssl_err)
        {
        case SSL_ERROR_WANT_READ:
          z_stream_set_cond(stream, G_IO_IN, TRUE);
          z_stream_set_cond(stream, G_IO_OUT, FALSE);
          break;

        case SSL_ERROR_WANT_WRITE:
          z_stream_set_cond(stream, G_IO_IN, FALSE);
          z_stream_set_cond(stream, G_IO_OUT, TRUE);
          break;

        case SSL_ERROR_SYSCALL:
          if (z_errno_is(EAGAIN) || z_errno_is(EINTR))
            break;

          if (z_errno_is(0))
            {
              z_proxy_ssl_handshake_set_error(handshake, ssl_err);
              z_proxy_log(handshake->proxy, CORE_ERROR, 1, "SSL handshake failed, EOF received; side='%s'",
                          EP_STR(handshake->side));
              goto done;
            }
          /* no break here: we let the code go to the next case so that the error gets logged */

        default:
          /* SSL handshake failed */
          z_proxy_ssl_handshake_set_error(handshake, ssl_err);
          z_proxy_log(handshake->proxy, CORE_ERROR, 1, "SSL handshake failed; side='%s', error='%s'",
                      EP_STR(handshake->side), z_proxy_ssl_handshake_get_error_str(handshake));
          goto done;
        }

      z_proxy_return(handshake->proxy, TRUE);
    }

  /* handshake completed */
  z_proxy_ssl_handshake_set_error(handshake, 0);

  /* print peer certificate info */
  peercert = SSL_get_peer_certificate(handshake->session->ssl);
  if (peercert && z_log_enabled(CORE_DEBUG, 4))
    {
      gchar name[1024];
      gchar issuer[1024];
      BIO *bio;
      char serial_str[128];
      char *ptr;
      long version = X509_get_version(peercert);

      bio = BIO_new(BIO_s_mem());

      if (bio)
        {
          unsigned long len;
          i2a_ASN1_INTEGER(bio, X509_get_serialNumber(peercert));

          len = BIO_get_mem_data(bio, &ptr);
          len = MIN(len, sizeof(serial_str) - 1);

          memcpy(serial_str, ptr, len);
          serial_str[len] = 0;

          X509_NAME_oneline(X509_get_subject_name(peercert), name, sizeof(name) - 1);
          X509_NAME_oneline(X509_get_issuer_name(peercert), issuer, sizeof(issuer) - 1);

          z_proxy_log(handshake->proxy, CORE_DEBUG, 4, "Identified peer; side='%s', peer='%s', "
                      "issuer='%s', serial='%s', version='%lu'",
                      EP_STR(handshake->side), name, issuer, serial_str, version);
          BIO_free_all(bio);
        }
    }
  if (peercert)
    X509_free(peercert);

done:
  z_proxy_leave(handshake->proxy);
  z_proxy_ssl_handshake_call_callback(handshake);

  return TRUE;
}

static void
z_proxy_ssl_handshake_destroy_notify(gpointer data)
{
  ZProxySSLHandshake *self = (ZProxySSLHandshake *) data;

  z_proxy_ssl_handshake_unref(self);
}

/**
 * Save stream state and set up our callbacks driving the SSL handshake.
 *
 * @param handshake     the handshake object
 * @param proxy_group   the proxy group whose poll will drive the handshake
 *
 * This function saves the stream state into the handshake object, and then sets up
 * the stream callbacks and conditions to our callbacks that will call SSL_accept() /
 * SSL_connect() while the operation has been completed.
 *
 * Depending on which side we're setting up the handshake, either G_IO_IN or G_IO_OUT is
 * set initially.
 *
 * @return TRUE if setting up the stream was successful
 */
static gboolean
z_proxy_ssl_setup_stream(ZProxySSLHandshake *handshake,
                         ZProxyGroup *proxy_group)
{
  z_proxy_enter(handshake->proxy);

  /* save stream callback state */
  if (!z_stream_save_context(handshake->stream, &handshake->stream_context))
    {
      z_proxy_log(handshake->proxy, CORE_ERROR, 3, "Failed to save stream context;");
      z_proxy_return(handshake->proxy, FALSE);
    }

  /* set up our own callbacks doing the handshake */
  z_stream_set_callback(handshake->stream, G_IO_IN, z_proxy_ssl_handshake_cb,
                        z_proxy_ssl_handshake_ref(handshake), z_proxy_ssl_handshake_destroy_notify);
  z_stream_set_callback(handshake->stream, G_IO_OUT, z_proxy_ssl_handshake_cb,
                        z_proxy_ssl_handshake_ref(handshake), z_proxy_ssl_handshake_destroy_notify);

  z_stream_set_nonblock(handshake->stream, TRUE);

  /* set up our timeout source */
  handshake->timeout = z_timeout_source_new(handshake->proxy->ssl_opts.handshake_timeout);
  g_source_set_callback(handshake->timeout, z_proxy_ssl_handshake_timeout,
                        z_proxy_ssl_handshake_ref(handshake), z_proxy_ssl_handshake_destroy_notify);
  g_source_attach(handshake->timeout, z_proxy_group_get_context(proxy_group));

  /* attach stream to the poll of the proxy group */
  z_stream_attach_source(handshake->stream, z_proxy_group_get_context(proxy_group));

  z_stream_set_cond(handshake->stream, G_IO_PRI, FALSE);
  z_stream_set_cond(handshake->stream, G_IO_IN, (handshake->side == EP_CLIENT));
  z_stream_set_cond(handshake->stream, G_IO_OUT, (handshake->side == EP_SERVER));

  z_proxy_return(handshake->proxy, TRUE);
}

/**
 * Restore stream state to the pre-handshake values.
 *
 * @param handshake     the handshake object
 *
 * This function re-sets the stream state to the pre-handshake state saved by
 * z_proxy_ssl_setup_stream().
 *
 * @return TRUE if restoring up the stream was successful
 */
static gboolean
z_proxy_ssl_restore_stream(ZProxySSLHandshake *handshake)
{
  gboolean res = TRUE;

  z_proxy_enter(handshake->proxy);

  if (handshake->timeout)
    {
      g_source_destroy(handshake->timeout);
      g_source_unref(handshake->timeout);
      handshake->timeout = NULL;
    }

  z_stream_detach_source(handshake->stream);

  if (!z_stream_restore_context(handshake->stream, &handshake->stream_context))
    {
      z_proxy_log(handshake->proxy, CORE_ERROR, 3, "Failed to restore stream context;");
      res = FALSE;
    }

  z_proxy_return(handshake->proxy, res);
}

/**
 * Completion callback used for our semi-nonblocking handshake.
 *
 * @param handshake     the handshake object
 * @param user_data     the gboolean which has to be set
 *
 * This function is used as a completion callback by z_proxy_ssl_do_handshake() if it's
 * doing a semi-nonblocking handshake, where it avoids starvation of other proxies running
 * in the same proxy group by iterating the main loop of the proxy group and waiting
 * for the handshake to be finished.
 *
 * The callback is passed a pointer to a gboolean: z_proxy_ssl_do_handshake() iterates
 * the main loop until the boolean is set by the callback, signaling that the handshake
 * has been finished.
 */
static void
z_proxy_ssl_handshake_completed(ZProxySSLHandshake *handshake G_GNUC_UNUSED,
                                gpointer user_data)
{
  z_enter();

  *((gboolean *) user_data) = TRUE;

  z_leave();
}

/**
 * Do an SSL handshake with blocking semantics.
 *
 * @param handshake     the handshake object
 * @param nonblocking   whether or not to do a semi-nonblocking handshake
 *
 * This function initiates an SSL handshake and waits for it to be finished. The handshake
 * is either done in a true blocking manner, where the underlying stream is blocking, or
 * in a semi-nonblocking one, where the underlying stream is nonblocking but we iterate
 * the proxy group main loop until the handshake is finished.
 *
 * @return TRUE if the handshake was successful, FALSE otherwise
 */
static gboolean
z_proxy_ssl_do_handshake(ZProxySSLHandshake *handshake,
                         gboolean nonblocking)
{
  z_proxy_enter(handshake->proxy);

  if (nonblocking)
    {
      ZProxyGroup *proxy_group = z_proxy_get_group(handshake->proxy);
      gboolean handshake_done = FALSE;

      z_proxy_ssl_handshake_set_callback(handshake, z_proxy_ssl_handshake_completed, &handshake_done, NULL);

      if (!z_proxy_ssl_setup_stream(handshake, proxy_group))
        z_proxy_return(handshake->proxy, FALSE);

      /* iterate until the handshake has been completed */
      while (!handshake_done && z_proxy_group_iteration(proxy_group))
        {
          ;
        }

      if (!z_proxy_ssl_restore_stream(handshake))
        z_proxy_return(handshake->proxy, FALSE);
    }
  else
    {
      /* non-blocking handshake, call the callback directly: the underlying
       * stream (and thus the BIO) is in blocking mode, so SSL_accept()/SSL_connect()
       * is done
       */
      z_stream_set_timeout(handshake->stream, handshake->proxy->ssl_opts.handshake_timeout);
      z_proxy_ssl_handshake_cb(handshake->stream, 0, (gpointer) handshake);
      z_stream_set_timeout(handshake->stream, -2);
    }

  z_proxy_return(handshake->proxy, (z_proxy_ssl_handshake_get_error(handshake) == 0));
}

/**
 * Setup the various parameters (certs, keys, etc.) and callbacks used by the SSL handshake.
 *
 * @param handshake     the handshake object
 *
 * This function initiates the SSL session that is used by the handshake. It sets up basic
 * handshake parameters (like the SSL methods we support, cipher specs, etc.) and the
 * callback functions that will be used by OpenSSL to verify certificates.
 *
 * @return TRUE if setting up the parameters/callbacks has succeeded, FALSE otherwise
 */
static gboolean
z_proxy_ssl_setup_handshake(ZProxySSLHandshake *handshake)
{
  ZProxy *self = handshake->proxy;
  gint side = handshake->side;
  SSL_CTX *ctx;
  SSL *tmpssl;
  ZSSLSession *ssl;
  int verify_mode = 0;

  z_proxy_enter(self);

  z_proxy_log(self, CORE_DEBUG, 6, "Performing SSL handshake; side='%s'", EP_STR(side));

  if (strcmp(self->ssl_opts.ssl_method[side]->str, "SSLv23") == 0)
    {
      if (side == EP_CLIENT)
        ctx = SSL_CTX_new(SSLv23_server_method());
      else
        ctx = SSL_CTX_new(SSLv23_client_method());
    }
  else if (strcmp(self->ssl_opts.ssl_method[side]->str, "SSLv2") == 0)
    {
      if (side == EP_CLIENT)
        ctx = SSL_CTX_new(SSLv2_server_method());
      else
        ctx = SSL_CTX_new(SSLv2_client_method());
    }
  else if (strcmp(self->ssl_opts.ssl_method[side]->str, "SSLv3") == 0)
    {
      if (side == EP_CLIENT)
        ctx = SSL_CTX_new(SSLv3_server_method());
      else
        ctx = SSL_CTX_new(SSLv3_client_method());
    }
  else if (strcmp(self->ssl_opts.ssl_method[side]->str, "TLSv1") == 0)
    {
      if (side == EP_CLIENT)
        ctx = SSL_CTX_new(TLSv1_server_method());
      else
        ctx = SSL_CTX_new(TLSv1_client_method());
    }
  else
    {
      z_proxy_log(self, CORE_POLICY, 1, "Bad SSL method; method='%s', side='%s'",
                  self->ssl_opts.ssl_method[side]->str, EP_STR(side));
      z_proxy_return(self, FALSE);
    }

  if (!ctx)
    {
      z_proxy_log(self, CORE_ERROR, 1, "Error allocating SSL_CTX struct;");
      z_proxy_return(self, FALSE);
    }

  if (!SSL_CTX_set_cipher_list(ctx, self->ssl_opts.ssl_cipher[side]->str))
    {
      z_proxy_log(self, CORE_ERROR, 1, "Error setting cipher spec; ciphers='%s', side='%s'",
                  self->ssl_opts.ssl_cipher[side]->str, EP_STR(side));
      z_proxy_return(self, FALSE);
    }

  SSL_CTX_set_options(ctx, SSL_OP_ALL |
                      (self->ssl_opts.disable_proto_sslv2[side] ? SSL_OP_NO_SSLv2 : 0) |
                      (self->ssl_opts.disable_proto_sslv3[side] ? SSL_OP_NO_SSLv3 : 0) |
                      (self->ssl_opts.disable_proto_tlsv1[side] ? SSL_OP_NO_TLSv1 : 0));

  if (side == EP_SERVER)
    SSL_CTX_set_client_cert_cb(ctx, z_proxy_ssl_client_cert_cb); /* instead of specifying key here */

  /* For server side, the z_proxy_ssl_app_verify_callback_cb sets up
     trusted CA list. It calls verify_cert callback for both sides. */

  SSL_CTX_set_cert_verify_callback(ctx, z_proxy_ssl_app_verify_cb, handshake);

  if (self->ssl_opts.verify_type[side] == PROXY_SSL_VERIFY_REQUIRED_TRUSTED)
    verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  else if (self->ssl_opts.verify_type[side] == PROXY_SSL_VERIFY_REQUIRED_UNTRUSTED ||
           self->ssl_opts.verify_type[side] == PROXY_SSL_VERIFY_OPTIONAL_UNTRUSTED ||
           self->ssl_opts.verify_type[side] == PROXY_SSL_VERIFY_OPTIONAL_TRUSTED)
    verify_mode = SSL_VERIFY_PEER;

  if (verify_mode)
    SSL_CTX_set_verify(ctx, verify_mode, z_proxy_ssl_verify_peer_cert_cb);

  tmpssl = SSL_new(ctx);
  SSL_set_options(tmpssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_set_app_data(tmpssl, handshake);
  SSL_CTX_free(ctx);
  if (!tmpssl)
    {
      z_proxy_log(self, CORE_ERROR, 1, "Error allocating SSL struct; side='%s'", EP_STR(side));
      z_proxy_return(self, FALSE);
    }

  ssl = handshake->session = z_ssl_session_new_ssl(tmpssl);
  SSL_free(tmpssl);
  if (!ssl)
    {
      z_proxy_log(self, CORE_ERROR, 1, "Error creating SSL session; side='%s'", EP_STR(side));
      z_proxy_return(self, FALSE);
    }

  if (side == EP_CLIENT)
    {
      if (!z_proxy_ssl_load_local_key(handshake) ||
          !z_proxy_ssl_load_local_ca_list(handshake))
        z_proxy_return(self, FALSE);
    }

  z_stream_ssl_set_session(handshake->stream, ssl);

  z_proxy_return(self, TRUE);
}

/**
 * Perform an SSL handshake with blocking semantics.
 *
 * @param handshake     the handshake object
 *
 * This function sets up the handshake parameters and then does the SSL handshake. If
 * the proxy associated with the handshake has the ZPF_NONBLOCKING flag set, it does a
 * semi-nonblocking handshake to avoid starvation of other proxies running in the same
 * proxy group.
 *
 * @return TRUE if the handshake was successful, FALSE otherwise
 */
gboolean
z_proxy_ssl_perform_handshake(ZProxySSLHandshake *handshake)
{
  ZProxy *self = handshake->proxy;
  gboolean res;

  z_proxy_enter(self);

  if (!z_proxy_ssl_setup_handshake(handshake))
    z_proxy_return(self, FALSE);

  res = z_proxy_ssl_do_handshake(handshake, self->flags & ZPF_NONBLOCKING);

  z_proxy_return(self, res);
}

/**
 * Do initial SSL setup of a proxy endpoint stream.
 *
 * @param self          the proxy instance
 * @param side          the side being set up
 *
 * Based on the policy security settings, this function pushed an SSL stream onto the
 * stream stack used on the specified endpoint of the proxy and requests a handshake
 * to be initiated.
 *
 * The SSL stream is pushed onto the stack if the security level is greater that 'NONE',
 * that is, there's any possibility that we'll have to use SSL on the endpoint. (The SSL
 * stream instance has its session set to NULL, that is, it's not actually doing
 * encapsulation initially.)
 *
 * The handshake is initiated only if the endpoint is in 'FORCE_SSL' mode, that is, an
 * SSL handshake precedes all protocol communication on the stream.
 *
 * @return TRUE if setup was successful, FALSE otherwise
 */
gboolean
z_proxy_ssl_init_stream(ZProxy *self, gint side)
{
  gboolean rc = TRUE;

  z_proxy_enter(self);

  if (self->ssl_opts.security[side] > PROXY_SSL_SEC_NONE)
    {
      ZStream *old;

      old = self->endpoints[side];
      self->endpoints[side] = z_stream_ssl_new(old, NULL);
      z_stream_unref(old);

      /* do an SSL handshake right away if we're in forced SSL mode */
      if (self->ssl_opts.security[side] == PROXY_SSL_SEC_FORCE_SSL)
        rc = z_proxy_ssl_request_handshake(self, side, FALSE);
    }

  z_proxy_return(self, rc);
}

/**
 * Start an asynchronous SSL handshake.
 *
 * @param handshake     the handshake object
 * @param cb            callback function to be called on completion
 * @param user_data     user_data passed to the callback
 *
 * This function sets up handshake parameters, sets up stream callbacks / conditions
 * and adds the stream to the context of the proxy group.
 *
 * The callback is called when the handshake has been completed: either by finishing a
 * successful SSL handshake or by failing the handshake.
 *
 * @return TRUE if starting up the handshake was successful, FALSE otherwise
 */
static gboolean
z_proxy_ssl_perform_handshake_async(ZProxySSLHandshake *handshake,
                                    ZProxySSLCallbackFunc cb,
                                    gpointer user_data,
                                    GDestroyNotify user_data_notify)
{
  ZProxyGroup *proxy_group = z_proxy_get_group(handshake->proxy);

  z_proxy_enter(handshake->proxy);

  if (!z_proxy_ssl_setup_handshake(handshake))
    z_proxy_return(handshake->proxy, FALSE);

  z_proxy_ssl_handshake_set_callback(handshake, cb, user_data, user_data_notify);

  if (!z_proxy_ssl_setup_stream(handshake, proxy_group))
    z_proxy_return(handshake->proxy, FALSE);

  z_proxy_return(handshake->proxy, TRUE);
}

/**
 * Completion callback function used by the client-side non-blocking handshake
 *
 * @param handshake     the handshake object
 * @param user_data     user_data passed to the callback
 *
 * This function is called when the client-side SSL handshake has been completed for
 * a non-blocking proxy instance.
 *
 * The function restores the stream state to the pre-handshake state, stores the SSL session,
 * frees the handshake object and then calls z_proxy_nonblocking_init() for the proxy
 * instance.
 */
static void
z_proxy_ssl_init_completed(ZProxySSLHandshake *handshake, gpointer user_data)
{
  ZProxy *self = handshake->proxy;
  gboolean success = FALSE;

  z_proxy_enter(self);

  g_assert(handshake == user_data);

  /* restore stream state to that of before the handshake */
  if (!z_proxy_ssl_restore_stream(handshake))
    z_proxy_return(self);

  success = (z_proxy_ssl_handshake_get_error(handshake) == 0);

  /* if the handshake was successful, set the session and call nonblocking init */
  if (success)
    {
      if (self->ssl_opts.ssl_sessions[handshake->side])
        z_proxy_ssl_clear_session(self, handshake->side);

      self->ssl_opts.ssl_sessions[handshake->side] = z_ssl_session_ref(handshake->session);

      /* call the nonblocking init callback of the proxy */
      success = z_proxy_nonblocking_init(self, z_proxy_group_get_poll(z_proxy_get_group(self)));
    }

  if (!success)
    {
      /* initializing the client stream or the proxy failed, stop the proxy instance */
      z_proxy_nonblocking_stop(self);
    }

  z_proxy_leave(self);
}

/**
 * Initiate SSL handshake for a non-blocking proxy.
 *
 * @param self          the proxy instance
 * @param side          the side being initialized
 *
 * This function is called from the proxy core when it's starting up a new non-blocking
 * proxy instance.
 *
 * If the configured handshake order is (client, server) then we can do a true non-blocking
 * handshake where the nonblocking init callback of the proxy is called as a continuation
 * after the handshake.
 *
 * calling z_proxy_ssl_init_stream().
 * In all other cases the function falls back to doing a semi-nonblocking handshake by
 *
 * @return TRUE if the setup (and possible handshake) succeeded, FALSE otherwise
 */
gboolean
z_proxy_ssl_init_stream_nonblocking(ZProxy *self, gint side)
{
  gboolean res = TRUE;

  z_proxy_enter(self);

  if (self->ssl_opts.security[side] > PROXY_SSL_SEC_NONE)
    {
      /* we support async handshake only on the client side, and only if handshake order
       * is (client, server) */
      if ((side == EP_CLIENT) && self->ssl_opts.handshake_seq == PROXY_SSL_HS_CLIENT_SERVER)
        {
          ZProxySSLHandshake *handshake;
          ZStream *old;

          old = self->endpoints[side];
          self->endpoints[side] = z_stream_ssl_new(old, NULL);
          z_stream_unref(old);

          handshake = z_proxy_ssl_handshake_new(self, self->endpoints[side], side);
          res = z_proxy_ssl_perform_handshake_async(handshake, z_proxy_ssl_init_completed,
                                                    z_proxy_ssl_handshake_ref(handshake),
                                                    z_proxy_ssl_handshake_destroy_notify);
          z_proxy_ssl_handshake_unref(handshake);
        }
      else
        {
          res = z_proxy_ssl_init_stream(self, side);

          if (res)
            res = z_proxy_nonblocking_init(self, z_proxy_group_get_poll(z_proxy_get_group(self)));
        }
    }
  else
    res = z_proxy_nonblocking_init(self, z_proxy_group_get_poll(z_proxy_get_group(self)));

  z_proxy_return(self, res);
}

/**
 * Request an SSL handshake to be done on one of the proxy endpoints.
 *
 * @param self          the proxy instance
 * @param side          the side the handshake is to be made on
 * @param forced        is this a forced handshake
 *
 * This function initiates an SSL handshake on one of both of the proxy
 * endpoints, depending on the SSL settings configured in the policy.
 *
 * If forced is TRUE, the function always does an SSL handshake on the
 * requested side independently of the handshake order configured.
 *
 * @return TRUE if the handshake was successful, FALSE if not
 */
gboolean
z_proxy_ssl_request_handshake(ZProxy *self, gint side, gboolean forced)
{
  gboolean rc = FALSE;
  ZProxySSLHandshake *handshake;

  z_proxy_enter(self);

  /* if already initialized, return right away */
  if (self->ssl_opts.ssl_sessions[side])
    z_proxy_return(self, TRUE);

  /* if the proxy requested that we force-connect to the server and
   * we're doing handshake at the client side, we have to connect
   * first */
  if ((side == EP_CLIENT)
      && self->ssl_opts.force_connect_at_handshake)
    {
      z_proxy_log(self, CORE_INFO, 6, "Force-establishing server connection since the configured handshake order requires it;");
      if (!z_proxy_connect_server(self, NULL, 0))
        {
          z_proxy_log(self, CORE_ERROR, 3, "Server connection failed to establish, giving up;");
          z_proxy_return(self, FALSE);
        }
    }

  /* we don't delay the handshake if:
   *   - we're the first according to the configured handshake order
   *   - the caller explicitly requested that we do the handshake right now
   *   - SSL isn't enabled on the other side
   *   - SSL is forced on this side and *not* on the other (this means
   *     that the other endpoint is using TLS and we usually cannot synchronize
   *     forced SSL and TLS handshake because TLS depends on the client requesting
   *     it)
   *   - the other endpoint has already completed the SSL handshake
   */
  if ((self->ssl_opts.handshake_seq != side)
      && !forced
      && self->ssl_opts.security[EP_OTHER(side)] > PROXY_SSL_SEC_NONE
      && !((self->ssl_opts.security[side] == PROXY_SSL_SEC_FORCE_SSL)
           && (self->ssl_opts.security[EP_OTHER(side)] != PROXY_SSL_SEC_FORCE_SSL))
      && (self->ssl_opts.ssl_sessions[EP_OTHER(side)] == NULL))
    {
      /* if we've requested a handshake, but the handshake order requires
         the other endpoint to be the first and that side isn't ready yet,
         we only register the intent */
      z_proxy_log(self, CORE_DEBUG, 6, "Delaying SSL handshake after the other endpoint is ready; side='%s'", EP_STR(side));
      self->ssl_opts.handshake_pending[side] = TRUE;
      z_proxy_return(self, TRUE);
    }

  /* at this point we're either the first side to do the handshake, or
     the other endpoint has already completed the handshake */

  handshake = z_proxy_ssl_handshake_new(self, self->endpoints[side], side);

  rc = z_proxy_ssl_perform_handshake(handshake);

  if (!rc || !handshake->session)
    {
      z_proxy_ssl_handshake_unref(handshake);
      z_proxy_return(self, rc);
    }

  if (self->ssl_opts.ssl_sessions[side])
    z_proxy_ssl_clear_session(self, side);
  self->ssl_opts.ssl_sessions[side] = z_ssl_session_ref(handshake->session);

  z_proxy_ssl_handshake_unref(handshake);

  if (side == EP_SERVER)
    z_proxy_ssl_register_host_iface(self);

  /* in case there's a pending handshake request on the other endpoint
     make sure we complete that */
  side = EP_OTHER(side);
  if (self->ssl_opts.handshake_pending[side])
    {
      z_proxy_log(self, CORE_DEBUG, 6, "Starting delayed SSL handshake; side='%s'", EP_STR(side));

      g_assert(self->endpoints[side] != NULL);
      handshake = z_proxy_ssl_handshake_new(self, self->endpoints[side], side);

      self->ssl_opts.handshake_pending[side] = FALSE;
      rc = z_proxy_ssl_perform_handshake(handshake);

      if (self->ssl_opts.ssl_sessions[side])
        z_proxy_ssl_clear_session(self, side);
      self->ssl_opts.ssl_sessions[side] = z_ssl_session_ref(handshake->session);

      z_proxy_ssl_handshake_unref(handshake);

      if (side == EP_SERVER)
        z_proxy_ssl_register_host_iface(self);
    }

  z_proxy_return(self, rc);
}
/**
 * Clear SSL state on one of the proxy endpoints.
 *
 * @param self          the proxy instance
 * @param side          the side being cleared
 *
 * This function cleans up SSL state on one of the endpoints of the proxy. It takes care
 * of freeing the SSL session and unregistering the host interface on the server endpoint.
 *
 */
void
z_proxy_ssl_clear_session(ZProxy *self, gint side)
{
  z_proxy_enter(self);

  if (self->ssl_opts.ssl_sessions[side])
    {
      if (side == EP_SERVER)
        {
          ZProxyHostIface *iface;

          iface = z_proxy_find_iface(self, Z_CLASS(ZProxyHostIface));
          if (iface)
            {
              z_proxy_del_iface(self, iface);
              z_object_unref(&iface->super);
            }
        }

      z_ssl_session_unref(self->ssl_opts.ssl_sessions[side]);
      self->ssl_opts.ssl_sessions[side] = NULL;
    }

  z_proxy_leave(self);
}

/**
 * Tell the proxy core to force-connect the server endpoint if the handshake order requires it.
 *
 * @param self          the proxy instance
 * @param val           whether or not to force-connect
 *
 * Certain proxies (eg. HTTP) delay connecting the server endpoint until the request has
 * been processed. This makes using the (server, client) handshake order impossible. As
 * a workaround the proxy SSL core provides a way for the proxy to request the server
 * endpoint to be force-connected right upon proxy startup so that the server-side SSL
 * handshake can be completed before the client handshake.
 *
 * This function sets the knob enabling force-connecting the server endpoint.
 *
 */
void
z_proxy_ssl_set_force_connect_at_handshake(ZProxy *self, gboolean val)
{
  z_proxy_enter(self);

  /* force-connecting the server side is meaningful only if the configured
   * handshake order is server-client */
  if (self->ssl_opts.handshake_seq == PROXY_SSL_HS_SERVER_CLIENT)
    self->ssl_opts.force_connect_at_handshake = val;

  z_proxy_leave(self);
}
