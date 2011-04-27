/***************************************************************************
 *
 * Copyright (c) 2009 BalaBit IT Ltd, Budapest, Hungary
 * All rights reserved.
 *
 * Author: Laszlo Attila Toth
 *
 ***************************************************************************/

#ifndef ZORP_PROXY_SSL_H_INCLUDED
#define ZORP_PROXY_SSL_H_INCLUDED

#include <zorp/proxycommon.h>
#include <zorp/ssl.h>

typedef enum
{
  PROXY_SSL_VERIFY_NONE                = 0,
  PROXY_SSL_VERIFY_OPTIONAL_UNTRUSTED  = 1,
#define PROXY_SSL_VERIFY_OPTIONAL PROXY_SSL_VERIFY_OPTIONAL_UNTRUSTED
  PROXY_SSL_VERIFY_OPTIONAL_TRUSTED    = 2,
  PROXY_SSL_VERIFY_REQUIRED_UNTRUSTED  = 3,
  PROXY_SSL_VERIFY_REQUIRED_TRUSTED    = 4,
} proxy_ssl_verify_type;

#define PROXY_SSL_HS_CLIENT_SERVER 0
#define PROXY_SSL_HS_SERVER_CLIENT 1

#define PROXY_SSL_HS_POLICY ZV_POLICY
#define PROXY_SSL_HS_ACCEPT ZV_ACCEPT
#define PROXY_SSL_HS_VERIFIED 10

typedef enum
{
  PROXY_SSL_SEC_NONE                    = 0,
  PROXY_SSL_SEC_FORCE_SSL               = 1,
  PROXY_SSL_SEC_ACCEPT_STARTTLS         = 2,
  PROXY_SSL_SEC_FORWARD_STARTTLS        = 3,
} proxy_ssl_security_type;

typedef struct _ZProxySsl {
  ZPolicyDict *dict;
  ZPolicyObj *ssl_struct;

  proxy_ssl_security_type security[EP_MAX];

  GString *ssl_method[EP_MAX];
  GString *ssl_cipher[EP_MAX];

  ZSSLSession *ssl_sessions[EP_MAX];

  ZPolicyObj *server_setup_key_cb, *server_setup_ca_list_cb, *server_setup_crl_list_cb, *server_verify_cert_cb;
  ZPolicyObj *client_setup_key_cb, *client_setup_ca_list_cb, *client_setup_crl_list_cb, *client_verify_cert_cb;

  EVP_PKEY *local_privkey[EP_MAX];
  X509 *peer_cert[EP_MAX];
  X509 *local_cert[EP_MAX];
  STACK_OF(X509) *local_ca_list[EP_MAX];
  STACK_OF(X509_NAME) *server_peer_ca_list;
  STACK_OF(X509_CRL) *local_crl_list[EP_MAX];

  gboolean force_connect_at_handshake;
  gint handshake_timeout;
  gint handshake_seq;
  gboolean handshake_pending[EP_MAX];
  GHashTable *handshake_hash[EP_MAX];

  proxy_ssl_verify_type verify_type[EP_MAX];
  int verify_depth[EP_MAX];
  gboolean disable_proto_sslv2[EP_MAX];
  gboolean disable_proto_sslv3[EP_MAX];
  gboolean disable_proto_tlsv1[EP_MAX];

  gboolean permit_invalid_certificates;
  gboolean server_check_subject;
  GString  *local_privkey_passphrase[EP_MAX];
} ZProxySsl;

struct _ZProxySSLHandshake;
typedef void (*ZProxySSLCallbackFunc)(struct _ZProxySSLHandshake *hs, gpointer user_data);
typedef struct _ZProxySSLHandshake {
  ZRefCount ref_cnt;
  ZSSLSession *session;
  ZStream *stream;
  ZProxy *proxy;
  gint side;

  /* result */
  gint ssl_err;
  gchar ssl_err_str[512];

  /* internals */
  GSource *timeout;

  ZStreamContext stream_context;
  ZProxySSLCallbackFunc completion_cb;
  gpointer completion_user_data;
  GDestroyNotify completion_user_data_notify;
} ZProxySSLHandshake;

ZProxySSLHandshake *z_proxy_ssl_handshake_new(ZProxy *proxy, ZStream *stream, gint side);
ZProxySSLHandshake *z_proxy_ssl_handshake_ref(ZProxySSLHandshake *self);
gboolean z_proxy_ssl_handshake_unref(ZProxySSLHandshake *self);

void z_proxy_ssl_config_defaults(ZProxy *self);
void z_proxy_ssl_register_vars(ZProxy *self);
void z_proxy_ssl_free_vars(ZProxy *self);
gboolean z_proxy_ssl_perform_handshake(ZProxySSLHandshake *handshake);
gboolean z_proxy_ssl_init_stream(ZProxy *self, gint side);
gboolean z_proxy_ssl_init_stream_nonblocking(ZProxy *self, gint side);
gboolean z_proxy_ssl_request_handshake(ZProxy *self, gint side, gboolean forced);
void z_proxy_ssl_clear_session(ZProxy *self, gint side);
void z_proxy_ssl_set_force_connect_at_handshake(ZProxy *self, gboolean val);

#endif
