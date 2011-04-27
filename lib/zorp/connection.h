#ifndef ZORP_CONNECTION_H_INCLUDED
#define ZORP_CONNECTION_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/stream.h>
#include <zorp/sockaddr.h>

enum
{
  ZD_PROTO_AUTO = 0,
  ZD_PROTO_TCP = 1,
  ZD_PROTO_UDP = 2,
};

typedef struct _ZConnection
{
  guint protocol;
  ZStream *stream;
  ZSockAddr *remote; /* the peer's address */
  ZSockAddr *local;  /* the explicit local address (no wildcard port spec) */
  ZSockAddr *dest;   /* the original destination of the client */
  struct _ZDispatchBind *dispatch_bind;
} ZConnection;

ZConnection *z_connection_new(void);
gchar *z_connection_format(ZConnection *conn, gchar *buf, gint buflen);
void z_connection_destroy(ZConnection *conn, gboolean close);

#endif
