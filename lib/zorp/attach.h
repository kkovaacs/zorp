#ifndef ZORP_ATTACH_H_INCLUDED
#define ZORP_ATTACH_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/connection.h>
#include <zorp/proxy.h>

typedef struct _ZAttachTCPParams
{
} ZAttachTCPParams;

typedef struct _ZAttachUDPParams
{
} ZAttachUDPParams;

typedef struct _ZAttachParams
{
  gint timeout;
  gboolean loose;       /**< choose port in the same group if the port can't be bound */
  gboolean random;      /**< choose port in the same group randomly (securely). if TRUE, loose should be TRUE too. */
  gint tos;
  union
  {
    ZAttachTCPParams tcp;
    ZAttachUDPParams udp;
  };
} ZAttachParams;

typedef struct _ZAttach ZAttach;

typedef void (*ZAttachCallbackFunc)(ZConnection *, gpointer user_data);

gboolean z_attach_start(ZAttach *self, ZPoll *poll, ZSockAddr **local);
gboolean z_attach_start_block(ZAttach *self, ZConnection **conn);
void z_attach_cancel(ZAttach *self);

ZAttach *z_attach_new(ZProxy *proxy, guint proto, ZSockAddr *local, ZSockAddr *remote, ZAttachParams *params, ZAttachCallbackFunc callback, gpointer user_data, GDestroyNotify destroy_data);
void z_attach_free(ZAttach *self);

#endif
