#ifndef ZORP_DISPATCH_H_INCLUDED
#define ZORP_DISPATCH_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/stream.h>
#include <zorp/sockaddr.h>
#include <zorp/connection.h>

typedef struct _ZDispatchEntry ZDispatchEntry;
typedef struct _ZDispatchBind ZDispatchBind;

/* dispatching priorities */

enum
{
  ZD_PRI_LISTEN=100,    /* used by listeners and receivers */
  ZD_PRI_NORMAL=0,      /* used by proxies supporting several subsessions for fastpath*/
  ZD_PRI_RELATED=-100,  /* used by proxies needing related connections, e.g. FTP data stream */
};

enum
{
  ZD_BIND_NONE,
  ZD_BIND_SOCKADDR,
  ZD_BIND_IFACE,
  ZD_BIND_IFACE_GROUP,
} ZDispatchBindType;


typedef struct _ZDispatchCommonParams
{
  gboolean threaded; 
  gboolean mark_tproxy;
  gboolean transparent;
} ZDispatchCommonParams;

typedef struct _ZDispatchTCPParams
{
  gboolean accept_one; /* prohibits other dispatch_registers */
  gint backlog;        /* listen backlog, the first dispatch registration counts */
} ZDispatchTCPParams;

typedef struct _ZDispatchUDPParams
{
  gint rcvbuf;
} ZDispatchUDPParams;

typedef struct _ZDispatchParams
{
  ZDispatchCommonParams common;
  union
  {
    ZDispatchTCPParams tcp;
    ZDispatchUDPParams udp;
  };
} ZDispatchParams;

typedef gboolean (*ZDispatchCallbackFunc)(ZConnection *conn, gpointer user_data);

/* ZDispatchBind */

/* The dispatch_table hashtable contains ZDispatchEntry structures keyed
 * with instances of this type */
struct _ZDispatchBind
{
  ZRefCount ref_cnt;
  gushort protocol;
  gushort type;
  union
  {
    struct
    {
      ZSockAddr *addr;
    } sa;
    struct
    {
      gchar iface[16];
      gint family;
      struct in_addr ip4;
      gushort port;
    } iface;
    struct
    {
      guint32 group;
      gint family;
      gushort port;
    } iface_group;
  };
};

ZDispatchBind *z_dispatch_bind_new_sa(guint protocol, ZSockAddr *addr);
ZDispatchBind *z_dispatch_bind_new_iface(guint protocol, const gchar *iface, gint family, const gchar *ip, guint port);
ZDispatchBind *z_dispatch_bind_new_iface_group(guint protocol, guint32 group, gint family, guint port);

gchar *z_dispatch_bind_format(ZDispatchBind *self, gchar *buf, gsize buflen);
ZDispatchBind *z_dispatch_bind_ref(ZDispatchBind *self);
void z_dispatch_bind_unref(ZDispatchBind *self);

/* Dispatch main entry points */

ZDispatchEntry *
z_dispatch_register(gchar *session_id,
                        ZDispatchBind *key,
		        ZSockAddr **bound_addr, 
                        gint prio, 
                        ZDispatchParams *params,
                        ZDispatchCallbackFunc cb, gpointer user_data, GDestroyNotify data_destroy);

void z_dispatch_unregister(ZDispatchEntry *de);

void z_dispatch_init(void);
void z_dispatch_destroy(void);

#endif
