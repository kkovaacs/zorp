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
 * $Id: proxy.h,v 1.82 2004/06/11 12:57:39 bazsi Exp $
 *
 ***************************************************************************/

#ifndef ZORP_PROXY_H_INCLUDED
#define ZORP_PROXY_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/zobject.h>
#include <zorp/stream.h>
#include <zorp/zpython.h>
#include <zorp/pydict.h>
#include <zorp/dispatch.h>
#include <zorp/poll.h>
#include <zorp/audit.h>
#include <zorp/thread.h>
#include <zorp/proxyssl.h>


/* proxy states, the order of these enums is important */
enum
{
  ZPS_INITIAL,
  ZPS_THREAD_STARTED,
  ZPS_CONFIG,
  ZPS_STARTING_UP,
  ZPS_WORKING,
  ZPS_SHUTTING_DOWN,
  ZPS_DESTROYING,
};

/* proxy flags */
enum 
{
  ZPF_NONBLOCKING=0x0001,
  ZPF_STOP_REQUEST=0x0002,
};

/* compatibility macros */
#define Z_VAR_GET               0x00000001      /* variable can be read */
#define Z_VAR_SET               0x00000003      /* variable can be read and written */
#define Z_VAR_GET_CONFIG        0x00000004
#define Z_VAR_SET_CONFIG        0x0000000C      /* variable can be read and written */

#define Z_VAR_TYPE(t) ((t) & 0x0000ff00)

#define Z_VAR_TYPE_INT          0x00000100      /* variable is an int */
#define Z_VAR_TYPE_STRING       0x00000200      /* variable is a string */
#define Z_VAR_TYPE_OBJECT       0x00000400      /* variable is a policy object */
#define Z_VAR_TYPE_HASH         0x00000500      /* variable is a hash */
#define Z_VAR_TYPE_METHOD       0x00000600      /* variable is a method */
#define Z_VAR_TYPE_CUSTOM       0x00000700      /* variable is something, requests are
                                                   processed via a function call */
#define Z_VAR_TYPE_DIMHASH      0x00000800      /* variable is a multidimensional hash */
#define Z_VAR_TYPE_ALIAS        0x00000900      /* variable is an alias of another variable */
#define Z_VAR_TYPE_OBSOLETE     0x00000A00      /* variable is an obsolete alias of another variable */


typedef struct _ZProxyParams ZProxyParams;
typedef struct _ZProxyIface ZProxyIface;
typedef struct _ZProxyFuncs ZProxyFuncs;
typedef struct _ZProxyGroup ZProxyGroup;
typedef struct _ZChannelProps ZChannelProps;

struct _ZProxyParams
{
  const gchar *session_id;
  ZPolicyObj *pyclient;
  ZStream *client;
  ZPolicyObj *handler;
  ZProxy *parent;
};

struct _ZProxyFuncs
{
  ZObjectFuncs super;
  gboolean (*config)(ZProxy *self);
  gboolean (*startup)(ZProxy *self);
  void (*main)(ZProxy *self);
  void (*shutdown)(ZProxy *self);
  void (*destroy)(ZProxy *self);
  gboolean (*nonblocking_init)(ZProxy *self, ZPoll *poll);
  void (*nonblocking_deinit)(ZProxy *self);
  void (*wakeup)(ZProxy *self);
};

struct _ZChannelProps
{
  guint8 tos[EP_DIR_MAX];
};

struct _ZProxy
{
  ZObject super;
  guint16 status;
  guint16 flags;
  gchar session_id[MAX_SESSION_ID];
  ZThread *proxy_thread;
  GThreadPriority proxy_pri;
  ZPolicyThread *thread;
  ZPolicyObj *handler;
  ZPolicyDict *dict;
  ZProxyGroup *group;
  ZStream *endpoints[EP_MAX];
  ZPolicyObj *py_endpoints[EP_MAX];

  ZChannelProps channel_props[EP_MAX];
  gboolean channel_props_set[EP_MAX];
  GString *language;

  /* a pointer to the parent proxy */
  ZProxy *parent_proxy;
  /* the linked list of child proxies */
  GList *child_proxies;

  GStaticMutex interfaces_lock;  
  GList *interfaces;

  ZProxySsl ssl_opts;
};

extern ZClass ZProxy__class;

/* function prototypes registered in the registry */
typedef ZProxy *(*ZProxyCreateFunc)(ZProxyParams *params);

/* log functions */
#define z_proxy_log(self, class, level, format, args...) 		\
  do {									\
    z_object_check_compatible((ZObject *) self, Z_CLASS(ZProxy));	\
    /*NOLOG*/ 								\
    z_log(((ZProxy *) self)->session_id, class, level, format,  ##args);	\
  } while (0)

#define z_proxy_log_data_dump(self, class, level, buf, len)             \
  do {									\
    z_object_check_compatible((ZObject *) self, Z_CLASS(ZProxy));	\
    /*NOLOG*/ 								\
    z_log_data_dump(((ZProxy *)self)->session_id, class, level, buf, len); \
  } while (0)

#define z_proxy_log_text_dump(self, class, level, buf, len)             \
  do {									\
    z_object_check_compatible((ZObject *) self, Z_CLASS(ZProxy));	\
    /*NOLOG*/ 								\
    z_log_text_dump(((ZProxy *)self)->session_id, class, level, buf, len); \
  } while (0)

#if ENABLE_TRACE
  #define z_proxy_trace(self, args...) z_proxy_log(self , CORE_TRACE, 7, ##args)
  #define z_proxy_enter(self) z_session_enter(((ZProxy *)self)->session_id)
  #define z_proxy_leave(self) z_session_leave(((ZProxy *)self)->session_id)
  #define z_proxy_cp(self) z_session_cp(((ZProxy *)self)->session_id)
#else
  #define z_proxy_trace(self, args...) ({void *__p G_GNUC_UNUSED = self;})
  #define z_proxy_enter(self)  ({void *__p G_GNUC_UNUSED = self;})
  #define z_proxy_leave(self)
  #define z_proxy_cp(self)  ({void *__p G_GNUC_UNUSED = self;})
#endif

#define z_proxy_return(self, ...)      do { z_proxy_leave(self); return __VA_ARGS__; } while (0)

/* interface support */
void z_proxy_add_iface(ZProxy *self, ZProxyIface *iface);
void z_proxy_del_iface(ZProxy *self, ZProxyIface *iface);
ZProxyIface *z_proxy_find_iface(ZProxy *self, ZClass *compat);

/* helper functions for communicating with the policy layer */
gboolean z_proxy_policy_config(ZProxy *);
gboolean z_proxy_policy_startup(ZProxy *);
void z_proxy_policy_shutdown(ZProxy *);
void z_proxy_policy_destroy(ZProxy *self); 

/* compatibility functions for ZPolicyDict based attribute handling */
void z_proxy_var_new(ZProxy *self, const gchar *name, guint flags, ...);

gboolean z_proxy_add_child(ZProxy *self, ZProxy *child_proxy);
gboolean z_proxy_del_child(ZProxy *self, ZProxy *child_proxy);

ZProxyGroup *z_proxy_get_group(ZProxy *self);
void z_proxy_set_group(ZProxy *self, ZProxyGroup *proxy_group);

/* misc helper functions */
gint z_proxy_connect_server(ZProxy *self, const gchar *host, gint port);
gint z_proxy_user_authenticated(ZProxy *self, const gchar *entity, gchar const **groups);

gboolean
z_proxy_get_addresses(ZProxy *self, 
                      guint *protocol,
                      ZSockAddr **client_address, ZSockAddr **client_local,
                      ZSockAddr **server_address, ZSockAddr **server_local,
                      ZDispatchBind **client_listen);
gboolean
z_proxy_get_addresses_locked(ZProxy *self, 
                             guint *protocol,
                             ZSockAddr **client_address, ZSockAddr **client_local,
                             ZSockAddr **server_address, ZSockAddr **server_local,
                             ZDispatchBind **client_listen);

gboolean z_proxy_threaded_start(ZProxy *self, ZProxyGroup *group);
gboolean z_proxy_nonblocking_start(ZProxy *self, ZProxyGroup *group);
void z_proxy_nonblocking_stop(ZProxy *self);


gboolean z_proxy_check_license(ZProxy *self);

static inline gboolean
z_proxy_stop_requested(ZProxy *self)
{
  return self->flags & ZPF_STOP_REQUEST; 
}

gboolean z_proxy_loop_iteration(ZProxy *self);

/* constructor for ZProxy */
ZProxy *
z_proxy_new(ZClass *class, ZProxyParams *params);

/* free method for ZProxy */
void z_proxy_free_method(ZObject *s);

static inline gboolean
z_proxy_config(ZProxy *self)
{ 
  return Z_FUNCS(self, ZProxy)->config(self);
}

static inline gboolean
z_proxy_startup(ZProxy *self)
{ 
  return Z_FUNCS(self, ZProxy)->startup(self);
}

static inline void
z_proxy_main(ZProxy *self)
{ 
  Z_FUNCS(self, ZProxy)->main(self);
}

static inline void
z_proxy_shutdown(ZProxy *self)
{ 
  Z_FUNCS(self, ZProxy)->shutdown(self);
}

static inline void
z_proxy_destroy(ZProxy *self)
{ 
  Z_FUNCS(self, ZProxy)->destroy(self);
}

static inline gboolean
z_proxy_nonblocking_init(ZProxy *self, ZPoll *poll)
{ 
  return Z_FUNCS(self, ZProxy)->nonblocking_init(self, poll);
}

static inline void
z_proxy_nonblocking_deinit(ZProxy *self)
{ 
  Z_FUNCS(self, ZProxy)->nonblocking_deinit(self);
}

static inline void 
z_proxy_wakeup(ZProxy *self)
{
  Z_FUNCS(self, ZProxy)->wakeup(self);
}

static inline ZProxy *
z_proxy_ref(ZProxy *self)
{
  return (ZProxy *) z_object_ref(&self->super);
}

static inline void 
z_proxy_unref(ZProxy *self)
{
  z_object_unref(&self->super);
}

static inline void
z_proxy_set_state(ZProxy *self, guint8 new_state)
{
  self->status = (self->status & ~0xFF) | new_state;
}

static inline guint8
z_proxy_get_state(ZProxy *self)
{
  return self->status & 0xFF;
}

/* Root class for proxy specific interfaces */
struct _ZProxyIface
{
  ZObject super;
  ZProxy *owner;
};

typedef ZObjectFuncs ZProxyIfaceFuncs;
extern ZClass ZProxyIface__class;

ZProxyIface *z_proxy_iface_new(ZClass *class, ZProxy *proxy);
void z_proxy_iface_free_method(ZObject *s);

/* ZProxyBasicIface */

/* NOTE: this interface is implemented by all proxies. dynamic references to
 * self->parent should only be used through this interface as in this case it
 * is ensured that the parent proxy exists by the time it is referenced.
 */ 

typedef ZProxyIface ZProxyBasicIface; 
typedef struct _ZProxyBasicIfaceFuncs 
{
  ZObjectFuncs super;
  gboolean (*get_var)(ZProxyBasicIface *self, const gchar *var_name, gchar **value);
  gboolean (*set_var)(ZProxyBasicIface *self, const gchar *var_name, gchar *value);
} ZProxyBasicIfaceFuncs;

extern ZClass ZProxyBasicIface__class;

static inline gboolean
z_proxy_basic_iface_get_var(ZProxyBasicIface *self, const gchar *var_name, gchar **value)
{
  return Z_FUNCS(self, ZProxyBasicIface)->get_var(self, var_name, value);
}

static inline gboolean
z_proxy_basic_iface_set_var(ZProxyBasicIface *self, const gchar *var_name, gchar *value)
{
  return Z_FUNCS(self, ZProxyBasicIface)->set_var(self, var_name, value);
}


ZProxyBasicIface *z_proxy_basic_iface_new(ZClass *class, ZProxy *proxy);
#define z_proxy_basic_iface_free_method z_proxy_iface_free_method

/* ZProxyStackIface */

typedef ZProxyIface ZProxyStackIface;
typedef struct _ZProxyStackIfaceFuncs 
{
  ZObjectFuncs super;
  void (*set_verdict)(ZProxyStackIface *self, ZVerdict verdict, const gchar *description);
  gboolean (*get_content_hint)(ZProxyStackIface *self, gint64 *content_length, const gchar **content_format);
  void (*set_content_hint)(ZProxyStackIface *self, gint64 content_length);
} ZProxyStackIfaceFuncs;

extern ZClass ZProxyStackIface__class;

static inline void
z_proxy_stack_iface_set_verdict(ZProxyStackIface *self, ZVerdict verdict, const gchar *description)
{
  z_proxy_log(self->owner, CORE_INFO, 4, "Received verdict from stacked proxy; verdict='%s', description='%s'", z_verdict_str(verdict), description);
  Z_FUNCS(self, ZProxyStackIface)->set_verdict(self, verdict, description);
}

static inline void
z_proxy_stack_iface_set_content_hint(ZProxyStackIface *self, gint64 content_length)
{
  if (Z_FUNCS(self, ZProxyStackIface)->set_content_hint)
    Z_FUNCS(self, ZProxyStackIface)->set_content_hint(self, content_length);
}

static inline gboolean
z_proxy_stack_iface_get_content_hint(ZProxyStackIface *self, gint64 *content_length, const gchar **content_format)
{
  if (Z_FUNCS(self, ZProxyStackIface)->get_content_hint)
    return Z_FUNCS(self, ZProxyStackIface)->get_content_hint(self, content_length, content_format);
  *content_length = -1;
  *content_format = "file";
  return TRUE;
}

#define z_proxy_stack_iface_new z_proxy_iface_new
#define z_proxy_stack_iface_free_method z_proxy_iface_free_method

typedef ZProxyIface ZProxyHostIface;
typedef struct _ZProxyHostIfaceFuncs
{
  ZObjectFuncs super;
  gboolean (*check_name)(ZProxyHostIface *s, const gchar *host_name, gchar *reason_buf, gsize reason_len);
} ZProxyHostIfaceFuncs;

extern ZClass ZProxyHostIface__class;

static inline gboolean
z_proxy_host_iface_check_name(ZProxyHostIface *s, const gchar *host_name, gchar *reason_buf, gsize reason_len)
{
  return Z_FUNCS(s, ZProxyHostIface)->check_name(s, host_name, reason_buf, reason_len);
}

gboolean z_proxy_stop_request(const gchar *session_id);


void z_proxy_hash_init(void);
void z_proxy_hash_destroy(void);

#endif
