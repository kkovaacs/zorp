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
 * $Id: dispatch.c,v 1.40 2004/05/22 16:02:57 bazsi Exp $
 *
 * Author  : SaSa
 * Auditor :
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/dispatch.h>
#include <zorp/listen.h>
#include <zorp/dgram.h>
#include <zorp/log.h>
#include <zorp/streamfd.h>
#include <zorp/thread.h>
#include <zorp/ifmonitor.h>

#include <string.h>

/*
 * Dispatcher module
 *
 * The top of the dispatcher system is a hash table that consists of chains,
 * keyed by the (protocol, address) pair they are listening on.
 * Each such chain consists of elements, ordered by a priority value.
 * These elements contain callback functions that will be notified when a new
 * connection is established to the chain's input point.
 */
 
#define MAX_DISPATCH_BIND_STRING 128

/* our SockAddr based hash contains elements of this type */
typedef struct _ZDispatchChain
{
  guint ref_cnt;
  gchar *session_id;
  ZDispatchBind *registered_key;
  ZSockAddr *bound_addr;
  GList *elements;
  GStaticRecMutex lock;
  gboolean threaded;
  GAsyncQueue *accept_queue;
  ZDispatchParams params;
  GList *listeners;
  GList *iface_watches;
  ZIfmonGroupWatch *iface_group_watch;
} ZDispatchChain;

/* Each ZDispatchChain structure contains a list of instances of this type */
struct _ZDispatchEntry
{
  gchar *session_id;
  gint prio;
  ZDispatchBind *chain_key;
  ZDispatchCallbackFunc callback;
  gpointer callback_data;
  GDestroyNotify data_destroy;
};

/* Global dispatch table and its mutex */
GHashTable *dispatch_table;
GStaticMutex dispatch_lock = G_STATIC_MUTEX_INIT;

/*
 * Locking within the Dispatch module
 *
 * There are two level locking within Dispatch:
 * 1) a global lock protecting the Dispatch hash table
 * 2) a per-chain lock protecting the chain's linked list and its reference counter
 *
 * If both locks are needed the global lock must be acquired first.
 */

typedef struct _ZListenerEntry
{
  ZListener *listener;
  ZRefCount ref_cnt;
} ZListenerEntry;

/**
 * z_listener_entry_new:
 * @listener: stolen reference for a ZListener
 *
 * Creates a new ZListenerEntry object and borrow a reference for the listener
 *
 * Returns: the new listener entry
 */
ZListenerEntry *
z_listener_entry_new(ZListener * listener)
{
  ZListenerEntry *self = g_new0(ZListenerEntry, 1);
  g_assert(listener != NULL);

  self->listener = listener;
  z_refcount_set(&self->ref_cnt, 1);
  return self;
}

void
z_listener_entry_destroy(ZListenerEntry *self)
{
  z_listener_unref(self->listener);
  g_free(self);
}

ZListenerEntry *
z_listener_entry_ref(ZListenerEntry *self)
{
  z_refcount_inc(&self->ref_cnt);
  return self;
}

/**
 * z_listener_entry_unref:
 * @self: listener entry
 *
 * Decreases the reference count of the listener entry. If it reaches zero, the listener entry is freed
 * and the reference count listener inside of the object is decreased.
 *
 * Returns true if the entry is freed
 */
gboolean
z_listener_entry_unref(ZListenerEntry *self)
{
  if (self && z_refcount_dec(&self->ref_cnt))
    {
      z_listener_entry_destroy(self);
      return TRUE;
    }
  return FALSE;
}

#define Z_DISPATCH_THREAD_EXIT_MAGIC ((ZConnection *) &z_dispatch_chain_thread)

static gpointer z_dispatch_chain_thread(gpointer st);
static void z_dispatch_connection(ZDispatchChain *chain, ZConnection *conn);

/**
 * z_dispatch_bind_equal:
 * @key1 1st key
 * @key2 2nd key
 *
 * Compares the keys by their IP and port values, used for hash key checking
 * function (g_hash_table_new).
 *
 * Returns:
 * TRUE if they equal
 */
static gboolean
z_dispatch_bind_equal(ZDispatchBind *key1, ZDispatchBind *key2)
{
  if (key1->type != key2->type || key1->protocol != key2->protocol)
    return FALSE;
  
  switch (key1->type)
    {
    case ZD_BIND_SOCKADDR:
      return z_sockaddr_equal(key1->sa.addr, key2->sa.addr);
    case ZD_BIND_IFACE:
      return g_str_equal(key1->iface.iface, key2->iface.iface) && key1->iface.port == key2->iface.port && key1->iface.ip4.s_addr == key2->iface.ip4.s_addr;
    case ZD_BIND_IFACE_GROUP:
      return key1->iface_group.group == key2->iface_group.group && key1->iface_group.port == key2->iface_group.port;
    default:
      g_assert_not_reached();
    }
}


/**
 * z_dispatch_bind_hash:
 * @key The key to generate a hash value from
 *
 * Generates an integer hash value from a key
 *
 * Returns:
 * The hash value
 */
static guint 
z_dispatch_bind_hash(ZDispatchBind *key)
{
  struct sockaddr_in *s_in;
  
  switch (key->type)
    {
    case ZD_BIND_SOCKADDR:
      g_assert(z_sockaddr_inet_check(key->sa.addr));
  
      s_in = (struct sockaddr_in *) &key->sa.addr->sa;
      return s_in->sin_family + ntohs(s_in->sin_port) + ntohl(s_in->sin_addr.s_addr) + key->protocol; 
    case ZD_BIND_IFACE:
      return g_str_hash(key->iface.iface) + ntohs(key->iface.port);
    case ZD_BIND_IFACE_GROUP:
      return (key->iface_group.group << 16) + ntohs(key->iface.port);
    default:
      g_assert_not_reached();
    }
}

gchar *
z_dispatch_bind_format(ZDispatchBind *self, gchar *buf, gsize buflen)
{
  gchar sabuf[MAX_SOCKADDR_STRING];
  gchar ipbuf[16];
  
  switch (self->type)
    {
    case ZD_BIND_SOCKADDR:
      g_snprintf(buf, buflen, "SA(proto=%d,addr=%s)", self->protocol, z_sockaddr_format(self->sa.addr, sabuf, sizeof(sabuf)));
      break;
    case ZD_BIND_IFACE:
      /* FIXME: preferred IP should be formatted according to family */
      g_snprintf(buf, buflen, "IFACE(proto=%d,iface=%s,ip=%s,port=%d,family=%d)", self->protocol, self->iface.iface, z_inet_ntoa(ipbuf, sizeof(ipbuf), self->iface.ip4), self->iface.port, self->iface.family);
      break;
    case ZD_BIND_IFACE_GROUP:
      g_snprintf(buf, buflen, "IFGROUP(proto=%d,iface_group=0x%x,port=%d,family=%d)", self->protocol, self->iface_group.group, self->iface_group.port, self->iface_group.family);
      break;
    default:
      g_assert_not_reached();
    }
  return buf;
}

static gboolean
z_dispatch_bind_is_wildcard(ZDispatchBind *self)
{
  switch (self->type)
    {
    case ZD_BIND_SOCKADDR:
      if (z_sockaddr_inet_check(self->sa.addr) && z_sockaddr_inet_get_port(self->sa.addr) == 0)
        return TRUE;
      break;
    case ZD_BIND_IFACE:
      return ntohs(self->iface.port) == 0;
    case ZD_BIND_IFACE_GROUP:
      return ntohs(self->iface_group.port) == 0;
    default:
      g_assert_not_reached();
    }
  return FALSE;
}

static inline void
z_dispatch_bind_init(ZDispatchBind *self, guint type, guint protocol)
{
  z_refcount_set(&self->ref_cnt, 1);
  self->type = type;
  self->protocol = protocol;
}

/**
 * z_dispatch_bind_new_sa:
 * @addr: socket address
 * @protocol: protocol identifier (ZD_PROTO_*)
 *
 * Create a new ZDispatchBind instance initializing it based on @addr and
 * @protocol. ZDispatchBind instances are used for keying the Dispatch hash
 * table.
 *
 * Returns: new ZDispatchBind structure
 **/
ZDispatchBind *
z_dispatch_bind_new_sa(guint protocol, ZSockAddr *addr)
{
  ZDispatchBind *self = g_new0(ZDispatchBind, 1);

  z_dispatch_bind_init(self, ZD_BIND_SOCKADDR, protocol);
  self->sa.addr = z_sockaddr_ref(addr);

  return self;
}

/**
 * z_dispatch_bind_new_iface:
 * @iface: interface name
 * @protocol: protocol identifier (ZD_PROTO_*)
 *
 * Create a new ZDispatchBind instance initializing it based on @addr and
 * @protocol. ZDispatchBind instances are used for keying the Dispatch hash
 * table.
 *
 * Returns: new ZDispatchBind structure
 **/
ZDispatchBind *
z_dispatch_bind_new_iface(guint protocol, const gchar *iface, gint family, const gchar *ip, guint port)
{
  ZDispatchBind *self = g_new0(ZDispatchBind, 1);

  z_dispatch_bind_init(self, ZD_BIND_IFACE, protocol);
  g_strlcpy(self->iface.iface, iface, sizeof(self->iface.iface));
  self->iface.family = family;
  self->iface.port = port;
  
  switch (family)
    {
    case AF_INET:
      z_inet_aton(ip, &self->iface.ip4);
      break;
    default:
      g_assert_not_reached();
    }

  return self;
}

/**
 * z_dispatch_bind_new_iface_group:
 * @group: interface name
 * @protocol: protocol identifier (ZD_PROTO_*)
 *
 * Create a new ZDispatchBind instance initializing it based on @group and
 * @protocol. ZDispatchBind instances are used for keying the Dispatch hash
 * table.
 *
 * Returns: new ZDispatchBind structure
 **/
ZDispatchBind *
z_dispatch_bind_new_iface_group(guint protocol, guint32 group, gint family, guint port)
{
  ZDispatchBind *self = g_new0(ZDispatchBind, 1);

  z_dispatch_bind_init(self, ZD_BIND_IFACE_GROUP, protocol);
  self->iface_group.group = group;
  self->iface_group.family = family;
  self->iface_group.port = port;
  
  return self;
}


/**
 * z_dispatch_bind_ref: 
 * @self: this
 *
 * Add a reference to @self:
 **/
ZDispatchBind *
z_dispatch_bind_ref(ZDispatchBind *self)
{
  z_refcount_inc(&self->ref_cnt);
  return self;
}

/**
 * z_dispatch_bind_unref: 
 * @self: this
 *
 * Decrement reference count for @self and free if that reaches zero.
 *
 **/
void
z_dispatch_bind_unref(ZDispatchBind *self)
{
  if (self && z_refcount_dec(&self->ref_cnt))
    {
      if (self->type == ZD_BIND_SOCKADDR)
        z_sockaddr_unref(self->sa.addr);
      
      g_free(self);
      
    }
}

/**
 * z_dispatch_chain_lock:
 * @self this
 *
 * Lock the chain's mutex
 */
static inline void
z_dispatch_chain_lock(ZDispatchChain *self)
{
  g_static_rec_mutex_lock(&self->lock);
}

/**
 * z_dispatch_chain_unlock:
 * @self this
 *
 * Unlock the chain's mutex
 */
static inline void
z_dispatch_chain_unlock(ZDispatchChain *self)
{
  g_static_rec_mutex_unlock(&self->lock);
}


static inline ZDispatchChain *z_dispatch_chain_ref(ZDispatchChain *self);
static inline void z_dispatch_chain_unref(ZDispatchChain *self);


/**
 * z_dispatch_chain_thread:
 * @st this
 *
 * The thread routine of a dispatcher chain, pops new connections from the
 * accept_queue and processes them by calling z_dispatch_connection.
 * When the popped connection is the special value Z_DISPATCH_THREAD_EXIT_MAGIC,
 * exits the processing loop and finishes the thread.
 * 
 * Returns: NULL
 */
static gpointer
z_dispatch_chain_thread(gpointer st)
{
  ZDispatchChain *self = (ZDispatchChain *) st;
  ZConnection *conn;
  glong acceptq_sum;
  gint count;
  
  /* g_thread_set_priority(g_thread_self(), G_THREAD_PRIORITY_HIGH); */ 
  /*LOG
   This message reports that a new dispatcher thread is starting. This is used if threaded
   dispatching is enabled.
   @see: Dispatcher
   */
  z_log(NULL, CORE_DEBUG, 4, "Dispatch thread starting;");
  acceptq_sum = 0;
  count = 0;
  while (1)
    {
      acceptq_sum += g_async_queue_length(self->accept_queue);
      if (count % 1000 == 0)
        {
          /*LOG
	    This message reports the dispatcher average accept queue length status.
	   */
	  z_log(NULL, CORE_DEBUG, 4, "Accept queue stats; avg_length='%ld'", acceptq_sum / 1000);
          acceptq_sum = 0;
        }
      conn = g_async_queue_pop(self->accept_queue);
      if (conn == Z_DISPATCH_THREAD_EXIT_MAGIC)
        break;
      z_dispatch_connection(self, conn);
      count++;
    }
  /*LOG
    This message reports that the dispatcher thread is exiting.
    It it likely that Zorp unbinds from that address.
   */
  z_log(NULL, CORE_DEBUG, 4, "Dispatch thread exiting;");
  z_dispatch_chain_unref(self);
  return NULL;
}


/**
 * z_dispatch_chain_new:
 * @protocol Protocol identifier (ZD_PROTO_*)
 * @bind_addr Address to bind to
 * @params Additional parameters (see ZDispatch*Params)
 *
 * Constructor of ZDispatchChain, allocates and initialises a new instance, optionally
 * starts a processing thread for it.
 *
 * Returns:
 * The new instance
 */
static ZDispatchChain *
z_dispatch_chain_new(const gchar *session_id, ZDispatchBind *key, ZDispatchParams *params)
{
  ZDispatchChain *self = g_new0(ZDispatchChain, 1);
  gchar thread_name[256], buf[256];
  
  z_enter();
  self->session_id = strdup(session_id);
  self->ref_cnt = 1;
  self->registered_key = z_dispatch_bind_ref(key);
  self->threaded = ((ZDispatchCommonParams *) params)->threaded;

  memcpy(&self->params, params, sizeof(*params));
  if (self->threaded)
    {
      self->accept_queue = g_async_queue_new();
      z_dispatch_chain_ref(self);
      g_snprintf(thread_name, sizeof(thread_name), "dispatch(%s)", z_dispatch_bind_format(key, buf, sizeof(buf)));
      if (!z_thread_new(thread_name, z_dispatch_chain_thread, self))
        {
	  /*LOG
	    This message indicates that Zorp was unable to create a
	    dispatcher thread for accepting new connection, and it is
	    reverting back to the original non-threaded mode.  It is likely
	    that Zorp reached its thread or resource limit. Check your logs
	    for further information.
	   */
          z_log(NULL, CORE_ERROR, 2, "Error creating dispatch thread, falling back to non-threaded mode;");
          z_dispatch_chain_unref(self);
          self->threaded = FALSE;
          g_async_queue_unref(self->accept_queue);
          self->accept_queue = NULL;
        }
    }
  z_return(self);
}

/**
 * z_dispatch_chain_ref:
 * @self this
 *
 * Increment the chain's reference counter.
 */
static inline ZDispatchChain *
z_dispatch_chain_ref(ZDispatchChain *self)
{
  z_dispatch_chain_lock(self);
  z_incref(&self->ref_cnt);
  z_dispatch_chain_unlock(self);
  return self;
}


/**
 * z_dispatch_chain_unref:
 * @self this
 *
 * Decrement the chain's reference counter, destroy it when the counter
 * reaches zero.
 */
static inline void
z_dispatch_chain_unref(ZDispatchChain *self)
{
  z_dispatch_chain_lock(self);  
  if (z_decref(&self->ref_cnt) == 0)
    {
      z_dispatch_chain_unlock(self);

      if (self->accept_queue)
        g_async_queue_unref(self->accept_queue);

      z_dispatch_bind_unref(self->registered_key);
      z_sockaddr_unref(self->bound_addr);
      g_free(self->session_id);
      g_free(self);
    }
  else
    z_dispatch_chain_unlock(self);

}

/**
 * z_dispatch_entry_free:
 * @entry this
 *
 * Destructor of ZDispatchEntry
 */
static void
z_dispatch_entry_free(ZDispatchEntry *entry)
{
  g_free(entry->session_id);
  z_dispatch_bind_unref(entry->chain_key);
  if (entry->data_destroy)
    entry->data_destroy(entry->callback_data);
  g_free(entry);
}


/**
 * z_dispatch_entry_compare_prio:
 * @a 1st entry
 * @b 2nd entry
 *
 * Compares the two entries by their priority, used for ordered inserting 
 * into the list by g_list_insert_sorted.
 *
 * Returns:
 * -1 if a is less prioritised than b
 *  0 if the priorities equals
 *  1 if a is more prioritised than b
 */
static gint
z_dispatch_entry_compare_prio(ZDispatchEntry *a, ZDispatchEntry *b)
{
  if (a->prio < b->prio)
    return -1;
  else if (a->prio == b->prio)
    return 0;
  else
    return 1;
}

/**
 * z_dispatch_connection:
 * @chain this
 * @conn The new connection to dispatch
 *
 * Iterates through the chain and dispatches the connection to the
 * chain items by passing it to their callbacks (for example to
 * z_py_zorp_dispatch_accept, which passes it to Dispatcher.accepted).
 */
static void 
z_dispatch_connection(ZDispatchChain *chain, ZConnection *conn)
{
  GList *p;
  ZDispatchEntry *entry;
  gchar buf[256];
  
  z_enter();
  z_dispatch_chain_lock(chain);
  /* the list is ordered by priority */
  for (p = chain->elements; p; p = g_list_next(p))
    {
      entry = (ZDispatchEntry *) p->data;
      /*LOG
        This message reports that a new connections is coming.
       */
      z_log(entry->session_id, CORE_DEBUG, 6, "Incoming connection; %s", conn ? z_connection_format(conn, buf, sizeof(buf)) : "conn=NULL");
      if ((entry->callback)(conn, entry->callback_data))
        {
          z_dispatch_chain_unlock(chain);
          z_return();
        }
    }
  z_dispatch_chain_unlock(chain);
  
  /* nobody needed this connection, destroy it */
  /*LOG
    This message indicates that a new connection was accepted, but no
    Listenet/Receiver/Proxy was interested in it.
   */
  z_log(NULL, CORE_ERROR, 3, "Nobody was interested in this connection; %s", z_connection_format(conn, buf, sizeof(buf)));
  z_connection_destroy(conn, TRUE);
  z_return();
}

/**
 * z_dispatch_accept:
 * @fdstream Socket stream
 * @client Address of remote endpoint
 * @dest Address of original destination
 * @user_data this
 *
 * Internal callback, called when a new incoming connection is established.
 * Creates and initialises a new ZConnection, and dispatches it to the chain
 * either synchronously by z_dispatch_connection or asynchronously by pushing
 * it to the chain's accept queue. 
 *
 * Note: this function runs in the main thread.
 * 
 * Returns: TRUE
 */
static gboolean
z_dispatch_accept(ZStream *fdstream, ZSockAddr *client, ZSockAddr *dest, gpointer user_data)
{
  ZConnection *conn = NULL;
  ZDispatchChain *chain = (ZDispatchChain *) user_data;
    
  z_enter();
  if (fdstream == NULL)
    {
      z_dispatch_connection(chain, NULL);
      z_return(TRUE);
    }
    
  if (chain->params.common.transparent)
    {
      ZSockAddr *listen_addr = NULL;
      gboolean non_transparent = FALSE;
      GList *p;

      switch (chain->registered_key->type)
        {
        case ZD_BIND_SOCKADDR:
          listen_addr = chain->registered_key->sa.addr;
          non_transparent = z_sockaddr_equal(listen_addr, dest);
          break;
        case ZD_BIND_IFACE:
        case ZD_BIND_IFACE_GROUP:

          /* NOTE: we are running in the main thread just like the
           * code that manipulates chain->listeners, thus we don't need to
           * lock here. This is even true for threaded listeners as
           * z_dispatch_accept runs in the main thread in that case too. 
           */

          for (p = chain->listeners; p; p = p->next)
            {
              ZListener *l = ((ZListenerEntry *) p->data)->listener;

              if (z_sockaddr_equal(l->local, dest))
                {
                  non_transparent = TRUE;
                  listen_addr = l->local;
                  break;
                }
            }
          break;
        }

      if (non_transparent)
        {
          gchar buf1[MAX_SOCKADDR_STRING], buf2[MAX_SOCKADDR_STRING];
          /*LOG
            This message indicates that Listener/Receiver was
            configured to be accept transparent connections, but it
            was connected directly.  Configure it either
            non-transparent or deny direct access to it and set up the
            appropriate TPROXY rule.

            @see: Listener 
            @see: Receiver
          */
          z_log(chain->session_id, CORE_ERROR, 1, "Transparent listener connected directly, dropping connection; local='%s', client_local='%s'", 
                z_sockaddr_format(listen_addr, buf1, sizeof(buf1)),
                z_sockaddr_format(dest, buf2, sizeof(buf2)));
          z_stream_close(fdstream, NULL);
          z_stream_unref(fdstream);
          z_sockaddr_unref(client);
          z_sockaddr_unref(dest);
          z_return(TRUE);
        }
    }
      
  conn = z_connection_new();
  conn->remote = client;
  conn->dest = dest;
  conn->local = z_sockaddr_ref(conn->dest);
  conn->dispatch_bind = z_dispatch_bind_ref(chain->registered_key);
  conn->protocol = chain->registered_key->protocol;
  conn->stream = fdstream;
    
  if (chain->threaded)
    g_async_queue_push(chain->accept_queue, conn);
  else
    z_dispatch_connection(chain, conn);
    
  z_return(TRUE);
}

static ZListener *
z_dispatch_new_listener(ZDispatchChain *chain, ZSockAddr *local)
{
  ZListener *listener = NULL;
  guint32 sock_flags = (chain->params.common.mark_tproxy ? ZSF_MARK_TPROXY : 0) | 
                            (chain->params.common.transparent ? ZSF_TRANSPARENT : 0);

  if (chain->registered_key->protocol == ZD_PROTO_TCP)
    {
      sock_flags |= chain->params.tcp.accept_one ? ZSF_ACCEPT_ONE : 0;
      listener = z_stream_listener_new(chain->session_id, local, sock_flags, chain->params.tcp.backlog, z_dispatch_accept, chain);
    }
  else if (chain->registered_key->protocol == ZD_PROTO_UDP)
    {
      listener = z_dgram_listener_new(chain->session_id, local, sock_flags, chain->params.udp.rcvbuf, z_dispatch_accept, chain);
    }
  return listener;
}

static gboolean
z_dispatch_iface_addr_matches(gint family, void *addr, ZDispatchBind *db)
{
  gboolean match = FALSE;
  
  if (db->type == ZD_BIND_IFACE)
    {
      switch (family)
        {
        case AF_INET:
          match = (db->iface.ip4.s_addr == 0) ||
                  (memcmp(addr, &db->iface.ip4, sizeof(struct in_addr)) == 0);
          break;
        default:
          g_assert_not_reached();
          break;
        }
    }
  else if (db->type == ZD_BIND_IFACE_GROUP)
    {
      match = TRUE;
    }
    
  return match;
}

static ZSockAddr *
z_dispatch_iface_to_sa(gint family, void *addr, guint16 port)
{
  gchar buf[16];

  switch (family)
    {
    case AF_INET:
      z_inet_ntoa(buf, sizeof(buf), *((struct in_addr *) addr));
      return z_sockaddr_inet_new(buf, port);
    default:
      g_assert_not_reached();
      break;
    }
  return NULL;
}

/**
 * z_dispatch_bind_iface_change:
 *
 * NOTE: this runs in the main thread
 **/
static void
z_dispatch_bind_iface_change(const gchar *iface G_GNUC_UNUSED, ZIfChangeType change, gint family, void *addr, gpointer user_data)
{
  ZDispatchChain *chain = (ZDispatchChain *) user_data;
  ZListener *listener;
  ZListenerEntry *listener_entry;
  gchar buf1[MAX_DISPATCH_BIND_STRING];
  gchar buf2[MAX_SOCKADDR_STRING];
  ZSockAddr *sa = NULL;
  gushort port;

  z_dispatch_bind_format(chain->registered_key, buf1, sizeof(buf1));
  if (chain->registered_key->type == ZD_BIND_IFACE)
    port = chain->registered_key->iface.port;
  else if (chain->registered_key->type == ZD_BIND_IFACE_GROUP)
    port = chain->registered_key->iface_group.port;
  else
    g_assert_not_reached();
  switch (change)
    {
    case Z_IFC_ADD:
      sa = z_dispatch_iface_to_sa(family, addr, port);
      z_sockaddr_format(sa, buf2, sizeof(buf2));
      if (z_dispatch_iface_addr_matches(family, addr, chain->registered_key))
        {
          GList *p;
          gboolean listener_exists = FALSE;

          for (p = chain->listeners; p; p = p->next)
            {
              listener_entry = (ZListenerEntry *) p->data;
              if (z_sockaddr_equal(sa, listener_entry->listener->bind_addr))
                {
                  listener_exists = TRUE;
                  z_listener_entry_ref(listener_entry);
                }
            }

          if (!listener_exists)
            {
              z_log(chain->session_id, CORE_DEBUG, 4, "Adding dynamic interface address; addr='%s', dispatch='%s'", buf2, buf1);
              listener = z_dispatch_new_listener(chain, sa);
              if (listener)
                {
                  listener_entry = z_listener_entry_new(listener);
                  chain->listeners = g_list_prepend(chain->listeners, listener_entry);
                  if (!z_listener_start(listener))
                    {
                      chain->listeners = g_list_remove(chain->listeners, listener_entry);
                      z_listener_entry_unref(listener_entry);
                    }
                }
            }
          else
            {
              z_log(chain->session_id, CORE_DEBUG, 5, "Dynamic interface address already bound, skipping bind this time; addr='%s', dispatch='%s'", buf2, buf1);
            }
        }
      else
        {
          z_log(chain->session_id, CORE_DEBUG, 5, "Address does not match expected dynamic address; addr='%s', dispatch='%s'", buf2, buf1);
        }
      z_sockaddr_unref(sa);
      break;
    case Z_IFC_REMOVE:
      {
        GList *p, *p_next;

        sa = z_dispatch_iface_to_sa(family, addr, port);
        z_sockaddr_format(sa, buf2, sizeof(buf2));
        z_log(chain->session_id, CORE_DEBUG, 4, "Removing dynamic interface address; addr='%s', dispatch='%s'", buf2, buf1);

        for (p = chain->listeners; p; p = p_next)
          {
            p_next = g_list_next(p);
            listener_entry = (ZListenerEntry *) p->data;
            if (z_sockaddr_equal(sa, listener_entry->listener->bind_addr))
              {
                ZListener *l = z_listener_ref(listener_entry->listener);
                if (z_listener_entry_unref(listener_entry))
                  {
                    z_listener_cancel(l);
                    chain->listeners = g_list_delete_link(chain->listeners, p);
                  }
                z_listener_unref(l);
              }
          }
        z_sockaddr_unref(sa);
      }
      break;
    }
}

/**
 * z_dispatch_bind_iface_change:
 *
 * NOTE: this runs in the main thread
 **/
static void
z_dispatch_bind_iface_group_change(guint32 group, ZIfChangeType change, const gchar *if_name, gpointer user_data)
{
  ZDispatchChain *chain = (ZDispatchChain *) user_data;

  switch (change)
    {
    case Z_IFC_ADD:
      chain->iface_watches = g_list_prepend(chain->iface_watches, z_ifmon_register_watch(if_name, chain->registered_key->iface_group.family, z_dispatch_bind_iface_change, chain, NULL));
      z_log(chain->session_id, CORE_DEBUG, 4, "Interface added to group; group='0x%x', name='%s'", group, if_name);
      break;
    case Z_IFC_REMOVE:
      {
        GList *p, *p_next;
        ZIfmonWatch *watch;

        for (p = chain->iface_watches; p; p = p_next)
          {
            p_next = g_list_next(p);
            watch = (ZIfmonWatch *) p->data;
            if (z_ifmon_watch_iface_matches(watch, if_name))
              {
                z_ifmon_unregister_watch(watch);
                chain->iface_watches = g_list_delete_link(chain->iface_watches, p);
                break;
              }
          }
        z_log(chain->session_id, CORE_DEBUG, 4, "Interface removed from group; group='0x%x', name='%s'", group, if_name);
      }
      break;
    }
}

/**
 * z_dispatch_bind_listener:
 * @session_id Session identifier
 * @chain this
 *
 * Starts listening/receiving for a chain. 
 * 
 * Returns:
 * TRUE on success
 */
static gboolean
z_dispatch_bind_listener(ZDispatchChain *chain, ZDispatchBind **bound_key)
{
  gboolean rc = TRUE;
  ZListener *listener;
  
  z_enter();
  *bound_key = NULL;
  switch (chain->registered_key->type)
    {
    case ZD_BIND_SOCKADDR:
      listener = z_dispatch_new_listener(chain, chain->registered_key->sa.addr);
      if (listener)
        {
          ZListenerEntry *entry = z_listener_entry_new(listener);

          chain->listeners = g_list_prepend(chain->listeners, entry);
          /* open fd so that we can get the local address */
          if (!z_listener_open(listener))
            {
              chain->listeners = g_list_remove(chain->listeners, entry);
              z_listener_entry_unref(entry);
              rc = FALSE;
              break;
            }
          chain->bound_addr = z_sockaddr_ref(listener->local);
          if (!z_listener_start(listener))
            {
              chain->bound_addr = NULL;
              z_sockaddr_unref(listener->local);
              chain->listeners = g_list_remove(chain->listeners, entry);
              z_listener_unref(listener);

              rc = FALSE;
              break;

            }
          *bound_key = z_dispatch_bind_new_sa(chain->registered_key->protocol, chain->bound_addr);
        }
      else
        rc = FALSE;

      break;
    case ZD_BIND_IFACE:
      if (chain->registered_key->protocol == 0)
        return FALSE;

      /* NOTE: we don't add a reference to chain, this interface
       * registration is always deleted before this ZDispatchChain
       * instance would be */

      chain->iface_watches = g_list_prepend(chain->iface_watches, z_ifmon_register_watch(chain->registered_key->iface.iface, chain->registered_key->iface.family, z_dispatch_bind_iface_change, chain, NULL));
      *bound_key = z_dispatch_bind_ref(chain->registered_key);
      break;
    case ZD_BIND_IFACE_GROUP:
      if (chain->registered_key->protocol == 0)
        return FALSE;

      /* NOTE: we don't add a reference to chain, this interface
       * registration is always deleted before this ZDispatchChain
       * instance would be */

      chain->iface_group_watch = z_ifmon_register_group_watch(chain->registered_key->iface_group.group, z_dispatch_bind_iface_group_change, chain, NULL);
      *bound_key = z_dispatch_bind_ref(chain->registered_key);
      break;
    }
    
  z_leave();
  return rc;
}


/**
 * z_dispatch_unbind_listener:
 * @chain this
 *
 * Stops listening/receiving for a chain. If the chain was using a processing\
 * thread, notifies it by sending the special connection value Z_DISPATCH_THREAD_EXIT_MAGIC
 * to it.
 */
static void
z_dispatch_unbind_listener(ZDispatchChain *chain)
{
  GList *p;

  z_enter();

  if (chain->threaded)
    {
      /* send exit magic to our threads */
      g_async_queue_push(chain->accept_queue, Z_DISPATCH_THREAD_EXIT_MAGIC);
    }
  if (chain->iface_group_watch)
    z_ifmon_unregister_group_watch(chain->iface_group_watch);
  while (chain->iface_watches)
    {
      z_ifmon_unregister_watch((ZIfmonWatch *) chain->iface_watches->data);
      chain->iface_watches = g_list_delete_link(chain->iface_watches, chain->iface_watches);
    }
  for (p = chain->listeners; p; p = g_list_next(p))
    {
      ZListenerEntry *l = (ZListenerEntry *) p->data;
      z_listener_cancel(l->listener);
      /* FIXME: refence counting??? */
      z_listener_entry_destroy(l);
    }
  g_list_free(chain->listeners);
  chain->listeners = NULL;
  z_return();
}


/**
 * z_dispatch_register:
 * @session_id Session identifier
 * @key: ZDispatchBind instance
 * @bound_addr The address actually bound to
 * @prio Priority level
 * @params Additional parameters, see ZDispatch*Params
 * @cb Callback to call when a connection is established
 * @user_data this
 * @data_destroy Pointer to the destructor
 *
 * Constructor for ZDispatchEntry. Creates and initialises a new chain item
 * instance, looks for a chain that is bound to the requested address, creates
 * a new one if no such chain found, inserts it into the chain ordered by
 * priority.
 *
 * Returns:
 * The new instance
 */
ZDispatchEntry *
z_dispatch_register(gchar *session_id,
                    ZDispatchBind *key,
                    ZSockAddr **bound_addr, 
                    gint prio, 
                    ZDispatchParams *params,
                    ZDispatchCallbackFunc cb, gpointer user_data, GDestroyNotify data_destroy)
{
  ZDispatchChain *chain;
  ZDispatchEntry *entry = NULL;
  ZDispatchBind *bound_key;

  z_session_enter(session_id);  

  g_static_mutex_lock(&dispatch_lock);

  if (z_dispatch_bind_is_wildcard(key))
    chain = NULL;
  else
    chain = g_hash_table_lookup(dispatch_table, key);

  if (!chain)
    {
      /* create hash chain */
      chain = z_dispatch_chain_new(session_id, key, params);

      if (!z_dispatch_bind_listener(chain, &bound_key))
        {
          z_dispatch_chain_unref(chain);
          g_static_mutex_unlock(&dispatch_lock);
          z_session_leave(session_id);
          return NULL;
        }
      /* chain is stored for the bound key (e.g. without the wildcard port) */
      g_hash_table_insert(dispatch_table, z_dispatch_bind_ref(bound_key), chain);
    }
  else
    {
      if (key->protocol == ZD_PROTO_TCP && chain->params.tcp.accept_one)
        {
          gchar buf[MAX_DISPATCH_BIND_STRING];
           
          /*LOG
            This message indicates that a Listener/Receiver/Proxy was unable
            bind to a specified address, because another instance is already
            listening there and specified that only one connection could be
            accepted.
           */
          z_log(session_id, CORE_ERROR, 1, 
                  "Error registering dispatch, previous entry specified accept_one; dispatch='%s'", 
                  z_dispatch_bind_format(key, buf, sizeof(buf)));
          goto error;
        }
        
      /* we have a fully specified key, which was already registered, bound_key == key */
      
      bound_key = z_dispatch_bind_ref(key);
      z_dispatch_chain_ref(chain);
    }
  
  if (bound_addr)
    *bound_addr = z_sockaddr_ref(chain->bound_addr);
  
  entry = g_new0(ZDispatchEntry, 1);
  entry->chain_key = bound_key;
  entry->session_id = g_strdup(session_id);
  entry->prio = prio;
  entry->callback = cb;
  entry->callback_data = user_data;
  entry->data_destroy = data_destroy;
  z_dispatch_chain_lock(chain);
  chain->elements = g_list_insert_sorted(chain->elements, entry, (GCompareFunc) z_dispatch_entry_compare_prio);
  z_dispatch_chain_unlock(chain);

 error:
  g_static_mutex_unlock(&dispatch_lock);
  
  z_session_leave(session_id);
  return entry;
}

/**
 * z_dispatch_unregister:
 * @entry this
 *
 * Destructor of ZDispatchEntry. Removes the entry from its chain,
 * destroying the chain if this was the last entry in it.
 */
void
z_dispatch_unregister(ZDispatchEntry *entry)
{
  ZDispatchChain *chain;
  ZDispatchBind *key;
  gchar buf[MAX_DISPATCH_BIND_STRING];
  gboolean found, unbind;
  gpointer orig_key, orig_chain;
  
  z_enter();
  g_static_mutex_lock(&dispatch_lock);
  found = g_hash_table_lookup_extended(dispatch_table, entry->chain_key, &orig_key, &orig_chain);
  key = (ZDispatchBind *) orig_key;
  chain = (ZDispatchChain *) orig_chain;
  if (found && chain)
    {
      GList *p;
      
      z_dispatch_chain_lock(chain);
      p = g_list_find(chain->elements, entry);
      if (p)
        {
          chain->elements = g_list_delete_link(chain->elements, p);
          z_dispatch_entry_free(entry);
        }
      else
        {
	  /*LOG
	    This message indicates that a Listener/Receiver/Proxy tries to
	    unbind from the specified address, but have not registered
	    itself to that address.
	   */
          z_log(NULL, CORE_ERROR, 1, "Internal error, dispatch entry not found (chain exists); dispatch='%s', entry='%p'", 
                z_dispatch_bind_format(entry->chain_key, buf, sizeof(buf)), entry);
        }

      g_assert(chain->ref_cnt >= (guint) (1 + (guint) (!!chain->threaded)));
      unbind = chain->ref_cnt == (guint) (1 + (guint) (!!chain->threaded));
      z_dispatch_chain_unlock(chain);
      if (unbind)
        {
          /* we need to unlock first as the underlying listener has its own
           * lock which is locked in the reverse order when the callback is
           * called. */
          z_dispatch_unbind_listener(chain);
          if (!g_hash_table_remove(dispatch_table, key))
            g_assert_not_reached();
          z_dispatch_bind_unref(key);

        }
      z_dispatch_chain_unref(chain);
    }
  else
    {
      /*LOG
	This message indicates that a Listener/Receiver/Proxy tries to
	unbind from the specified address, but Zorp does not bind to that
	address.
       */
      z_log(NULL, CORE_ERROR, 1, 
            "Internal error, dispatch entry not found (no chain); dispatch='%s', entry='%p'", 
            z_dispatch_bind_format(entry->chain_key, buf, sizeof(buf)), entry);
    }
  g_static_mutex_unlock(&dispatch_lock);
  z_return();
}

/* module initialization */

/**
 * z_dispatch_init:
 *
 * Initialises the global hash table of chains.
 */
void
z_dispatch_init(void)
{
  dispatch_table = g_hash_table_new((GHashFunc) z_dispatch_bind_hash, (GEqualFunc) z_dispatch_bind_equal);
}


/**
 * z_dispatch_destroy:
 *
 * Destroys the global hash table of chains.
 * FIXME?: what happens if there are still chains in the table?
 */
void
z_dispatch_destroy(void)
{
  if (dispatch_table)
    {
      g_hash_table_destroy(dispatch_table);
      dispatch_table = NULL;
    }
}
