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
 * $Id: proxy.c,v 1.132 2004/07/05 16:57:46 sasa Exp $
 *
 * Author  : Bazsi
 * Auditor : kisza
 * Last audited version: 1.23
 * Notes:
 *
 ***************************************************************************/

#include <zorp/proxy.h>
#include <zorp/policy.h>
#include <zorp/streamfd.h>
#include <zorp/streamline.h>
#include <zorp/streambuf.h>
#include <zorp/streamssl.h>
#include <zorp/log.h>
#include <zorp/io.h>
#include <zorp/thread.h>
#include <zorp/proxygroup.h>

#include <zorp/policy.h>
#include <zorp/pydict.h>
#include <zorp/pystream.h>
#include <zorp/pysockaddr.h>
#include <zorp/pyproxy.h>
#include <zorp/pydispatch.h>
#include <zorp/notification.h>
#include <zorp/audit.h>
#include <zorp/pyaudit.h>

#include <stdarg.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * References between child and parent proxies work as follows
 *
 * When a proxy wants to stack a child proxy a ZStackedProxy structure is
 * created which contains the stream objects towards the child, and also
 * contains references to both the proxy and its child. These references are
 * removed when the ZStackedProxy structure is freed using
 * z_stacked_proxy_destroy.
 *
 * When the child proxy starts up it adds a reference to its parent still in
 * the parent proxy's thread using z_proxy_add_child() in z_proxy_new(). 
 * This adds a reference from child to parent through its parent_proxy
 * field, and from parent to child through its child_proxies list. This is a
 * circular reference.
 *
 * 1) The child proxy exits first
 * 
 *    When the child proxy exits it calls z_proxy_destroy() which in turn
 *    calls z_proxy_set_parent(NULL) which drops the reference to its
 *    parent. The circular reference is now resolved. The parent will detect
 *    that its child exited (probably one of the streams indicates EOF) and
 *    calls z_stacked_proxy_destroy() for the ZStackedProxy structure
 *    associated with this child. It closes and frees streams, and removes
 *    the child proxy from the parent->child_proxies list.
 *
 * 2) The parent proxy exits first
 *
 *    It is assumed that ZStackedProxy structures associated with any child
 *    proxy is freed prior to calling z_proxy_destroy(). This assumption is
 *    valid as ZTransfer or proxy specific transfer code calls
 *    z_stacked_proxy_destroy(), thus the only remaining reference to the
 *    child proxy instance is through child_proxies.
 *    
 *    When the parent proxy exits, it calls z_proxy_destroy() which in turn
 *    frees every item on its child_proxies list.
 *
 *  3) The parent and child proxies exit at the same time
 * 
 *    In this case the exit is not synchronized by the EOF the parent reads
 *    from the child. Thus z_stacked_proxy_destroy() and z_proxy_destroy()
 *    might race on the following (possibly shared) data accesses:
 *     z_stacked_proxy_destroy:
 *       child is removed from parent->child_list
 *     z_proxy_destroy (parent):
 *       child is removed from parent->child_list (if present)
 *     z_proxy_destroy (child):
 *       child->parent is set to NULL
 *
 * Synchronization during reference counting
 *
 * The general rule is that every proxy instance modifies its own data
 * fields only in order to avoid locking.  The only locks used are the
 * recursive mutexes protecting the reference counts. The only exception to
 * this rule happens when the child proxy starts up and adds itself to its
 * parent's child_proxies list. The synchronization here is also simple as
 * this happens in the parent proxy's thread, thus no locks are necessary.
 * 
 * Interface list locking
 *
 * The interface list is manipulated from two threads simoultaneously:
 *   1) the parent might add/remove interface to the list anytime
 *   2) the child queries the list when it wants to communicate with the parent
 *
 * A race might occur when the list is being deleted and the child wants to
 * communicate with the parent (for example: parent exits at the same time
 * the child wants to call set_verdict). This is resolved by using a
 * GStaticMutex in ZProxy called interfaces_lock. It is assumed that the
 * ZProxyIface class does not touch the interfaces_lock in its destructor as
 * in that case a deadlock might occur.
 */

/*
 * This hashtable contains the ZProxy instances indexed by their session_id. 
 * It is used by the SZIG code to look be able to communicate with actual
 * proxies.
 */
static GStaticMutex proxy_hash_mutex = G_STATIC_MUTEX_INIT;
static GHashTable *proxy_hash = NULL;

/**
 * z_proxy_get_service_session_id:
 * @self: the proxy
 *
 * Get the session_id of the service instance where the specified proxy
 * instance belongs to. Each session may contain a stack of proxies, each
 * with a different session id. The first parts of these proxy specific
 * session IDs are the same. This function returns that.
 *
 * For example, the proxy might have the session_id of svc/ssh:0/ssh, the
 * service specific session id is the first two parts, e.g. svc/ssh:0.
 *
 * NOTE: The returned string is duplicated.
 *
 * Returns: th service session id
 *
 */
static gchar *
z_proxy_get_service_session_id(ZProxy *self)
{
  gchar *proxy_session;
  gint len;

  g_assert(self->session_id != NULL);

  proxy_session = strrchr(self->session_id, '/');

  g_assert(proxy_session != NULL);

  len = proxy_session - self->session_id;
  return g_strndup(self->session_id, len);
}

/**
 * z_proxy_register:
 * @self: The proxy to be registered
 *
 * It registers the proxy instance in the proxy_hash, based on its session name.
 */
static void
z_proxy_register(ZProxy *self)
{
  gchar *session_id;
  GList *list = NULL;
  GList *list_new = NULL;

  session_id = z_proxy_get_service_session_id(self);

  g_static_mutex_lock(&proxy_hash_mutex);

  list = g_hash_table_lookup(proxy_hash, session_id);

  z_proxy_ref(self);
  list_new = g_list_prepend(list, self);
  if (list_new != list)
    {
      /* NOTE: frees the old session_id in the hash, but leaves the list intact */
      g_hash_table_remove(proxy_hash, session_id);
      g_hash_table_insert(proxy_hash, session_id, list_new);
    }
  else
    g_free(session_id);

  g_static_mutex_unlock(&proxy_hash_mutex);
}

/**
 * z_proxy_unregister:
 * @self: the proxy to be unregistered
 *
 * Unregisters the proxy. If the proxy list is no longer used, it is destroyed
 */
static void
z_proxy_unregister(ZProxy *self)
{
  gchar *session_id;
  GList *list, *list_new;

  session_id = z_proxy_get_service_session_id(self);

  g_static_mutex_lock(&proxy_hash_mutex);
  list = g_hash_table_lookup(proxy_hash, session_id);
  list_new = g_list_remove(list, self);
  z_proxy_unref(self);

  if (list != list_new)
    {
      g_hash_table_remove(proxy_hash, session_id);
      
      if (list_new)
        g_hash_table_insert(proxy_hash, session_id, list_new);
      else
        g_free(session_id);
    }
  else
    {
      g_free(session_id);
    }

  g_static_mutex_unlock(&proxy_hash_mutex);
}


/**
 * z_proxy_stop_req_cb:
 * @self: proxy instance
 * @user_data: not used
 *
 * Sets the stop request flag for the proxy
 */
static void
z_proxy_stop_req_cb(gpointer s, gpointer user_data G_GNUC_UNUSED)
{
  ZProxy *self = (ZProxy *)s;
  
  self->flags |= ZPF_STOP_REQUEST;
  z_proxy_wakeup(self);
}

/**
 * z_proxy_stop_request:
 * @session_id: proxy thread's session_id
 *
 * Sets the stop request flag for each proxy
 *
 * Returns: TRUE if the proxy list found, FALSE otherwise
 *
 */
gboolean
z_proxy_stop_request(const gchar *session_id)
{
  GList *list;
  gboolean verdict = FALSE;

  g_static_mutex_lock(&proxy_hash_mutex);
  
  list = g_hash_table_lookup(proxy_hash, session_id);

  if (list)
    {
      g_list_foreach(list, z_proxy_stop_req_cb, NULL);
      verdict = TRUE;
    }
  g_static_mutex_unlock(&proxy_hash_mutex);

  return verdict;
}





/**
 * z_proxy_hash_unref_proxy:
 * @key: not used
 * @value: GList instance
 * @user_data: not used
 *
 * unrefs all proxy in the list
 */
static void
z_proxy_hash_unref_proxy(gpointer key G_GNUC_UNUSED, gpointer value, gpointer user_data G_GNUC_UNUSED)
{
  GList *list = value, *l;
  
  for (l = list; l; l = l->next)
    z_proxy_unref((ZProxy *) l->data);

  g_list_free(list);
}

/**
 * z_proxy_hash_init:
 *
 * Initalizes the proxy list
 */
void
z_proxy_hash_init(void)
{
  g_static_mutex_lock(&proxy_hash_mutex);
  proxy_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  g_static_mutex_unlock(&proxy_hash_mutex);
}

/**
 * z_proxy_hash_destroy:
 *
 * Deinitializes proxy list
 */
void
z_proxy_hash_destroy(void)
{
  g_static_mutex_lock(&proxy_hash_mutex);
  if (proxy_hash)
    {
      g_hash_table_foreach(proxy_hash, z_proxy_hash_unref_proxy, NULL);
      g_hash_table_destroy(proxy_hash);
      proxy_hash = NULL;
    }
  g_static_mutex_unlock(&proxy_hash_mutex);
}

/**
 * z_proxy_policy_call_event:
 * @self this #ZProxy instance
 * @event the called python event
 *
 * Thiis function call the @event event from current instance.
 *
 * Returns: a boolean value
 */
static gboolean
z_proxy_policy_call_event(ZProxy *self, gchar *event, gchar *old_event_name)
{
  ZPolicyObj *res;
  gboolean called;
  /*LOG
    This message reports that Zorp is about to call the proxy's %event() event.
   */
  z_proxy_log(self, CORE_DEBUG, 7, "calling %s() event;", event);
  res = z_policy_call(self->handler, event, NULL, &called, self->session_id);
  if (!called && old_event_name)
    {
      static gboolean obsolete_name_logged = FALSE;

      z_policy_var_unref(res);
      res = z_policy_call(self->handler, old_event_name, NULL, &called, self->session_id);
      
      if (!obsolete_name_logged && called)
        {
          obsolete_name_logged = TRUE;
          z_proxy_log(self, CORE_POLICY, 0, "Obsolete policy handler in Proxy definition; new_name='%s', old_name='%s'", event, old_event_name);
        }
    }
  if (res == NULL && called)
    {
      z_proxy_leave(self);
      return FALSE;
    }
  z_policy_var_unref(res);
  return TRUE;
}

/**
 * z_proxy_policy_call:
 * @self this #ZProxy instance
 * @event the called python event family
 *
 * This function call a python event family.
 * If event named to "event" it's first call
 * __pre_event__. If the call was success it's
 * call event and for last it's call __post_event__.
 *
 * Returns: TRUE if all call is success, FALSE otherwise
 */
static gboolean
z_proxy_policy_call(ZProxy *self, gchar *event, gchar *old_event_name)
{
  gchar event_string[512];
  
  z_proxy_enter(self);
  
  z_policy_thread_acquire(self->thread);

  g_snprintf(event_string, sizeof(event_string), "__pre_%s__", event);
  if (z_proxy_policy_call_event(self, event_string, NULL))
    {
      if (z_proxy_policy_call_event(self, event, old_event_name))
        {
          g_snprintf(event_string, sizeof(event_string), "__post_%s__", event);
          if (z_proxy_policy_call_event(self, event_string, NULL))
            {
              z_policy_thread_release(self->thread);
              z_proxy_leave(self);
              return TRUE;
            }
        }
    }

  z_policy_thread_release(self->thread);

  z_proxy_leave(self);
  return FALSE;
}

/**
 * z_proxy_policy_config:
 * @self: this ZProxy instance
 *
 * Acquires the thread associated with this Proxy instance and calls
 * the __pre_config__, config and __post_config__ events.
 *
 **/
gboolean
z_proxy_policy_config(ZProxy *self)
{
  z_proxy_enter(self);
  
  z_proxy_set_state(self, ZPS_CONFIG);

  z_policy_struct_set_is_config(self->ssl_opts.ssl_struct, TRUE);

  if (!z_proxy_policy_call(self, "config", NULL))
    {
      z_proxy_leave(self);
      return FALSE;
    }
  
#if 0
  // FIXME: readd variable dump
  z_policy_thread_acquire(self->thread);
  z_proxy_vars_dump_values(self->vars, self);
  z_policy_thread_release(self->thread);
#endif

  z_policy_struct_set_is_config(self->ssl_opts.ssl_struct, FALSE);

  z_proxy_leave(self);
  return TRUE;
}

/**
 * z_proxy_policy_startup:
 * @self: this ZProxy instance
 *
 * Acquires the thread associated with this TProxy instance and calls
 * the __pre_startup__, startup and __post_startup__ events.
 **/
gboolean
z_proxy_policy_startup(ZProxy *self)
{
  z_proxy_enter(self);
  z_proxy_set_state(self, ZPS_STARTING_UP);

  if (!z_proxy_policy_call(self, "startup", "startUp"))
    {
      z_proxy_leave(self);
      return FALSE;
    }

  z_proxy_set_state(self, ZPS_WORKING);

  z_proxy_leave(self);
  return TRUE;
}

/**
 * z_proxy_policy_shutdown:
 * @self: this ZProxy instance
 *
 * Acquires the thread associated with this TProxy instance and calls
 * the __pre_shutdown__, shutdown and __post_shutdown events.
 **/
void 
z_proxy_policy_shutdown(ZProxy *self)
{
  z_proxy_enter(self);
  z_proxy_set_state(self, ZPS_SHUTTING_DOWN);

  z_proxy_policy_call(self, "shutdown", "shutDown");

  z_proxy_leave(self);
}

/**
 * z_proxy_policy_destroy:
 * @self: this ZProxy instance
 *
 * Acquires the thread associated with this TProxy instance and calls
 * the __destroy__ event.
 **/
void 
z_proxy_policy_destroy(ZProxy *self)
{
  ZPolicyObj *res;
  gboolean called;

  /* NOTE: this function is also called when thread creation failed, in which case we are unable to call our Python functions */
  
  z_proxy_enter(self);
  if (z_proxy_get_state(self) > ZPS_THREAD_STARTED)
    {
      /*LOG
        This message reports that Zorp is about to call the proxy's __destroy__() event.
        This method handles the pre destroy tasks, like the shutdown of the server side connection.
       */
      z_proxy_log(self, CORE_DEBUG, 7, "calling __destroy__() event;");
      z_policy_thread_acquire(self->thread);
      res = z_policy_call(self->handler, "__destroy__", NULL, &called, self->session_id);
      z_policy_var_unref(res);
      z_policy_thread_release(self->thread);
      z_proxy_set_state(self, ZPS_DESTROYING);
    }
  z_proxy_leave(self);
}

/**
 * z_proxy_set_priority:
 * @self: ZProxy instance
 * @pri: new priority
 *
 * This function changes the proxy priority in the current process. If the
 * proxy has its own thread, then its thread priority is changed, if it is a
 * nonblocking proxy, nothing is changed.
 *
 * The current proxy priority is stored in the self->proxy_pri member.
 **/
void
z_proxy_set_priority(ZProxy *self, GThreadPriority pri)
{
  GList *l;
  
  if (self->proxy_pri != pri)
    {
      if ((self->flags & ZPF_NONBLOCKING) == 0 && self->proxy_thread)
        {
          g_thread_set_priority(self->proxy_thread->thread, pri);
        }
      for (l = self->child_proxies; l; l = l->next)
        {
          if (z_proxy_get_state(l->data) > ZPS_CONFIG && z_proxy_get_state(l->data) < ZPS_SHUTTING_DOWN)
            z_proxy_set_priority(l->data, pri);
        }
      self->proxy_pri = pri;
    }
}


static void
z_proxy_propagate_channel_props(ZProxy *self G_GNUC_UNUSED)
{
}


/**
 * z_proxy_connect_server:
 * @self: proxy instance
 * @host: host to connect to, used as a hint by the policy layer but may as well be ignored
 * @port: port in host to connect to
 * 
 * Send a connectServer event to the associated policy object.  Returns TRUE
 * if the server-side connection is established, otherwise the
 * connection to the client should be closed.
 **/
gboolean
z_proxy_connect_server(ZProxy *self, const gchar *host, gint port)
{
  ZPolicyObj *res, *args;
  gint rc;
  gboolean called;
  
  z_proxy_enter(self);

  /* It might be possible that we already connected to the server: if
     the SSL handshake order is server-client, we *do* have to connect
     to the server before starting the client handshake. If this is
     the case we simply return the already established connection. */
  if (self->endpoints[EP_SERVER] &&
      !z_stream_broken(self->endpoints[EP_SERVER]))
    {
      z_proxy_log(self, CORE_INFO, 6, "Using already established server connection;");
      z_proxy_return(self, TRUE);
    }

  z_proxy_propagate_channel_props(self);

  if (self->endpoints[EP_SERVER])
    {
      z_stream_shutdown(self->endpoints[EP_SERVER], SHUT_RDWR, NULL);
      z_stream_close(self->endpoints[EP_SERVER], NULL);
      z_stream_unref(self->endpoints[EP_SERVER]);
      self->endpoints[EP_SERVER] = NULL;

      z_proxy_ssl_clear_session(self, EP_SERVER);
    }

  z_policy_thread_acquire(self->thread);
  if (host && host[0])
    {
      args = z_policy_var_build("(si)", host, port);
      res = z_policy_call(self->handler, "setServerAddress", args, &called, self->session_id);
      if (!res)
        {
          z_policy_thread_release(self->thread);
          z_proxy_return(self, FALSE);
        }
      if (!z_policy_var_parse(res, "i", &rc) || !rc)
        {
          z_policy_thread_release(self->thread);
          z_proxy_return(self, FALSE);
        }
      z_policy_var_unref(res);
    }

  res = z_policy_call(self->handler, "connectServer", NULL, &called, self->session_id);

  if (res && z_policy_stream_check(res))
    {
      self->endpoints[EP_SERVER] = z_policy_stream_get_stream(res);
    }
  else
    {
      rc = FALSE;
      goto error;
    }

  z_policy_var_unref(res);
  z_policy_thread_release(self->thread);

  z_proxy_propagate_channel_props(self);

  if (self->endpoints[EP_SERVER])
    rc = z_proxy_ssl_init_stream(self, EP_SERVER);
  else
    rc = FALSE;

  z_proxy_return(self, rc);

 error:
  z_policy_var_unref(res);
  z_policy_thread_release(self->thread);

  z_proxy_propagate_channel_props(self);

  z_proxy_return(self, FALSE);
}

/**
 * z_proxy_user_authenticated:
 * @self: proxy instance
 * @entity: the name of the authenticated entity
 *
 * This function is called by the proxy when it decides that the user is
 * authenticated by some inband authentication method.
 **/
gboolean
z_proxy_user_authenticated(ZProxy *self, const gchar *entity, gchar const **groups)
{
  ZPolicyObj *res, *groups_tuple;
  gboolean called;
  gboolean rc = TRUE;
  
  z_proxy_enter(self);
  z_policy_thread_acquire(self->thread);
  
  if (groups)
    {
      groups_tuple = z_policy_convert_strv_to_list(groups);
    }
  else
    {
      groups_tuple = z_policy_none;
      z_policy_var_ref(groups_tuple);
    }
  res = z_policy_call(self->handler, "userAuthenticated", z_policy_var_build("(sOs)", entity, groups_tuple, "inband"), &called, self->session_id);
  z_policy_var_unref(groups_tuple);
  if (!res)
    rc = FALSE;
  z_policy_var_unref(res);
  z_policy_thread_release(self->thread);
  z_proxy_leave(self);
  return rc;
}





/**
 * z_proxy_get_addresses_locked:
 * @self: proxy instance
 * @protocol: the protocol number (ZD_PROTO_*) is returned here
 * @client_address: the remote address of the client is returned here
 * @client_local: the local address of the connection to the client is returned here
 * @server_address: the remote address of the server is returned here
 * @server_local: the local address of the connection to the server is returned here
 * @client_listen: the address of the listener which initiated this session is returned here
 *
 * This function is used to query the addresses used to connecting the proxy
 * to the client and server. The utilized application protocol is also
 * returned and the listener address which accepted the connection. 
 *
 * NOTE: this function assumes that a Python thread state is acquired.
 **/
gboolean
z_proxy_get_addresses_locked(ZProxy *self, 
                             guint *protocol,
                             ZSockAddr **client_address, ZSockAddr **client_local,
                             ZSockAddr **server_address, ZSockAddr **server_local,
                             ZDispatchBind **client_listen)
{
  ZPolicyObj *o;

  z_proxy_enter(self);

  if (protocol)
    {
      ZPolicyObj *pyproto;
      
      pyproto = z_session_getattr(self->handler, "protocol");
      if (PyInt_Check(pyproto))
        *protocol = PyInt_AsLong(pyproto);
      else
        *protocol = ZD_PROTO_TCP;
      z_policy_var_unref(pyproto);
    }

  if (client_address)
    {
      o = z_session_getattr(self->handler, "client_address");
      *client_address = z_policy_sockaddr_get_sa(o);
      z_policy_var_unref(o);
    }

  if (client_local)
    {
      o = z_session_getattr(self->handler, "client_local");
      *client_local = z_policy_sockaddr_get_sa(o);
      z_policy_var_unref(o);
    }

  if (client_listen)
    {
      o = z_session_getattr(self->handler, "client_listen");
      *client_listen = z_policy_dispatch_bind_get_db(o);
      z_policy_var_unref(o);
    }

  if (server_address)
    {
      o = z_session_getattr(self->handler, "server_address");
      *server_address = z_policy_sockaddr_get_sa(o);
      z_policy_var_unref(o);
    }

  if (server_local)
    {
      o = z_session_getattr(self->handler, "server_local");
      *server_local = z_policy_sockaddr_get_sa(o);
      z_policy_var_unref(o);
    }

  z_proxy_leave(self);
  return TRUE;
}

/**
 * z_proxy_get_addresses:
 * @self: proxy instance
 * @protocol: the protocol number (ZD_PROTO_*) is returned here
 * @client_address: the remote address of the client is returned here
 * @client_local: the local address of the connection to the client is returned here
 * @server_address: the remote address of the server is returned here
 * @server_local: the local address of the connection to the server is returned here
 * @client_listen: the address of the listener which initiated this session is returned here
 *
 * This function is used to query the addresses used to connecting the proxy
 * to the client and server. The utilized application protocol is also
 * returned and the listener address which accepted the connection.
 *
 * NOTE: this function acquires the thread state associated with @self.
 **/
gboolean
z_proxy_get_addresses(ZProxy *self, 
                      guint *protocol,
                      ZSockAddr **client_address, ZSockAddr **client_local,
                      ZSockAddr **server_address, ZSockAddr **server_local,
                      ZDispatchBind **client_listen)
{
  gboolean success;
  z_policy_thread_acquire(self->thread);
  success = z_proxy_get_addresses_locked(self, protocol, client_address, client_local, server_address, server_local, client_listen);
  z_policy_thread_release(self->thread);
  return success;
}

/**
 * z_proxy_set_parent:
 * @self: ZProxy instance referring to self
 * @parent: ZProxy instance referring to the parent proxy
 *
 * This function is called to change the reference to the parent proxy.
 * A value of NULL specifies to drop the reference, anything else
 * removes the earlier reference and assigns a new one. See the 
 * comment on locking at the beginning of this file for more details.
 **/
gboolean
z_proxy_set_parent(ZProxy *self, ZProxy *parent)
{
  ZProxy *old_parent;

  z_proxy_enter(self);  
  if (parent)
    {
      /* establish parent link */
      if (!self->parent_proxy)
        {
          z_proxy_ref(parent);
          self->parent_proxy = parent;
        }
      else
        {
          z_proxy_leave(self);
          return FALSE;
        }
    }
  else
    {
      /* remove parent link */
      if (self->parent_proxy)
        {
          old_parent = self->parent_proxy;
          self->parent_proxy = parent;
          z_proxy_unref(old_parent);
        }
      else
        {
          z_proxy_leave(self);
          return FALSE;
        }
    }
  z_proxy_leave(self);
  return TRUE;
}

/**
 * z_proxy_add_child:
 * @self: ZProxy instance referring to self
 * @child_proxy: ZProxy instance to be added to the child list
 *
 * This function adds the specified ZProxy instance to the child_proxies
 * linked list.
 **/
gboolean
z_proxy_add_child(ZProxy *self, ZProxy *child_proxy)
{
  z_enter();
  if (z_proxy_set_parent(child_proxy, self))
    {
      self->child_proxies = g_list_prepend(self->child_proxies, z_proxy_ref(child_proxy));
      z_return(TRUE);
    }
  z_return(FALSE);
}

/**
 * z_proxy_del_child:
 * @self: ZProxy instance referring to self
 * @child_proxy: ZProxy instance to be deleted from the child_proxies list
 *
 * This function removes @child_proxy from the child_proxies list in @self.
 **/
gboolean
z_proxy_del_child(ZProxy *self, ZProxy *child_proxy)
{
  z_proxy_enter(self);

  self->child_proxies = g_list_remove(self->child_proxies, child_proxy);
  z_proxy_unref(child_proxy);

  z_proxy_leave(self);
  return TRUE;
}


void 
z_proxy_set_group(ZProxy *self, ZProxyGroup *group)
{
  self->group = z_proxy_group_ref(group);
}

ZProxyGroup *
z_proxy_get_group(ZProxy *self)
{
  return self->group;
}

/**
 * z_proxy_add_iface:
 * @self: ZProxy instance
 * @iface: exported interface to add
 *
 * This function adds an exported function interface callable from
 * other proxies to the set of supported interface.
 **/
void
z_proxy_add_iface(ZProxy *self, ZProxyIface *iface)
{
  z_object_ref(&iface->super);
  g_static_mutex_lock(&self->interfaces_lock);
  self->interfaces = g_list_prepend(self->interfaces, iface);
  g_static_mutex_unlock(&self->interfaces_lock);
}

/**
 * z_proxy_del_iface:
 * @self: ZProxy instance
 * @iface: exported interface to delete
 *
 * This function deletes the interface specified in @iface from the set of
 * supported interfaces. 
 *
 * NOTE: the locking implemented here assumes that the destructor for
 * z_proxy_iface will not touch interfaces lock again.
 **/
void
z_proxy_del_iface(ZProxy *self, ZProxyIface *iface)
{
  g_static_mutex_lock(&self->interfaces_lock);
  self->interfaces = g_list_remove(self->interfaces, iface);
  g_static_mutex_unlock(&self->interfaces_lock);
  z_object_unref(&iface->super);
}

/** 
 * z_proxy_find_iface:
 * @self: ZProxy instance
 * @compat: search for an interface compatible with this class
 *
 * This function iterates on the set of supported interfaces in @self and
 * returns the first compatible with the class specified in @compat.
 **/
ZProxyIface *
z_proxy_find_iface(ZProxy *self, ZClass *compat)
{
  GList *p;
  
  if (!self)
    return NULL;
    
  if (!z_object_is_subclass(Z_CLASS(ZProxyIface), compat))
    {
      /*LOG
	This message indicates an internal error, please contact your Zorp support for assistance.
       */
      z_proxy_log(self, CORE_ERROR, 3, "Internal error, trying to look up a non-ZProxyIface compatible interface;");
      return NULL;
    }
  g_static_mutex_lock(&self->interfaces_lock);
  for (p = self->interfaces; p; p = p->next)
    {
      ZObject *obj;
      ZProxyIface *iface;
      
      obj = (ZObject *) p->data;
      if (z_object_is_compatible(obj, compat))
        {
          iface = (ZProxyIface *) z_object_ref(obj);
          g_static_mutex_unlock(&self->interfaces_lock);
          return iface;
        }
    }
  g_static_mutex_unlock(&self->interfaces_lock);
  return NULL;
}

void
z_proxy_var_register_va(ZProxy *s, ZPolicyDict *dict, const gchar *name, guint flags, va_list args)
{
  guint type = Z_VAR_TYPE(flags);
  flags = flags & 0x0f;
  switch (type)
    {
    case Z_VAR_TYPE_INT:
      z_policy_dict_register(dict, 
                             Z_VT_INT, name, flags, va_arg(args, gint *), NULL, 
                             NULL);
      break;
    case Z_VAR_TYPE_STRING:
      z_policy_dict_register(dict, 
                             Z_VT_STRING, name, flags | Z_VF_CONSUME, va_arg(args, GString *), NULL, 
                             NULL);
      break;
    case Z_VAR_TYPE_OBJECT:
      z_policy_dict_register(dict, 
                             Z_VT_OBJECT, name, flags | Z_VF_CONSUME, va_arg(args, ZPolicyObj **), NULL, 
                             NULL);
      break;
    case Z_VAR_TYPE_ALIAS:
      z_policy_dict_register(dict, 
                             Z_VT_ALIAS, name, flags, va_arg(args, gchar *), NULL, 
                             NULL);
      break;
    case Z_VAR_TYPE_OBSOLETE:
      z_policy_dict_register(dict, 
                             Z_VT_ALIAS, name, flags | Z_VF_OBSOLETE, va_arg(args, gchar *), NULL, 
                             NULL);
      break;
    case Z_VAR_TYPE_METHOD:
      {
        gpointer user_data = va_arg(args, gpointer);
        gpointer method = va_arg(args, gpointer);
        z_policy_dict_register(dict, 
                               Z_VT_METHOD, name, flags, method, user_data, NULL, NULL,
                               NULL);
        break;
      }
    case Z_VAR_TYPE_HASH:
      z_policy_dict_register(dict, 
                             Z_VT_HASH, name, flags | Z_VF_CONSUME, va_arg(args, GHashTable *), NULL,
                             NULL);
      break;
    case Z_VAR_TYPE_DIMHASH:
      z_policy_dict_register(dict, 
                             Z_VT_DIMHASH, name, flags | Z_VF_CONSUME, va_arg(args, gpointer), NULL,
                             NULL);
      break;
    case Z_VAR_TYPE_CUSTOM:
      {
        gpointer value = va_arg(args, gpointer);
        gpointer get_value = va_arg(args, gpointer);
        gpointer set_value = va_arg(args, gpointer);
        gpointer free_value = va_arg(args, gpointer);
        
        z_policy_dict_register(dict, 
                               Z_VT_CUSTOM, name, flags, 
                                 value, get_value, set_value, free_value,
                                 s, NULL,                // user_data, user_data_free
                                 NULL,                   // end of CUSTOM args
                               NULL); 
        break;
      }
    default:
      g_assert(0);
      break;

    }
}

void
z_proxy_var_new(ZProxy *self, const gchar *name, guint flags, ...)
{
  va_list(args);

  va_start(args, flags);
  z_proxy_var_register_va(self, self->dict, name, flags, args);
  va_end(args);
}


/**
 * FIXME: we may want to add functions to manipulate self->endpoints and
 * update self->py_endpoints whenever self->endpoints changes. The
 * implementation here basically assumes that whenever self->endpoints
 * changes the Python layer queries proxy.client_stream or
 * proxy.server_stream. If this is not the case the Python layer may use a
 * stale stream.
 **/
static ZPolicyObj *
z_proxy_query_stream(ZProxy *self, gchar *name, gpointer value G_GNUC_UNUSED)
{
  ZPolicyObj *res;
  gint side;

  z_proxy_enter(self);
  if (strcmp(name, "client_stream") == 0)
    {
      side = EP_CLIENT;
    }
  else if (strcmp(name, "server_stream") == 0)
    {
      side = EP_SERVER;
    }
  else
    {
      g_assert_not_reached();
    }
  res = self->py_endpoints[side];
  if (!res)
    {
      /* no stream yet in cache */
      if (self->endpoints[side])
        {
          /* but there is one in C side */
          self->py_endpoints[side] = res = z_policy_stream_new(self->endpoints[side]);
        }
      else
        {
          res = z_policy_none;
        }
    }
  else if (((ZPolicyStream *) res)->stream != self->endpoints[side]) 
    {
      /* the cache is out of sync */
      z_stream_unref(((ZPolicyStream *)res)->stream);
      z_stream_ref(self->endpoints[side]);
      ((ZPolicyStream *)res)->stream = self->endpoints[side];
    }
  z_policy_var_ref(res);
  z_proxy_leave(self);
  return res;
}

/* methods for the ZProxy class */


/**
 * z_proxy_config_method:
 * @self: ZProxy instance
 *
 * This function is referenced as the default config method for the ZProxy
 * class. It calls the "config" method in the policy.
 * Returns FALSE upon failure, and TRUE otherwise.
 **/
gboolean
z_proxy_config_method(ZProxy *self)
{
  z_policy_dict_register(self->dict, Z_VT_INT8, "client_remote_tos", Z_VF_RW, &self->channel_props[EP_CLIENT].tos[EP_DIR_IN], NULL);
  z_policy_dict_register(self->dict, Z_VT_INT8, "client_local_tos", Z_VF_RW, &self->channel_props[EP_CLIENT].tos[EP_DIR_OUT], NULL);
  z_policy_dict_register(self->dict, Z_VT_INT8, "server_remote_tos", Z_VF_RW, &self->channel_props[EP_SERVER].tos[EP_DIR_IN], NULL);
  z_policy_dict_register(self->dict, Z_VT_INT8, "server_local_tos", Z_VF_RW, &self->channel_props[EP_SERVER].tos[EP_DIR_OUT], NULL);

  z_proxy_var_new(self, "language", 
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET_CONFIG | Z_VAR_GET_CONFIG,
                  self->language);
  z_proxy_var_new(self, "client_stream",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, z_proxy_query_stream, NULL, NULL);
  z_proxy_var_new(self, "server_stream",
                  Z_VAR_TYPE_CUSTOM | Z_VAR_GET,
                  NULL, z_proxy_query_stream, NULL, NULL);

  z_proxy_ssl_register_vars(self);

  return z_proxy_policy_config(self);
}

/**
 * z_proxy_startup_method:
 * @self: ZProxy instance
 *
 * This function is referenced as the default startup method for the ZProxy
 * class. It calls the "startup" method in the policy.
 * Returns FALSE upon failure, and TRUE otherwise.
 **/
gboolean
z_proxy_startup_method(ZProxy *self)
{
  return z_proxy_policy_startup(self);
}

/**
 * z_proxy_main_method:
 * @self: ZProxy instance
 *
 * This function is referenced as the default main method for the ZProxy
 * class. Currently it does nothing and should be overriden in descendant
 * classes.
 **/
void
z_proxy_main_method(ZProxy *self G_GNUC_UNUSED)
{
  ;
}

/**
 * z_proxy_shutdown_method:
 * @self: ZProxy instance
 *
 * This function is referenced as the default shutdown method for the ZProxy
 * class. It calls the "shutdown" method in the policy.
 * Returns FALSE upon failure, and TRUE otherwise.
 **/
void
z_proxy_shutdown_method(ZProxy *self)
{
  z_proxy_policy_shutdown(self);
}

/**
 * z_proxy_destroy_method:
 * @self: proxy instance
 *
 * This function is called from proxy implementation when the proxy is to
 * exit. Frees up associated resources, closes streams, etc. Note that the
 * ZProxy instance is not freed immediately as the reference from Python and
 * the caller still exists. z_proxy_destroy() ensures however that circular
 * references are resolved so the proxy will be freed as soon as those
 * references are dropped.
 **/
void
z_proxy_destroy_method(ZProxy *self)
{
  int i;
  ZPolicyObj *handler;
  ZPolicyThread *thread;
  ZPolicyDict *dict;
  GList *ifaces, *p;

  z_proxy_enter(self);
  z_proxy_policy_destroy(self);

  /* this also removes the link to parent */

  z_proxy_set_parent(self, NULL);
  while (self->child_proxies)
    {
      z_proxy_del_child(self, (ZProxy *) self->child_proxies->data);
    }

  g_static_mutex_lock(&self->interfaces_lock);
  ifaces = self->interfaces;
  self->interfaces = NULL;
  g_static_mutex_unlock(&self->interfaces_lock);

  while (ifaces)
    {
      z_object_unref((ZObject *) ifaces->data);
      p = ifaces;
      ifaces = ifaces->next;
      g_list_free_1(p);
    }
  
  z_proxy_unregister(self);

  thread = self->thread;
  if (z_proxy_get_state(self) > ZPS_THREAD_STARTED)
    {  
      for (i = EP_CLIENT; i <= EP_SERVER; i++)
        {
          z_policy_thread_acquire(thread);
          z_policy_var_unref(self->py_endpoints[i]);
          z_policy_thread_release(thread);
          
          if (self->endpoints[i])
            {
              z_stream_shutdown(self->endpoints[i], SHUT_RDWR, NULL);
              z_stream_close(self->endpoints[i], NULL);
              z_stream_unref(self->endpoints[i]);
              self->endpoints[i] = NULL;
            }
        }
      
      z_policy_thread_acquire(thread);
      self->thread = NULL;

      z_proxy_ssl_free_vars(self);

      dict = self->dict;
      self->dict = NULL;
      z_policy_dict_unwrap(dict, self->handler);
      z_policy_dict_destroy(dict);

      handler = self->handler;
      self->handler = NULL;
      z_policy_var_unref(handler);  

      z_policy_thread_release(thread);
    }
  else
    {
      self->thread = NULL;
    }
  z_policy_thread_destroy(thread);
  
  z_proxy_leave(self);
}

/**
 * z_proxy_run_method:
 * @self: ZProxy instance
 *
 * This function is referenced as the default run method for the ZProxy
 * class. It is started by the proxy specific thread and calls the
 * appropriate policy functions (config, startup), then continues by
 * calling z_proxy_main().
 **/
void
z_proxy_run(ZProxy *self)
{
  z_proxy_enter(self);
  if (z_proxy_config(self) &&
      z_proxy_startup(self) &&
      z_proxy_ssl_init_stream(self, EP_CLIENT))
    {
      z_proxy_propagate_channel_props(self);
      z_proxy_main(self);
    }
  z_proxy_shutdown(self);
  z_proxy_destroy(self);
  z_proxy_leave(self);
}

/**
 * z_proxy_thread_func:
 * @s: ZProxy instance as a general pointer
 * 
 * This is the default thread function for proxies. The thread is started
 * in z_proxy_start().
 **/
static gpointer
z_proxy_thread_func(gpointer s)
{
  ZProxy *self = Z_CAST(s, ZProxy);
  
  self->proxy_thread = z_thread_self();
  z_proxy_set_state(self, ZPS_THREAD_STARTED);
  z_proxy_run(self);
  z_proxy_unref(self);
  return NULL;
}

/**
 * z_proxy_threaded_start:
 * @self: ZProxy instance
 *
 * Starts the proxy by creating the new proxy thread. This function
 * is usually called by proxy constructors.
 **/
gboolean
z_proxy_threaded_start(ZProxy *self, ZProxyGroup *proxy_group)
{
  z_proxy_set_group(self, proxy_group);
  z_proxy_ref(self);
  if (!z_thread_new(self->session_id, z_proxy_thread_func, self))
    {
      /*LOG
	This message indicates that Zorp was unable to create a new thread for the new proxy instance.
	It is likely that Zorp reached a thread limit, or not enough resource is available.
       */
      z_proxy_log(self, CORE_ERROR, 2, "Error creating proxy thread;");
      z_proxy_destroy(self);
      z_proxy_unref(self);
      return FALSE;
    }
  return TRUE;
}

gboolean
z_proxy_nonblocking_start(ZProxy *self, ZProxyGroup *proxy_group)
{
  gboolean success;
  
  z_proxy_set_group(self, proxy_group);
  success = z_proxy_config(self) &&
            z_proxy_startup(self) &&
            z_proxy_ssl_init_stream_nonblocking(self, EP_CLIENT);
  return success;
}

void
z_proxy_nonblocking_stop(ZProxy *self)
{
  z_proxy_nonblocking_deinit(self);
  
  z_proxy_shutdown(self);
  z_proxy_destroy(self);
  z_proxy_group_stop_session(self->group, self);
}

/**
 * z_proxy_wakeup:
 * @self: ZProxy instance
 *
 * This function should try its best to wake-up the specified ZProxy
 * instance from sleeping, to check for example the stop-request flag.
 *
 * It currently checks whether the proxy is a non-blocking one, and wakes up
 * the associated poll loop.
 *
 * Proxies might override this function to provide additional wakeup methods.
 *
 * NOTE: this runs in a separate thread
 **/
void
z_proxy_wakeup_method(ZProxy *self)
{
  if ((self->flags & ZPF_NONBLOCKING) != 0)
    z_proxy_group_wakeup(self->group);
}

/**
 * z_proxy_loop_iteration:
 * @s: the proxy instance
 *
 * This function is to be called by proxies in their main loop. Whenever
 * this function returns FALSE the proxy should finish its processing and exit.
 * 
 * It currently calls propagate_channel_props and checks the ZPF_STOP_REQUEST flag.
 *
 * Returns: TRUE if the proxy can continue, FALSE if it has to be stopped
 *
 */
gboolean
z_proxy_loop_iteration(ZProxy *s)
{
  z_proxy_propagate_channel_props(s);

  if (z_proxy_stop_requested(s))
    {
      /*LOG
        A stop request arrived to the proxy. It has to be stopped.
      */
      z_proxy_log(s, CORE_INFO, 2, "User initiated proxy termination request received;");
      return FALSE;
    }
  else
    {
      return TRUE;
    }
}

/**
 * z_proxy_new:
 * @proxy_class: proxy class to instantiate
 * @params: ZProxyParams containing ZProxy parameters
 *
 * This function is to be called from proxy constructors to initialize
 * common fields in the ZProxy struct. 
 *
 * NOTE: unlike in previous versions, z_proxy_new is called with the Python
 * interpreter unlocked, thus it must grab the interpreter lock to create
 * thread specific Python state.
 *
 **/
ZProxy *
z_proxy_new(ZClass *proxy_class, ZProxyParams *params)
{
  ZProxy *self;
  ZProxyIface *iface;
  ZPolicyThread *policy_thread;
  
  z_enter();
  self = Z_NEW_COMPAT(proxy_class, ZProxy);
  
  if (params->client)
    {
      self->endpoints[EP_CLIENT] = params->client;
      z_stream_ref(params->client);
    }

  g_strlcpy(self->session_id, params->session_id, sizeof(self->session_id));
  self->language = g_string_new("en");
  
  
  self->dict = z_policy_dict_new();
  
  iface = (ZProxyIface *) z_proxy_basic_iface_new(Z_CLASS(ZProxyBasicIface), self);
  z_proxy_add_iface(self, iface);
  z_object_unref(&iface->super);
  
  z_python_lock();
  z_policy_dict_wrap(self->dict, params->handler);
  self->handler = params->handler;
  z_policy_var_ref(params->handler);
  policy_thread = z_policy_thread_self();
  self->thread = z_policy_thread_new(policy_thread ? z_policy_thread_get_policy(policy_thread) : current_policy);
  z_python_unlock();

  z_proxy_register(self);
  z_proxy_ssl_config_defaults(self);

  z_proxy_add_child(params->parent, self);
  z_return(self);
}


/**
 * z_proxy_free_method:
 * @self: proxy instance
 *
 * Called when the proxy object is finally to be freed (when the Python layer
 * releases its reference). Calls the proxy specific free function and
 * frees self
 **/
void
z_proxy_free_method(ZObject *s)
{
  ZProxy *self = Z_CAST(s, ZProxy);
  
  z_enter();
  z_proxy_log(self, CORE_DEBUG, 7, "Freeing ZProxy instance;");
  z_proxy_group_unref(self->group);
  z_object_free_method(s);
  z_leave();
}

static ZProxyFuncs z_proxy_funcs =
{
  {
    Z_FUNCS_COUNT(ZProxy),
    z_proxy_free_method,
  },
  .config = z_proxy_config_method,
  .startup = z_proxy_startup_method,
  .main = z_proxy_main_method,
  .shutdown = z_proxy_shutdown_method,
  .destroy = z_proxy_destroy_method,
  .nonblocking_init = NULL,
  .nonblocking_deinit = NULL,
  .wakeup = z_proxy_wakeup_method
};

ZClass ZProxy__class = 
{
  Z_CLASS_HEADER,
  &ZObject__class,
  "ZProxy",
  sizeof(ZProxy),
  &z_proxy_funcs.super,
};

/* ZProxyIface */

/**
 * z_proxy_iface:
 * @class: derived class description
 * @proxy: proxy instance to be associated with this interface
 *
 * Constructor for ZProxyIface objects and derivates. A ZProxyIface
 * class encapsulates a function interface which permits inter-proxy
 * communication. 
 **/
ZProxyIface *
z_proxy_iface_new(ZClass *class, ZProxy *proxy)
{
  ZProxyIface *self;
  
  self = Z_NEW_COMPAT(class, ZProxyIface);
  self->owner = z_proxy_ref(proxy);
  return self;
}

/**
 * z_proxy_iface_free_method:
 * @s: ZProxyIface instance passed as a ZObject pointer
 *
 * Destructor for ZProxyIface objects, frees associated references.
 **/
void
z_proxy_iface_free_method(ZObject *s)
{
  ZProxyIface *self = Z_CAST(s, ZProxyIface);
  
  z_proxy_unref(self->owner);
  self->owner = NULL;
  z_object_free_method(s);
}

ZObjectFuncs z_proxy_iface_funcs =
{
  Z_FUNCS_COUNT(ZObject),
  z_proxy_iface_free_method,
};

ZClass ZProxyIface__class =
{
  Z_CLASS_HEADER,
  Z_CLASS(ZObject),
  "ZProxyIface",
  sizeof(ZProxyIface),
  &z_proxy_iface_funcs
};

/* ZProxyBasicIface */

static gboolean
z_proxy_basic_iface_get_var_method(ZProxyBasicIface *self, const gchar *var_name, gchar **value)
{
  ZPolicyObj *value_obj, *value_str;
  ZProxy *owner = self->owner;
  gboolean success = FALSE;

  z_policy_lock(owner->thread);

  value_obj = z_policy_getattr(owner->handler, (gchar *) var_name);
  if (!value_obj)
    goto exit;

  value_str = z_policy_var_str(value_obj);
  g_assert(z_policy_str_check(value_str));
  *value = g_strdup(z_policy_str_as_string(value_str));
  z_policy_var_unref(value_obj);
  z_policy_var_unref(value_str);

  success = TRUE;
 exit:
  z_policy_unlock(owner->thread);

  return success;
}

static gboolean
z_proxy_basic_iface_set_var_method(ZProxyBasicIface *self G_GNUC_UNUSED, const gchar *var_name G_GNUC_UNUSED, gchar *value G_GNUC_UNUSED)
{
  return FALSE;
}


/**
 * z_proxy_basic_iface_new:
 * @class: class description
 * @proxy: associated proxy
 *
 * Constructor for ZProxyBasicIface class, derived from ZProxyIface.
 **/
ZProxyBasicIface *
z_proxy_basic_iface_new(ZClass *class, ZProxy *proxy)
{
  ZProxyBasicIface *self;
  
  self = (ZProxyBasicIface *) z_proxy_iface_new(class, proxy);
  return self;
}

ZProxyBasicIfaceFuncs z_proxy_basic_iface_funcs =
{
  {
    Z_FUNCS_COUNT(ZObject),
    NULL
  },
  .get_var = z_proxy_basic_iface_get_var_method,
  .set_var = z_proxy_basic_iface_set_var_method,
};

ZClass ZProxyBasicIface__class =
{
  Z_CLASS_HEADER,
  Z_CLASS(ZProxyIface),
  "ZProxyBasicIface",
  sizeof(ZProxyBasicIface),
  &z_proxy_basic_iface_funcs.super
};


ZProxyStackIfaceFuncs z_proxy_stack_iface_funcs =
{
  {
    Z_FUNCS_COUNT(ZObject),
    NULL
  },
  .set_verdict = NULL,
  .get_content_hint = NULL,
  .set_content_hint = NULL
};

ZClass ZProxyStackIface__class =
{
  Z_CLASS_HEADER,
  Z_CLASS(ZProxyIface),
  "ZProxyStackIface",
  sizeof(ZProxyStackIface),
  &z_proxy_stack_iface_funcs.super
};

ZProxyHostIfaceFuncs z_proxy_host_iface_funcs =
{
  {
    Z_FUNCS_COUNT(ZObject),
    .free_fn = NULL
  },
  .check_name = NULL,
};


ZClass ZProxyHostIface__class =
{
  Z_CLASS_HEADER,
  Z_CLASS(ZProxyIface),
  "ZProxyHostIface",
  sizeof(ZProxyHostIface),
  &z_proxy_host_iface_funcs.super
};


