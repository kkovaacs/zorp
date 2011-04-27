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
 * Author  : Bazsi
 * Auditor : 
 * Notes:
 *
 ***************************************************************************/

#include <zorp/proxystack.h>
#include <zorp/streamfd.h>
#include <zorp/streamline.h>
#include <zorp/streambuf.h>
#include <zorp/connect.h>

#include <zorp/pystream.h>
#include <zorp/pyproxy.h>
#include <zorp/pysockaddr.h>

/**
 * z_proxy_stack_prepare_streams:
 * @self: ZProxy instance
 * @downpair:
 * @uppair:
 *
 **/
static gboolean
z_proxy_stack_prepare_streams(ZProxy *self, gint *downpair, gint *uppair)
{
  z_proxy_enter(self);

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, downpair) == -1)
    {
      /*LOG
        This message indicates that stacking a child proxy failed, because
        creating an AF_UNIX domain socketpair failed on the client side.
       */
      z_proxy_log(self, CORE_ERROR, 1, "Error creating client socketpair for stacked proxy; error='%s'", g_strerror(errno));
      z_proxy_leave(self);
      return FALSE;
    }
  else if (socketpair(AF_UNIX, SOCK_STREAM, 0, uppair) == -1)
    {
      close(downpair[0]);
      close(downpair[1]);
      /*LOG
        This message indicates that stacking a child proxy failed, because
        creating an AF_UNIX domain socketpair failed on the server side.
       */
      z_proxy_log(self, CORE_ERROR, 1, "Error creating server socketpair for stacked proxy; error='%s'", g_strerror(errno));
      z_proxy_leave(self);
      return FALSE;
    }
  z_proxy_leave(self);
  return TRUE;
}

/**
 * z_proxy_stack_proxy:
 * @self: proxy instance
 * @proxy_class: a Python class to be instantiated as the child proxy
 *
 * This function is called to start a child proxy.
 **/
gboolean
z_proxy_stack_proxy(ZProxy *self, ZPolicyObj *proxy_class, ZStackedProxy **stacked, ZPolicyDict *stack_info)
{
  int downpair[2], uppair[2];
  ZPolicyObj *res, *client_stream, *server_stream, *stack_info_obj;
  ZStream *tmpstream;
  ZStream *client_upstream, *server_upstream;
  
  z_proxy_enter(self);
  if (proxy_class == z_policy_none)
    { 
      z_policy_var_unref(proxy_class);
      z_proxy_leave(self);
      return FALSE;
    }
  
  if (!z_proxy_stack_prepare_streams(self, downpair, uppair))
    {
      z_policy_var_unref(proxy_class);
      z_proxy_leave(self);
      return FALSE;
    }
  
  /*LOG
    This message reports that Zorp is about to stack a proxy class
    with the given fds as communication channels.
   */
  z_proxy_log(self, CORE_DEBUG, 6, "Stacking subproxy; client='%d:%d', server='%d:%d'", downpair[0], downpair[1], uppair[0], uppair[1]);
  
  tmpstream = z_stream_fd_new(downpair[1], "");
  client_stream = z_policy_stream_new(tmpstream);
  z_stream_unref(tmpstream);
  
  tmpstream = z_stream_fd_new(uppair[1], "");
  server_stream = z_policy_stream_new(tmpstream);
  z_stream_unref(tmpstream);

  if (stack_info)
    {
      stack_info_obj = z_policy_struct_new(stack_info, Z_PST_SHARED);
    }
  else
    {
      Py_XINCREF(Py_None);
      stack_info_obj = Py_None;
    }

  res = z_policy_call(self->handler, "stackProxy", z_policy_var_build("(OOOO)", client_stream, server_stream, proxy_class, stack_info_obj),
                        NULL, self->session_id);
  
  z_policy_var_unref(client_stream);
  z_policy_var_unref(server_stream);
  z_policy_var_unref(stack_info_obj);
  
  if (!res || res == z_policy_none || !z_policy_proxy_check(res))
    {
      z_proxy_log(self, CORE_ERROR, 3, "Error stacking subproxy;");
      close(downpair[0]);
      close(downpair[1]);
      close(uppair[0]);
      close(uppair[1]);
      z_policy_var_unref(res);
      z_proxy_leave(self);
      return FALSE;
    }

  client_upstream = z_stream_fd_new(downpair[0], "");
  server_upstream = z_stream_fd_new(uppair[0], "");
  *stacked = z_stacked_proxy_new(client_upstream, server_upstream, NULL, self, z_policy_proxy_get_proxy(res), 0);
  z_policy_var_unref(res);
  
  z_proxy_leave(self);
  return TRUE;
}

static gboolean
z_proxy_stack_fds(ZProxy *self, gint client_fd, gint server_fd, gint control_fd, ZStackedProxy **stacked, guint32 flags)
{
  ZStream *client_upstream, *server_upstream, *control_stream = NULL;

  z_proxy_enter(self);
  client_upstream = z_stream_fd_new(client_fd, "");
  server_upstream = z_stream_fd_new(server_fd, "");
  if (control_fd != -1)
    control_stream = z_stream_fd_new(control_fd, "");

  *stacked = z_stacked_proxy_new(client_upstream, server_upstream, control_stream, self, NULL, flags);
  
  z_proxy_leave(self);
  return TRUE;
}






/**
 * z_proxy_stack_program:
 * @self: proxy instance
 * @program: path to program to execute
 *
 * This function is called to start a program as a filtering child proxy.
 **/
static gboolean
z_proxy_stack_program(ZProxy *self, const gchar *program, ZStackedProxy **stacked)
{
  int downpair[2], uppair[2], controlpair[2];
  pid_t pid;
  
  z_proxy_enter(self);

  if (!z_proxy_stack_prepare_streams(self, downpair, uppair))
    {
      z_proxy_leave(self);
      return FALSE;
    }

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, controlpair) < 0)
    {
      close(downpair[0]);
      close(downpair[1]);
      close(uppair[0]);
      close(uppair[1]);
      close(controlpair[0]);
      close(controlpair[1]);
      /*LOG
        This message indicates that stacking a child proxy failed, because
        creating an AF_UNIX domain socketpair failed for the control
        channel.
       */
      z_proxy_log(self, CORE_ERROR, 1, "Error creating control socketpair for stacked proxy; error='%s'", g_strerror(errno));
      z_proxy_leave(self);
      return FALSE;
    }
  
  /*LOG
    This message reports that Zorp is about to stack a program
    with the given fds as communication channels.
   */
  z_proxy_log(self, CORE_DEBUG, 6, "Stacking program; client='%d:%d', server='%d:%d', control='%d:%d', program='%s'", 
              downpair[0], downpair[1], uppair[0], uppair[1], controlpair[0], controlpair[1], program);
 
  pid = fork();

  if (pid == 0)
    {
      int i;
      /* child */
      
      dup2(downpair[1], 0);
      dup2(uppair[1], 1);
      /* standard error is inherited */
      dup2(controlpair[1], 3);
      
      for (i = 4; i < sysconf(_SC_OPEN_MAX); i++)
        close(i);
      execl("/bin/sh", "/bin/sh", "-c", program, NULL);
      fprintf(stderr, "Error starting program; program='%s', error='%s'", program, strerror(errno));
      exit(127);
    }
  else if (pid < 0)
    {
      z_proxy_log(self, CORE_ERROR, 2, "Program stacking failed, fork returned error; program='%s', error='%s'", program, g_strerror(errno));

      close(downpair[0]);
      close(downpair[1]);
      close(uppair[0]);
      close(uppair[1]);
      close(controlpair[0]);
      close(controlpair[1]);
      z_proxy_leave(self);
      return FALSE;
    }

  close(downpair[1]);
  close(uppair[1]);
  close(controlpair[1]);
  if (!z_proxy_stack_fds(self, downpair[0], uppair[0], controlpair[0], stacked, 0))
    {
      z_proxy_leave(self);
      return FALSE;
    }
  z_proxy_leave(self);
  return TRUE;
}


static gboolean
z_proxy_stack_tuple(ZProxy *self, ZPolicyObj *tuple, ZStackedProxy **stacked, ZPolicyDict *stack_info_dict)
{
  guint stack_method;
  ZPolicyObj *arg = NULL;
  gboolean success = FALSE;
  ZSockAddr *sa;
  const gchar *stack_info, *provider_name;
  
  if (!z_policy_tuple_get_verdict(tuple, &stack_method) ||
      z_policy_seq_length(tuple) < 2)
    goto invalid_tuple;

  arg = z_policy_seq_getitem(tuple, 1);
  switch (stack_method)
    {
    case Z_STACK_PROXY:
      if (z_policy_seq_length(tuple) != 2)
        goto invalid_tuple;

      success = z_proxy_stack_proxy(self, arg, stacked, stack_info_dict);
      break;
    case Z_STACK_PROGRAM:
      if (!z_policy_str_check(arg))
        goto invalid_tuple;

      success = z_proxy_stack_program(self, z_policy_str_as_string(arg), stacked);
      break;

    default:
      break;
    }
    
 exit:
  if (arg)
    z_policy_var_unref(arg);
  return success;

 invalid_tuple:
  z_proxy_log(self, CORE_POLICY, 1, "Invalid stack tuple;");
  success = FALSE;
  goto exit;
}


/**
 * z_proxy_stack_object:
 * @self: ZProxy instance
 * @stack_obj: Python object to be stacked
 *
 * This function is a more general interface than
 * z_proxy_stack_proxy/z_proxy_stack_object it first decides how the
 * specified Python object needs to be stacked, performs stacking and
 * returns the stacked proxy.
 **/
gboolean
z_proxy_stack_object(ZProxy *self, ZPolicyObj *stack_obj, ZStackedProxy **stacked, ZPolicyDict *stack_info)
{
  *stacked = NULL;
  if (z_policy_str_check(stack_obj))
    return z_proxy_stack_program(self, z_policy_str_as_string(stack_obj), stacked);
  else 
  if (z_policy_seq_check(stack_obj))
    return z_proxy_stack_tuple(self, stack_obj, stacked, stack_info);
  else
    return z_proxy_stack_proxy(self, stack_obj, stacked, stack_info);
}


/* stacked proxy */

static inline ZStackedProxy *
z_stacked_proxy_ref(ZStackedProxy *self)
{
  z_refcount_inc(&self->ref_cnt);
  return self;
}

static void
z_stacked_proxy_unref(ZStackedProxy *self)
{
  if (self && z_refcount_dec(&self->ref_cnt))
    {
      g_free(self);
    }
}

/** 
 * z_stacked_proxy_new:
 * @client_stream: client side stream
 * @server_stream: server side stream
 * @control_stream: control stream
 * @proxy: ZProxy instance which initiated stacking
 * @child_proxy: ZProxy instance of the 'child' proxy
 * 
 * This function creates a new ZStackedProxy instance encapsulating
 * information about a stacked proxy instance. This information can be freed
 * by calling z_stacked_proxy_destroy().  It consumes the stream references
 * passed to it (client, server) but does not consume the proxy
 * references (@proxy and @child_proxy)
 **/
ZStackedProxy *
z_stacked_proxy_new(ZStream *client_stream, ZStream *server_stream, ZStream *control_stream G_GNUC_UNUSED, ZProxy *proxy, ZProxy *child_proxy, guint32 flags)
{
  ZStackedProxy *self = g_new0(ZStackedProxy, 1);
  gchar buf[Z_STREAM_MAX_NAME];
  
  z_proxy_enter(proxy);
  
  z_refcount_set(&self->ref_cnt, 1);
  self->flags = flags;

  if (client_stream)
    {
      z_stream_set_nonblock(client_stream, TRUE);

      g_snprintf(buf, sizeof(buf), "%s/client_downstream", proxy->session_id);
      z_stream_set_name(client_stream, buf);
      self->downstreams[EP_CLIENT] = client_stream;
    }
  
  if (server_stream)
    {
      z_stream_set_nonblock(server_stream, TRUE);
  
      g_snprintf(buf, sizeof(buf), "%s/server_downstream", proxy->session_id);
      z_stream_set_name(server_stream, buf);
      self->downstreams[EP_SERVER] = server_stream;
    }

  self->proxy = z_proxy_ref(proxy);
  if (child_proxy)
    self->child_proxy = z_proxy_ref(child_proxy);


   
  z_proxy_leave(proxy);
  return self;
}


/**
 * z_stacked_proxy_destroy:
 * @self: ZStackedProxy instance
 *
 * This function frees all references associated with a stacked proxy.
 **/
void
z_stacked_proxy_destroy(ZStackedProxy *self)
{
  gint i;

  z_enter();
  g_static_mutex_lock(&self->destroy_lock);
  self->destroyed = TRUE;
  if (self->control_stream)
    {
      z_stream_detach_source(self->control_stream);
      z_stream_shutdown(self->control_stream, SHUT_RDWR, NULL);
      z_stream_close(self->control_stream, NULL);
      z_stream_unref(self->control_stream);
      self->control_stream = NULL;
    }

  /* no callbacks after this point, thus the control stream callback
   * does not need a reference */
  for (i = 0; i < EP_MAX; i++)
    {
      if (self->downstreams[i])
        {
          z_stream_shutdown(self->downstreams[i], SHUT_RDWR, NULL);
          z_stream_close(self->downstreams[i], NULL);
          z_stream_unref(self->downstreams[i]);
          self->downstreams[i] = NULL;
        }
    }

  
  if (self->child_proxy)
    {
      z_proxy_del_child(self->proxy, self->child_proxy);
      z_proxy_unref(self->child_proxy);
      self->child_proxy = NULL;
    }
  if (self->proxy)
    {
      z_proxy_unref(self->proxy);
      self->proxy = NULL;
    }
  g_static_mutex_unlock(&self->destroy_lock);
  z_stacked_proxy_unref(self);
  z_return();
}

