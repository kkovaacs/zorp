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
 * $Id: ftp.c,v 1.281 2004/07/23 09:36:59 sasa Exp $
 *
 * Author:  Andras Kis-Szabo <kisza@sch.bme.hu>
 * Author:  Attila SZALAY <sasa@balabit.hu>
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include "ftp.h"

#include <zorp/zorp.h>
#include <zorp/registry.h>
#include <zorp/sockaddr.h>
#include <zorp/pysockaddr.h>
#include <zorp/policy.h>
#include <zorp/log.h>
#include <zorp/thread.h>
#include <zorp/io.h>
#include <zorp/streamfd.h>
#include <zorp/streamssl.h>
#include <zorp/proxysslhostiface.h>
#include <zorp/pystream.h>
#include <zorp/pyproxy.h>
#include <zorp/attach.h>

#include <ctype.h>
#include <assert.h>

/* FIXMEE
 * Correcting the read and write error handling
 */

#define SIDE_TO_STRING(side) side == EP_CLIENT ? "client" : side == EP_SERVER ? "server" : "unknown"

GHashTable *ftp_command_hash = NULL;
GHashTable *ftp_answer_hash  = NULL;

void ftp_data_reset(FtpProxy *self);
gboolean ftp_data_abort(FtpProxy *self);
gboolean ftp_stream_write(FtpProxy *self,
                          char     side,
                          guchar   *line,
                          guint    length);
void ftp_proxy_free(ZObject *s);

void ftp_command_reject(FtpProxy *self);

gboolean ftp_answer_write(FtpProxy *self, gchar *msg);
gboolean ftp_command_write_setup(FtpProxy *self, gchar *answer_c, gchar *answer_p);
gboolean ftp_command_write(FtpProxy *self, char *msg);

static gboolean
ftp_connect_server_event(FtpProxy *self, gchar *hostname, guint port)
{
  ZSockAddr *client_local, *server_local;
  gchar tmpip[16];
  
  z_proxy_enter(self);
  if (!z_proxy_connect_server(&self->super, hostname, port))
    {
      /* There's no need to log, because we trust, that the called
       * funcion log in every cases.
       */
      z_proxy_return(self, FALSE);
    }

  /*
    This must be after connect server event because we want to
    wait for all router, and NATs to change addresses.
    We set up the address pools, where we link to connect and accept
    sockaddrs.
   */
  if (!z_proxy_get_addresses(&self->super, NULL, NULL, &client_local, NULL, &server_local, NULL))
    z_proxy_return(self, FALSE);
  
  /* This cannot hapen, because we connected in each side */
  g_assert(client_local != NULL && server_local != NULL);
  z_inet_ntoa(tmpip, sizeof(tmpip), ((struct sockaddr_in *) &client_local->sa)->sin_addr);
  self->server_port = ntohs(((struct sockaddr_in *) &client_local->sa)->sin_port);
  if (self->data_port_min && self->data_port_max)
    self->data_local_buf[EP_CLIENT] = z_sockaddr_inet_range_new(tmpip, self->data_port_min, self->data_port_max);
  else
    self->data_local_buf[EP_CLIENT] = z_sockaddr_inet_new(tmpip, 0);

  g_assert(self->data_local_buf[EP_CLIENT]);
  z_inet_ntoa(tmpip, sizeof(tmpip), ((struct sockaddr_in *) &server_local->sa)->sin_addr);
  if (self->data_port_min != 0 && self->data_port_max != 0)
    self->data_local_buf[EP_SERVER] = z_sockaddr_inet_range_new(tmpip, self->data_port_min, self->data_port_max);
  else
    self->data_local_buf[EP_SERVER] = z_sockaddr_inet_new(tmpip, 0);

  g_assert(self->data_local_buf[EP_SERVER]);
  z_sockaddr_unref(client_local);
  z_sockaddr_unref(server_local);
  z_proxy_return(self, TRUE);
}

void
ftp_state_set(FtpProxy *self, guint order)
{
  z_proxy_enter(self);
  z_stream_set_cond(self->super.endpoints[order], G_IO_IN, TRUE);
  z_stream_set_cond(self->super.endpoints[1 - order], G_IO_IN, FALSE);
  z_proxy_return(self);
}

void
ftp_state_both(FtpProxy *self)
{
  z_proxy_enter(self);
  z_stream_set_cond(self->super.endpoints[EP_CLIENT], G_IO_IN, TRUE);
  z_stream_set_cond(self->super.endpoints[EP_SERVER], G_IO_IN, TRUE);
  z_proxy_return(self);
}

static gboolean
ftp_data_client_accepted(ZConnection *conn, gpointer user_data)
{
  FtpProxy *self = (FtpProxy *) user_data;
  
  z_proxy_enter(self);
  if (self->data_stream[EP_CLIENT] || self->data_state == FTP_DATA_CANCEL)
    z_proxy_return(self, FALSE);
  
  g_mutex_lock(self->lock);
  if (conn && conn->stream)
    {
      gchar tmp_sockaddr[120];
      
      /*LOG
        This message reports that the data connection is accepted from the client.
       */
      z_proxy_log(self, FTP_SESSION, 5, "Data connection accepted on client side; address='%s'", z_sockaddr_format(conn->remote, tmp_sockaddr, sizeof(tmp_sockaddr)));
      self->data_stream[EP_CLIENT] = z_stream_ref(conn->stream);
      self->data_remote[EP_CLIENT] = z_sockaddr_ref(conn->remote);
      self->data_state |= FTP_DATA_CLIENT_READY;
    }
  else
    {
      self->data_stream[EP_CLIENT] = NULL;
      self->data_remote[EP_CLIENT] = NULL;
      self->data_state = FTP_DATA_CANCEL;
      self->state = FTP_QUIT;
      self->ftp_data_hangup = TRUE;
    }

  if (conn)
    z_connection_destroy(conn, FALSE);

  g_mutex_unlock(self->lock);
  z_poll_wakeup(self->poll);
  z_proxy_return(self, TRUE);
}

static gboolean
ftp_data_server_accepted(ZConnection *conn, gpointer user_data)
{
  FtpProxy *self = (FtpProxy *) user_data;
  
  z_proxy_enter(self);
  if (self->data_stream[EP_SERVER] || self->data_state == FTP_DATA_CANCEL)
    z_proxy_return(self, FALSE);
  
  g_mutex_lock(self->lock);
  if (conn && conn->stream)
    {
      gchar tmp_sockaddr[120];
      
      /*LOG
        This message reports that the data connection is accepted from the server.
       */
      z_proxy_log(self, FTP_SESSION, 5, "Data connection accepted on server side; address='%s'", z_sockaddr_format(conn->remote, tmp_sockaddr, sizeof(tmp_sockaddr)));
      self->data_stream[EP_SERVER] = z_stream_ref(conn->stream);
      self->data_remote[EP_SERVER] = z_sockaddr_ref(conn->remote);
      self->data_state |= FTP_DATA_SERVER_READY;
    }
  else
    {
      self->data_stream[EP_SERVER] = NULL;
      self->data_remote[EP_SERVER] = NULL;
      self->data_state = FTP_DATA_CANCEL;
      self->state = FTP_QUIT;
      self->ftp_data_hangup = TRUE;
    }

  if (conn)
    z_connection_destroy(conn, FALSE);

  g_mutex_unlock(self->lock);
  z_poll_wakeup(self->poll);
  z_proxy_return(self, TRUE);
}

void
ftp_data_client_connected(ZConnection *conn, gpointer user_data)
{
  FtpProxy *self = (FtpProxy *) user_data;
  
  z_proxy_enter(self);
  g_mutex_lock(self->lock);
  if (!(self->data_state & FTP_DATA_CLIENT_READY) &&
      self->data_state != FTP_DATA_CANCEL &&
      self->data_state != FTP_DATA_DESTROY)
    {
      if (conn && conn->stream)
        {
          gchar tmp_sockaddr[120];
      
          /*LOG
            This message reports that the data connection is established to the client.
           */
          z_proxy_log(self, FTP_SESSION, 5, "Data connection established on client side; address='%s'", z_sockaddr_format(conn->remote, tmp_sockaddr, sizeof(tmp_sockaddr)));
          self->data_stream[EP_CLIENT] = z_stream_ref(conn->stream);

          z_sockaddr_unref(self->data_remote[EP_CLIENT]);
          self->data_remote[EP_CLIENT] = z_sockaddr_ref(conn->remote);
  
          self->data_state |= FTP_DATA_CLIENT_READY;
        }
      else
        {
          /* We assume that lower level log if problem occured */
          self->data_state = FTP_DATA_DESTROY;
          self->state = FTP_QUIT;
          self->ftp_data_hangup = TRUE;
        }
      
      if (conn)
        {
          z_connection_destroy(conn, FALSE);
          conn = NULL;
        }
      z_poll_wakeup(self->poll);
    }
  g_mutex_unlock(self->lock);

  if (conn)
    {
      /*LOG
        This message indicates that the data connection is established to the client, but the no connection is expected or
        the connection is canceled meanwhile.
       */
      z_proxy_log(self, FTP_ERROR, 4, "Connected to client, but connection is not expected; state='%ld'", self->data_state);
      z_connection_destroy(conn, TRUE);
    }
  z_proxy_return(self);
}

void
ftp_data_server_connected(ZConnection *conn, gpointer user_data)
{
  FtpProxy *self = (FtpProxy *) user_data;
  
  z_proxy_enter(self);
  g_mutex_lock(self->lock);
  if (!(self->data_state & FTP_DATA_SERVER_READY) &&
      self->data_state != FTP_DATA_CANCEL &&
      self->data_state != FTP_DATA_DESTROY)
    {
      if (conn && conn->stream)
        {
          gchar tmp_sockaddr[120];
      
          /*LOG
            This message reports that the data connection is established to the server.
           */
          z_proxy_log(self, FTP_SESSION, 5, "Data connection established on server side; address='%s'", z_sockaddr_format(conn->remote, tmp_sockaddr, sizeof(tmp_sockaddr)));
          self->data_stream[EP_SERVER] = z_stream_ref(conn->stream);

          z_sockaddr_unref(self->data_remote[EP_SERVER]);
          self->data_remote[EP_SERVER] = z_sockaddr_ref(conn->remote);
  
          self->data_state |= FTP_DATA_SERVER_READY;
        }
      else
        {
          /* We assume that lower level log, if problem occured */
          self->data_state = FTP_DATA_DESTROY;
          self->state = FTP_SERVER_TO_CLIENT;   /* not considered fatal */
        }
  
      z_poll_wakeup(self->poll);
      if (conn)
        {
          z_connection_destroy(conn, FALSE);
          conn = NULL;
        }
    }
  g_mutex_unlock(self->lock);

  if (conn)
    {
      /*LOG
        This message indicates that the data connection is established to the server, but the no connection is expected or
        the connection is canceled meanwhile.
       */
      z_proxy_log(self, FTP_ERROR, 4, "Connected to server, but connection is not expected; state='%ld'", self->data_state);
      z_connection_destroy(conn, TRUE);
    }
  
  z_proxy_return(self);
}

ZAttachCallbackFunc data_attach_callbacks[] =
{
  ftp_data_client_connected, 
  ftp_data_server_connected
};

ZDispatchCallbackFunc data_accept_callbacks[] =
{
  ftp_data_client_accepted, 
  ftp_data_server_accepted
};

gboolean
ftp_data_prepare(FtpProxy *self, gint side, gchar mode)
{
  ZDispatchParams dpparam;
  ZDispatchBind *db;
  ZAttachParams aparam;
  ZSockAddr *tmpaddr;
  gchar tmpip[16];

  z_proxy_enter(self);
  /* FIXMEE Correct handling of not freed streams! */
  self->data_stream[side] = NULL;
  if (mode == 'L')
    {
      memset(&dpparam, 0, sizeof(dpparam));
      dpparam.tcp.accept_one = FALSE;
      dpparam.tcp.backlog = 1;
      dpparam.common.mark_tproxy = TRUE;
      z_proxy_ref(&self->super);
      if (self->data_listen[side] != NULL)
        {
          /*LOG
            This message indicates that the previous data connection was not
            completely teared down and a new one is about to accept.
            This message indicates an internal error, please contact the BalaBit QA team.
           */
          z_proxy_log(self, FTP_ERROR, 3, "Internal error, previous dispatcher not unregistered; side='%s', mode='%c'", SIDE_TO_STRING(side), mode);
          z_dispatch_unregister(self->data_listen[side]);
        }

      db = z_dispatch_bind_new_sa(ZD_PROTO_TCP, self->data_local_buf[side]);
      self->data_listen[side] = z_dispatch_register(self->super.session_id,
                                                    db,
                                                    &tmpaddr,
                                                    ZD_PRI_RELATED,
                                                    &dpparam,
                                                    data_accept_callbacks[side],
                                                    self,
                                                    (GDestroyNotify)z_proxy_unref);
      z_dispatch_bind_unref(db);
      if (!self->data_listen[side])
        {
          /* We assume that lower level log if problem occured */
          z_proxy_unref(&self->super);
          z_proxy_return(self, FALSE);
        }
      self->data_local[side] = tmpaddr;
      
      if (self->data_connect[side])
        {
          /*LOG
            This message indicates that the previous data connection was not
            completely teared down while a new connection is being
            established. This message indicates an internal error, please
            contact the BalaBit QA team.
           */
          z_proxy_log(self, FTP_ERROR, 3, "Internal error, previous attach not unregistered; side='%s', mode='%c'", SIDE_TO_STRING(side), mode);
          z_attach_cancel(self->data_connect[side]);
          z_attach_free(self->data_connect[side]);
          self->data_connect[side] = NULL;
        }
    }
  else if (mode == 'C')
    {
      if (side == EP_CLIENT)
        {
          guint port;
          tmpaddr = self->data_local_buf[side];
          z_inet_ntoa(tmpip, sizeof(tmpip), ((struct sockaddr_in *) &tmpaddr->sa)->sin_addr);
          switch (self->active_connection_mode)
            {
            case FTP_ACTIVE_TWENTY:
              port = 20;
              break;
              
            case FTP_ACTIVE_RANDOM:
              port = 0;
              break;
              
            case FTP_ACTIVE_MINUSONE:
            default:
              port = self->server_port - 1;
            }
          self->data_local[side] = z_sockaddr_inet_new(tmpip, port);
        }
      else
        {
          self->data_local[side] = z_sockaddr_ref(self->data_local_buf[side]);
        }
        
      memset(&aparam, 0, sizeof(aparam));
      aparam.timeout = -1;
      if (self->data_connect[side] != NULL)
        {
          /*LOG
            This message indicates that the previous data connection was not
            completely teared down and a new one is being established.
            This message indicates an internal error, please contact the BalaBit QA team.
           */
          z_proxy_log(self, FTP_ERROR, 3, "Internal error, previous attach not unregistered; side='%s', mode='%c'", SIDE_TO_STRING(side), mode);
          z_attach_cancel(self->data_connect[side]);
          z_attach_free(self->data_connect[side]);
        }
      z_proxy_ref(&self->super);
      self->data_connect[side] = z_attach_new(&self->super,
                                              ZD_PROTO_TCP,
                                              self->data_local[side],
                                              self->data_remote[side],
                                              &aparam,
                                              data_attach_callbacks[side],
                                              self,
                                              (GDestroyNotify) z_proxy_unref);

      z_sockaddr_unref(self->data_local[side]);
      self->data_local[side] = NULL;
      if (!self->data_connect[side])
        {
          /* We assume that lower level log if problem accured */
          z_proxy_unref(&self->super);
          z_proxy_leave(self);
          return FALSE;
        }

      if (self->data_listen[side])
        {
          /*LOG
            This message indicates that the previous data connection was not
            completely teared down and a new one is about to accept.
            This message indicates an internal error, please contact the BalaBit QA team.
           */
          z_proxy_log(self, FTP_ERROR, 3, "Internal error, previous dispatcher not unregistered; side='%s', mode='%c'", SIDE_TO_STRING(side), mode);
          z_dispatch_unregister(self->data_listen[side]);
          self->data_listen[side] = NULL;
        }
    }
  z_proxy_return(self, TRUE);
}

void
ftp_data_reset(FtpProxy *self)
{
  z_proxy_enter(self);
  /*LOG
    This message indicates that the data connection is going to be
    destroyed.
   */
  z_proxy_log(self, FTP_DEBUG, 6, "Resetting data connection; state='%d', oldstate='%d'", self->state, self->oldstate);
  if (self->data_connect[EP_CLIENT])
    {
      z_attach_cancel(self->data_connect[EP_CLIENT]);
      z_attach_free(self->data_connect[EP_CLIENT]);
      self->data_connect[EP_CLIENT] = NULL;
    }
  
  if (self->data_connect[EP_SERVER])
    {
      z_attach_cancel(self->data_connect[EP_SERVER]);
      z_attach_free(self->data_connect[EP_SERVER]);
      self->data_connect[EP_SERVER] = NULL;
    }
  
  if (self->data_listen[EP_CLIENT])
    {
      z_dispatch_unregister(self->data_listen[EP_CLIENT]);
      self->data_listen[EP_CLIENT] = NULL;
    }
  
  if (self->data_listen[EP_SERVER])
    {
      z_dispatch_unregister(self->data_listen[EP_SERVER]);
      self->data_listen[EP_SERVER] = NULL;
    }

  if (self->data_stream[EP_CLIENT])
    {
      z_stream_shutdown(self->data_stream[EP_CLIENT], SHUT_RDWR, NULL);
      z_stream_close(self->data_stream[EP_CLIENT], NULL);
      z_stream_unref(self->data_stream[EP_CLIENT]);
      self->data_stream[EP_CLIENT] = NULL;
    }
  
  if (self->data_stream[EP_SERVER])
    {
      z_stream_shutdown(self->data_stream[EP_SERVER], SHUT_RDWR, NULL);
      z_stream_close(self->data_stream[EP_SERVER], NULL);
      z_stream_unref(self->data_stream[EP_SERVER]);
      self->data_stream[EP_SERVER] = NULL;
    }
  
  g_mutex_lock(self->lock);
  
  if (self->data_remote[EP_CLIENT])
    {
      z_sockaddr_unref(self->data_remote[EP_CLIENT]);
      self->data_remote[EP_CLIENT] = NULL;
    }
  
  if (self->data_remote[EP_SERVER])
    {
      z_sockaddr_unref(self->data_remote[EP_SERVER]);
      self->data_remote[EP_SERVER] = NULL;
    }
  
  if (self->data_local[EP_CLIENT])
    {
      z_sockaddr_unref(self->data_local[EP_CLIENT]);
      self->data_local[EP_CLIENT] = NULL;
    }
  
  if (self->data_local[EP_SERVER])
    {
      z_sockaddr_unref(self->data_local[EP_SERVER]);
      self->data_local[EP_SERVER] = NULL;
    }

  self->data_state = 0;
  g_mutex_unlock(self->lock);

  if (self->transfer)
    {
      z_transfer2_cancel(self->transfer);
      self->transfer = NULL;
    }

  z_stream_set_cond(self->super.endpoints[EP_CLIENT],
                   G_IO_PRI,
                   FALSE);

  if (self->ftp_data_hangup)
    {
      ftp_answer_write(self, "421 Logoff");
      self->ftp_data_hangup = FALSE;
    }

  if (self->preamble)
    {
      g_free(self->preamble);
      self->preamble = NULL;
    }

  if (self->state != FTP_QUIT)
    {
      switch(self->oldstate)
        {
          case FTP_SERVER_TO_CLIENT:
            ftp_state_set(self, EP_SERVER);
            self->state = self->oldstate;
            break;
            
          case FTP_CLIENT_TO_SERVER:
            ftp_state_set(self, EP_CLIENT);
            self->state = self->oldstate;
            break;
            
          default:
            break;
        }
    }
  self->oldstate = 0;
  z_proxy_return(self);
}

void
ftp_data_start(FtpProxy *self)
{
  z_proxy_enter(self);
  if (self->data_state & FTP_DATA_COMMAND_START)
    {
      /*LOG
        This message indicates an internal error that a previous data connection was not
        completed successfully. This condition should not occur, though the
        event is harmless, an explicit data reset clears this state.
        Please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 3, "Internal error, previous data connection is not closed properly; data_state='%lx", self->data_state);
      ftp_data_reset(self);
    }
  self->data_state |= FTP_DATA_COMMAND_START;

  z_stream_set_cond(self->super.endpoints[EP_CLIENT],
                   G_IO_IN,
                   FALSE);
  z_stream_set_cond(self->super.endpoints[EP_CLIENT],
                   G_IO_PRI,
                   TRUE);
  z_proxy_return(self);
}

static gboolean
ftp_data_do_ssl_handshake(FtpProxy *self, gint side)
{
  gboolean rc = TRUE;

  z_proxy_enter(self);

  /* require SSL if:
   * - we're using FTPS and the protection level is private
   * - the proxy requires SSL on this side
   */
  if ((self->data_protection_enabled[side])
      || self->super.ssl_opts.security[side] == PROXY_SSL_SEC_FORCE_SSL)
    {
      ZProxySSLHandshake *handshake;
      ZStream *old;

      /* push an SSL stream on */
      old = self->data_stream[side];
      self->data_stream[side] = z_stream_ssl_new(old, NULL);
      z_stream_unref(old);

      /* do handshake */
      handshake = z_proxy_ssl_handshake_new(&self->super, self->data_stream[side], side);

      rc = z_proxy_ssl_perform_handshake(handshake);
      if (!handshake->session)
        rc = FALSE;

      z_proxy_ssl_handshake_unref(handshake);
    }

  z_proxy_return(self, rc);
}

static gboolean
ftp_data_create_transfer(FtpProxy *self)
{
  gboolean rc = TRUE;
  ZStream *streams[EP_MAX];
  gint first_side;
  gchar tmpsaddr_client[120];
  gchar tmpsaddr_server[120];

  z_proxy_enter(self);
  if (!self->data_stream[EP_CLIENT] || !self->data_stream[EP_SERVER])
    {
      /*LOG
        This message indicates an internal error that the proxy is unable to
        start a stacked data proxy because either the data connection to the
        FTP client or the FTP server is not yet established.
        Please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 2, "Internal error, cannot start data proxy because peers are not yet connected;");
      z_proxy_return(self, FALSE);
    }

  /* do SSL handshake if required */
  if (self->super.ssl_opts.handshake_seq == PROXY_SSL_HS_CLIENT_SERVER)
    first_side = EP_CLIENT;
  else
    first_side = EP_SERVER;

  rc = ftp_data_do_ssl_handshake(self, first_side);
  if (rc)
    rc = ftp_data_do_ssl_handshake(self, EP_OTHER(first_side));

  if (!rc)
    {
      z_proxy_log(self, FTP_ERROR, 3, "SSL handshake failed on data connection, cannot start transfer;");
      z_proxy_return(self, FALSE);
    }

  if (self->command_desc && self->command_desc->need_data == 2) /* data: cli -> svr */
    {
      streams[EP_CLIENT] = self->data_stream[EP_CLIENT];
      streams[EP_SERVER] = self->data_stream[EP_SERVER];
    }
  else if (self->command_desc && self->command_desc->need_data == 1) /* data: svr -> cli */
    {
      streams[EP_CLIENT] = self->data_stream[EP_SERVER];
      streams[EP_SERVER] = self->data_stream[EP_CLIENT];
    }
  else
    {
      /*LOG
        This message indicates an internal error that the current command
        descriptor changed while the data connection was being set up, thus
        we are unable to know which direction is permitted during data
        transfer. Please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 2, "Internal error, current command descriptor does not specify data transfer;");
      z_proxy_leave(self);
      return FALSE;
    }
  self->data_stream[EP_SERVER] = NULL;
  self->data_stream[EP_CLIENT] = NULL;
  
  /*LOG
    This message reports that data connection is established between the client and the server, and proxy
    is being stacked for the data transfer.
   */
  z_proxy_log(self, FTP_SESSION, 4, "Data connection established; client_type='%s', client_address='%s', server_type='%s', server_address='%s', flow='%s'",
              self->data_listen[EP_CLIENT] ? "passive" : "active", z_sockaddr_format(self->data_remote[EP_CLIENT], tmpsaddr_client, sizeof(tmpsaddr_client)),
              self->data_connect[EP_SERVER] ? "passive" : "active", z_sockaddr_format(self->data_remote[EP_SERVER], tmpsaddr_server, sizeof(tmpsaddr_server)),
              self->command_desc->need_data == 1 ? "download" : self->command_desc->need_data == 2 ? "upload" : "unknown");

  if (!ftp_data_transfer(self, streams[EP_CLIENT], streams[EP_SERVER]))
    {
      ftp_command_reject(self);
      self->drop_answer = TRUE;
    }

  ftp_data_reset(self);
  z_proxy_return(self, rc);
}

static void
ftp_data_next_step(FtpProxy *self)
{
  gchar buf[4096];

  z_proxy_enter(self);
  g_mutex_lock(self->lock);
  z_proxy_trace(self, "data_state = '%lx'", self->data_state);
  if ((self->data_state & FTP_DATA_COMMAND_START) &&
      !(self->data_state & FTP_DATA_SERVER_START))
    {
      z_proxy_cp(self);
      if (self->data_connect[EP_SERVER])
        {
          if (ftp_policy_bounce_check(self, EP_SERVER, self->data_remote[EP_SERVER], TRUE))
            {
              if (!z_attach_start(self->data_connect[EP_SERVER], NULL, &self->data_local[EP_SERVER]))
                {
                  /* NOTE: We assume here, that lower level log if problem occured */
                  g_mutex_unlock(self->lock);
                  ftp_data_reset(self);
                  z_proxy_leave(self);
                  return;
                }
            }
          else
            {
              /*LOG
                This message indicates that the IP address of the data
                connection to be established differs from the IP of the
                control connection. This might be caused by a real bounce
                attack on FTP, or a erroneously configured NAT translation
                on the client or server side.
               */
              z_proxy_log(self, FTP_POLICY, 3, "Possible bounce attack; connect='TRUE', side='server', remote='%s'", z_sockaddr_format(self->data_remote[EP_SERVER], buf, sizeof(buf)));
              g_mutex_unlock(self->lock);
              ftp_data_reset(self);
              z_proxy_return(self);
            }
        }
      self->data_state |= FTP_DATA_SERVER_START;
    }
  
  if ((self->data_state & FTP_SERVER_FIRST_READY) == FTP_SERVER_FIRST_READY &&
       !(self->data_state & FTP_DATA_CLIENT_START))
    {
      z_proxy_cp(self);
      if (!self->data_connect[EP_SERVER])
        {
          if (!ftp_policy_bounce_check(self, EP_SERVER, self->data_remote[EP_SERVER], FALSE))
            {
              /*LOG
                This message indicates that the IP address of the data
                connection to be established differs from the IP of the
                control connection. This might be caused by a real bounce
                attack on FTP, or a erroneously configured NAT translation
                on the client or server side.
               */
              z_proxy_log(self, FTP_POLICY, 3, "Possible bounce attack; connect='FALSE', side='server', remote='%s'", z_sockaddr_format(self->data_remote[EP_SERVER], buf, sizeof(buf)));
              g_mutex_unlock(self->lock);
              ftp_data_reset(self);
              z_proxy_leave(self);
              return;
            }
        }

      z_stream_set_cond(self->super.endpoints[EP_SERVER],
                       G_IO_IN,
                       FALSE);
                       
      self->data_state |= FTP_DATA_CLIENT_START;
      if (self->data_connect[EP_CLIENT])
        {
          if (ftp_policy_bounce_check(self, EP_CLIENT, self->data_remote[EP_CLIENT], TRUE))
            {
              if (!z_attach_start(self->data_connect[EP_CLIENT], NULL, &self->data_local[EP_CLIENT]))
                {
                  /* NOTE: We assume here, that lower level log if problem occured */
                  g_mutex_unlock(self->lock);
                  ftp_data_reset(self);
                  z_proxy_leave(self);
                  return;
                }
            }
          else
            {
              /*LOG
                This message indicates that the IP address of the data
                connection to be established differs from the IP of the
                control connection. This might be caused by a real bounce
                attack on FTP, or a erroneously configured NAT translation
                on the client or server side.
               */
              z_proxy_log(self, FTP_POLICY, 3, "Possible bounce attack; connect='TRUE', side='client', remote='%s'", z_sockaddr_format(self->data_remote[EP_CLIENT], buf, sizeof(buf)));
              g_mutex_unlock(self->lock);
              ftp_data_reset(self);
              z_proxy_return(self);
            }
        }
    }
  
  if (self->data_state == FTP_SERVER_CONNECT_READY)
    {
      if (!self->data_connect[EP_CLIENT])
        {
          if (!ftp_policy_bounce_check(self, EP_CLIENT, self->data_remote[EP_CLIENT], FALSE))
            {
              /*LOG
                This message indicates that the IP address of the data
                connection to be established differs from the IP of the
                control connection. This might be caused by a real bounce
                attack on FTP, or a erroneously configured NAT translation
                on the client or server side.
               */
              z_proxy_log(self, FTP_POLICY, 3, "Possible bounce attack; connect='FALSE', side='client', remote='%s'", z_sockaddr_format(self->data_remote[EP_CLIENT], buf, sizeof(buf)));
              g_mutex_unlock(self->lock);
              ftp_data_reset(self);
              z_proxy_return(self);
            }
        }
      
      g_mutex_unlock(self->lock);
      if (!ftp_data_create_transfer(self))
        ftp_data_reset(self);
      z_proxy_return(self);
    }
  else if (self->data_state == FTP_DATA_CANCEL)
    {
      g_mutex_unlock(self->lock);
      ftp_data_reset(self);
      z_proxy_return(self);
    }
  else if (self->data_state == FTP_DATA_DESTROY)
    {
      /* FIXME
       * Correcly handling if one of the connection closed (server/client)
       */
      g_mutex_unlock(self->lock);
      ftp_data_reset(self);
//      ftp_data_abort(self);
//      SET_ANSWER(MSG_INVALID_PARAMETER);
//      self->state = FTP_QUIT;
//      ftp_command_reject(self);
      z_proxy_return(self);
    }
  g_mutex_unlock(self->lock);
  z_proxy_return(self);
}

gboolean
ftp_data_abort(FtpProxy *self)
{
  char buf[3];
  gsize len;
  GIOStatus rc;

  z_proxy_enter(self);
  ftp_data_reset(self);
  buf[0]=0xff;
  buf[1]=0xf4;
  buf[2]=0xff;
  rc = z_stream_write_pri(self->super.endpoints[EP_SERVER], buf, 3, &len, NULL);
  if (rc == G_IO_STATUS_NORMAL)
    {
      buf[0]=0xf2;
      rc = z_stream_write(self->super.endpoints[EP_SERVER], buf, 1, &len, NULL);
      ftp_stream_write(self, 'S', "ABOR", 4);
    }
  z_proxy_return(self, rc == G_IO_STATUS_NORMAL);
}


static gboolean ftp_client_data(ZStream *stream, GIOCondition cond, gpointer user_data);

static gboolean ftp_server_data(ZStream *stream, GIOCondition cond, gpointer user_data);
        
gboolean
ftp_stream_client_init(FtpProxy *self)
{
  ZStream *tmpstream;
  
  z_proxy_enter(self);
  if (!self->super.endpoints[EP_CLIENT])
    {
      /*LOG
        This message indicates an internal error, please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 1, "Internal error, client side not connected;");
      z_proxy_return(self, FALSE);
    }
  self->super.endpoints[EP_CLIENT]->timeout = self->timeout;
  
  tmpstream = self->super.endpoints[EP_CLIENT];
  self->super.endpoints[EP_CLIENT] = z_stream_line_new(tmpstream, self->max_line_length, ZRL_EOL_CRLF);

  z_stream_unref(tmpstream);

  z_stream_set_cond(self->super.endpoints[EP_CLIENT],
                   G_IO_IN,
                   FALSE);
  z_stream_set_cond(self->super.endpoints[EP_CLIENT],
                   G_IO_OUT,
                   FALSE);
  z_stream_set_cond(self->super.endpoints[EP_CLIENT],
                   G_IO_PRI,
                   FALSE);
                       
  z_stream_set_callback(self->super.endpoints[EP_CLIENT],
                        G_IO_IN,
                        ftp_client_data,
                        self, 
                        NULL);
  z_stream_set_callback(self->super.endpoints[EP_CLIENT],
                        G_IO_PRI,
                        ftp_client_data,
                        self, 
                        NULL);

  z_poll_add_stream(self->poll, self->super.endpoints[EP_CLIENT]);
  z_proxy_return(self, TRUE);
}

gboolean
ftp_stream_server_init(FtpProxy *self)
{
  ZStream *tmpstream;
  
  z_proxy_enter(self);
  if (!self->super.endpoints[EP_SERVER])
    {
      /*LOG
        This message indicates an internal error, please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 1, "Internal error, server side not connected;");
      z_proxy_return(self, FALSE);
    }
  self->super.endpoints[EP_SERVER]->timeout = self->timeout;
  
  tmpstream = self->super.endpoints[EP_SERVER];
  self->super.endpoints[EP_SERVER] = z_stream_line_new(tmpstream, self->max_line_length, ZRL_EOL_CRLF);
  z_stream_unref(tmpstream);

  z_stream_set_cond(self->super.endpoints[EP_SERVER],
                   G_IO_IN,
                   FALSE);
  z_stream_set_cond(self->super.endpoints[EP_SERVER],
                   G_IO_OUT,
                   FALSE);
  z_stream_set_cond(self->super.endpoints[EP_SERVER],
                   G_IO_PRI,
                   FALSE);
                       
  z_stream_set_callback(self->super.endpoints[EP_SERVER],
                        G_IO_IN,
                        ftp_server_data,
                        self,
                        NULL);
  z_poll_add_stream(self->poll, self->super.endpoints[EP_SERVER]);
  z_proxy_return(self, TRUE);
}

static void
ftp_deinit_streams(FtpProxy *self)
{
  if (self->super.endpoints[EP_CLIENT])
    z_poll_remove_stream(self->poll, self->super.endpoints[EP_CLIENT]);
  if (self->super.endpoints[EP_SERVER])
    z_poll_remove_stream(self->poll, self->super.endpoints[EP_SERVER]);
}

void
ftp_proxy_regvars(FtpProxy *self)
{
  z_proxy_enter(self);
  z_proxy_var_new(&self->super, "transparent_mode",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->transparent_mode);
                  
  z_proxy_var_new(&self->super, "permit_unknown_command",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->permit_unknown_command);
                  
  z_proxy_var_new(&self->super, "permit_empty_command",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->permit_empty_command);

  z_proxy_var_new(&self->super, "max_line_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_line_length);
                  
  z_proxy_var_new(&self->super, "max_username_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_username_length);
                  
  z_proxy_var_new(&self->super, "max_password_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_password_length);
                  
  z_proxy_var_new(&self->super, "max_hostname_length",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_hostname_length);
  
  z_proxy_var_new(&self->super, "masq_address_client",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  self->masq_address[EP_CLIENT]);
                  
  z_proxy_var_new(&self->super, "masq_address_server",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  self->masq_address[EP_SERVER]);

  z_proxy_var_new(&self->super, "request",
                  Z_VAR_TYPE_HASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->policy_command_hash);
  z_proxy_var_new(&self->super, "commands",
                  Z_VAR_TYPE_OBSOLETE | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  "request");
                  
  z_proxy_var_new(&self->super, "response",
                  Z_VAR_TYPE_DIMHASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->policy_answer_hash);
  z_proxy_var_new(&self->super, "answers",
                  Z_VAR_TYPE_OBSOLETE | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  "response");

  z_proxy_var_new(&self->super, "request_command",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->request_cmd);
                  
  z_proxy_var_new(&self->super, "request_parameter",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->request_param);

  z_proxy_var_new(&self->super, "response_status",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->answer_cmd);
  z_proxy_var_new(&self->super, "answer_code",
                  Z_VAR_TYPE_OBSOLETE | Z_VAR_GET | Z_VAR_SET,
                  "response_status");
                  
  z_proxy_var_new(&self->super, "response_parameter",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->answer_param);
  z_proxy_var_new(&self->super, "answer_parameter",
                  Z_VAR_TYPE_OBSOLETE | Z_VAR_GET | Z_VAR_SET,
                  "response_param");
  
  z_proxy_var_new(&self->super, "data_mode",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->data_mode);

  z_proxy_var_new(&self->super, "username",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->username);
                  
  z_proxy_var_new(&self->super, "password",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->password);

  z_proxy_var_new(&self->super, "hostname",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->hostname);

  z_proxy_var_new(&self->super, "hostport",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET,
                  &self->hostport);

  z_proxy_var_new(&self->super, "proxy_username",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->proxy_username);

  z_proxy_var_new(&self->super, "proxy_password",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->proxy_password);

  z_proxy_var_new(&self->super, "proxy_auth_needed",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET,
                  &self->proxy_auth_needed);

  z_proxy_var_new(&self->super, "auth",
                  Z_VAR_TYPE_OBJECT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->auth);

  z_proxy_var_new(&self->super, "response_strip_msg",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->response_strip_msg);

  z_proxy_var_new(&self->super, "timeout",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->timeout);

  z_proxy_var_new(&self->super, "buffer_size",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_GET_CONFIG | Z_VAR_SET_CONFIG,
                  &self->buffer_size);

  z_proxy_var_new(&self->super, "target_port_range",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  self->target_port_range);

  z_proxy_var_new(&self->super, "data_port_min",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->data_port_min);

  z_proxy_var_new(&self->super, "data_port_max",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->data_port_max);

  z_proxy_var_new(&self->super, "valid_chars_username",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  self->valid_chars_username);

  z_proxy_var_new(&self->super, "active_connection_mode",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->active_connection_mode);

  z_proxy_var_new(&self->super, "max_continuous_line",
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->max_continuous_line);

  z_proxy_var_new(&self->super, "features",
                  Z_VAR_TYPE_HASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->policy_features);

  z_proxy_return(self);
}

void
ftp_config_set_defaults(FtpProxy * self)
{

  z_proxy_enter(self);
  self->ftp_state = FTP_STATE_CONNECT;
  self->transparent_mode = TRUE;
  self->permit_empty_command = TRUE;
  self->permit_unknown_command = FALSE;
  self->response_strip_msg = FALSE;
  
  self->max_line_length = 255;
  self->max_username_length = 32;
  self->max_password_length = 64;
  self->max_hostname_length = 128;

  self->line = g_new0(char, FTP_LINE_MAX_LEN + 1);
  self->username = g_string_new("");
  self->password = g_string_new("");
  self->hostname = g_string_new("");
  self->proxy_username = g_string_new("");
  self->proxy_password = g_string_new("");
  self->proxy_auth_needed = 0;
  self->auth_done = FALSE;
  
  self->data_mode = FTP_DATA_KEEP;

  self->masq_address[EP_SERVER] = g_string_new("");
  self->masq_address[EP_CLIENT] = g_string_new("");

  self->lock = g_mutex_new();
  self->timeout = 300000;
  self->max_continuous_line = 100;
  self->policy_command_hash = ftp_policy_command_hash_create();
  self->policy_answer_hash = ftp_policy_answer_hash_create();
  self->policy_features = g_hash_table_new(g_str_hash, g_str_equal);
  self->request_cmd = g_string_sized_new(4);
  self->request_param = g_string_new("");
  self->answer_cmd = g_string_sized_new(4);
  self->answer_param = g_string_new("");
  self->target_port_range = g_string_new("21");
  self->hostport = 21;
  self->poll = z_poll_new();
  self->data_port_min = 40000;
  self->data_port_max = 41000;
  self->auth_tls_ok[EP_CLIENT] = FALSE;
  self->auth_tls_ok[EP_SERVER] = FALSE;
  self->data_protection_enabled[EP_CLIENT] = FALSE;
  self->data_protection_enabled[EP_SERVER] = FALSE;
  self->valid_chars_username = g_string_new("a-zA-Z0-9._@");
  self->buffer_size = 4096;
  z_proxy_return(self);
}

gboolean 
ftp_config_init(FtpProxy *self)
{
  z_proxy_enter(self);
  if (self->max_line_length > FTP_LINE_MAX_LEN)
    {
      /*LOG
        This message indicates that the configured max_line_length is above upper limit and
        Zorp sets it to the upper limit.
       */
      z_proxy_log(self, FTP_POLICY, 2, "Max_line_length above upper limit; max_line_length='%d', upper_limit='%d'", self->max_line_length, FTP_LINE_MAX_LEN);
      self->max_line_length = FTP_LINE_MAX_LEN;
    }
    
  if (self->max_username_length > self->max_line_length)
    {
      /*LOG
        This message indicates that the configured max_username_length is above max_line_length
        which does not make sense and Zorp sets it to the max_line_length.
       */
      z_proxy_log(self, FTP_POLICY, 2, "Max_username_length above max_line_length; max_username_length='%d', max_line_length='%d'", self->max_username_length, self->max_line_length);
      self->max_username_length = self->max_line_length;
    }
    
  if (self->max_password_length > self->max_line_length)
    {
      /*LOG
        This message indicates that the configured max_password_length is above max_line_length
        which does not make sense and Zorp sets it to the max_line_length.
       */
      z_proxy_log(self, FTP_POLICY, 2, "Max_password_length above max_line_length; max_password_length='%d', max_line_length='%d'", self->max_password_length, self->max_line_length);
      self->max_password_length = self->max_line_length;
    }
    
  if (self->max_hostname_length > self->max_line_length)
    {
      /*LOG
        This message indicates that the configured max_hostname_length is above max_line_length
        which does not make sense and Zorp sets it to the max_line_length.
       */
      z_proxy_log(self, FTP_POLICY, 2, "Max_hostname_length above max_line_length; max_hostname_length='%d', max_line_length='%d'", self->max_hostname_length, self->max_line_length);
      self->max_hostname_length = self->max_line_length;
    }

  if (!z_charset_parse(&self->username_charset, self->valid_chars_username->str))
    {
      /*LOG
        This message indicates that the character set specified in the
        valid_chars_username attribute has a syntax error.
       */
      z_proxy_log(self, FTP_POLICY, 2, "Error parsing valid_chars_username; value='%s'", self->valid_chars_username->str);
      z_proxy_return(self, FALSE);
    }
  z_proxy_return(self, TRUE);
}

GIOStatus
ftp_read_line_get (FtpProxy * self, guint side, gint *error_value)
{
  gint readback = G_IO_STATUS_ERROR;
  guint i;
  gint state;
  char *tmp;
  guint pos1;
  unsigned char funcs[10] = { 241, 242, 243, 244, 245, 246, 247, 248, 249, '\0' };
  unsigned char negot[5] = { 251, 252, 253, 254, '\0' };

  z_proxy_enter(self);
  self->line_length = self->max_line_length;
  readback = z_stream_line_get_copy(self->super.endpoints[side], self->line, &self->line_length, NULL);
  *error_value = errno;
  if (readback != G_IO_STATUS_NORMAL)
    {
      /* NOTE Here we assume that lower level log if problem occured */
      self->line_length = 0;
      z_proxy_return(self, readback);
    }

  tmp = g_new0(char, (self->line_length) + 2);
  state = FTP_TELNET;
  pos1 = 0;
  if (self->line_length)
    for (i = 0; i < self->line_length; i++)
      {
        // TODO: adding SB SE
        switch (state)
          {
          case FTP_TELNET:
            if ((unsigned char) self->line[i] != 255)
              {
                tmp[pos1++] = self->line[i];
              }
            else
              {
                if ((unsigned char) self->line[i + 1] == 255)
                  {
                    tmp[pos1++] = self->line[i];
                    i++;
                  }
                else
                  {
                    state = FTP_TELNET_IAC;
                  }
              }
            break;
            
          case FTP_TELNET_IAC:
            if (strchr (funcs, self->line[i]))
              {
                // in funcs
                state = FTP_TELNET;
                if ((unsigned char) self->line[i + 1] == 242)
                  {
                    i++;
                  }
              }
            else if (strchr (negot, self->line[i]))
              {
                // in negotiation
                state = FTP_TELNET_IAC_DW;
              }
            else if ((unsigned char) self->line[i] == 250)
              {
                state = FTP_TELNET_IAC_FUNC;
              }
            else
              {
                // Bad seq
              }
            break;
            
          case FTP_TELNET_IAC_DW:
            state = FTP_TELNET;
            break;
            
          case FTP_TELNET_IAC_FUNC:
            if ((unsigned char) self->line[i] == 240)
              state = FTP_TELNET;
            break;

          default:
            break;
          }
      }
  tmp[pos1] = 0;
  self->line_length = pos1;
  /* It's theoretically impossible to overflow. */
  strcpy(self->line, tmp);
  g_free (tmp);
  z_proxy_return(self, readback);
}

gboolean
ftp_stream_write(FtpProxy *self, char side, guchar *line, guint length)
{
  gsize bytes_written = 0;
  gchar buf[2 * length + 3];
  guint i, j;
  GIOStatus rc;

  z_proxy_enter(self);
  for (i = 0, j = 0; i < length; i++)
    {
      buf[j++] = line[i];
      if (line[i] == 255)
        {
          buf[j++] = 255;
        }
    }
  buf[j++] = '\r';
  buf[j++] = '\n';

  switch (side)
    {
    case 'S':
      rc = z_stream_write(self->super.endpoints[EP_SERVER], buf, j, &bytes_written, NULL);
      break;

    case 'C':
      rc = z_stream_write(self->super.endpoints[EP_CLIENT], buf, j, &bytes_written, NULL);
      break;

    default:
      /*LOG
        This message indicates an internal error, please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 1, "Internal error in stream write, side is wrong; side='%c'", side);
      assert(0);
      break;
    }

  if (bytes_written == j)
    z_proxy_return(self, TRUE);

  if (rc == G_IO_STATUS_NORMAL)
    {
      /*LOG
        This message reports that Zorp was unable to write out a full line and some data
        remained in the buffer.
       */
      z_proxy_log(self, FTP_ERROR, 4, "Cannot write full line; remained='%.*s'", j, buf + bytes_written);
    }
  z_proxy_return(self, FALSE);
}

gboolean
ftp_answer_parse(FtpProxy *self)
{
  char answer[4];
  int i;

  z_proxy_enter(self);  
  for (i = 0; i < 3; i++)
    if (!isdigit(self->line[i]))
      {
        /*LOG
          This message indicates that the server's answer does not begin with a valid 3 character
          long number.
         */
        z_proxy_log(self, FTP_VIOLATION, 1, "Server answer doesn't begin with number; line='%s'", self->line);
        z_proxy_leave(self);
        return FALSE;
      }
    else
      answer[i] = self->line[i];

  answer[3] = '\0'; /* zero terminate answer */

  g_string_assign(self->answer_cmd, answer);

  self->line[self->line_length] = 0;
  
  g_string_assign(self->answer_param, self->line + 4);
  
  /*LOG
    This message reports that a valid answer is read from the server.
   */
  z_proxy_log(self, FTP_RESPONSE, 6, "Response arrived; rsp='%s', rsp_prm='%s'", self->answer_cmd->str, self->answer_param->str);
  
  z_proxy_leave(self);
  return TRUE;
}

gboolean
ftp_answer_fetch(FtpProxy *self, gboolean *continued)
{
  guint res;
  gboolean cont = FALSE;
  int i;
  gint error_value;

  z_proxy_enter(self);
  res = ftp_read_line_get(self, EP_SERVER, &error_value);
  if (res == G_IO_STATUS_EOF)
    z_proxy_return(self, FALSE); /* read EOF */
    
  if (res != G_IO_STATUS_NORMAL)
    {
      /*LOG
        This message indicates that Zorp was unable to fetch the answer from
        the server. It is likely caused by some timeout.
       */
      z_proxy_log(self, FTP_ERROR, 1, "Error reading from server; error='%s'", strerror(error_value));
      z_proxy_return(self, FALSE);
    }
    
  if (*continued)
    {
      z_cp();
      g_string_append_c(self->answer_param, '\n');

      z_proxy_log(self, FTP_RESPONSE, 6, "Response continuation arrived; data='%s'", self->line);

      if(self->line_length < 4)
        {
          cont = TRUE;
          g_string_append_len(self->answer_param, self->line, self->line_length);
        }
      else
        {
          for (i = 0; i < 3 ; i++)
            {
              if (!isdigit(self->line[i]))
                {
                  cont = TRUE;
                  break;
                }
            }

          if (i == 3 && !memcmp(self->line, self->answer_cmd->str, 3) && (self->line[i] == ' ' || self->line[i] == '-'))
            {
              g_string_append_len(self->answer_param, self->line + 4, self->line_length - 4);
              if (self->line[i] == '-')
                cont = TRUE;
            }
          else
            {
              g_string_append_len(self->answer_param, self->line, self->line_length);
              cont = TRUE;
            }
        }
    }
  else
    {
      z_cp();
      if (self->line_length < 4)
        {
          /*LOG
            This message indicates that too short answer is read from the server.
            A valid answer must be at least 4 character long.
           */
          z_proxy_log(self, FTP_VIOLATION, 1, "Line is too short to be a valid answer; line='%s'", self->line);
          z_proxy_return(self, FALSE);
        }

      if (self->line[3] != ' ' && self->line[3] != '-')
        {
          /*LOG
            This message indicates that the server's answer has invalid continuation mark.
           */
          z_proxy_log(self, FTP_VIOLATION, 1, "Server answer has wrong continuation mark; line='%s'", self->line);
          z_proxy_return(self, FALSE);
        }

      if (!ftp_answer_parse(self))
        z_proxy_return(self, FALSE);
    }

  *continued = (cont || self->line[3]=='-');
  z_proxy_return(self, TRUE);
}

void
ftp_answer_process(FtpProxy *self) 
{
  FtpInternalCommand *command = self->command_desc;
  int res;

  z_proxy_enter(self);
  res = ftp_policy_answer_hash_do(self);
  self->answer_code = atoi(self->answer_cmd->str);
  if (res == FTP_RSP_ACCEPT)
    {
      if (command && command->answer)
        res = command->answer(self);
    }
  self->answer_handle = res;

  switch (res)
    {
    case FTP_RSP_ACCEPT:
      ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);
      break;
      
    case FTP_RSP_ABORT:
      self->state = FTP_QUIT;  /* no break; we must write answer... */
      
    case FTP_RSP_REJECT:
      /*LOG
        This message indicates that the given response is rejected and changed by the policy.
       */
      z_proxy_log(self, FTP_POLICY, 3, "Rejected answer; from='%s', to='%s %s'", self->line, self->answer_cmd->str, self->answer_param->str);
      ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);
      break;
      
    case FTP_NOOP:
      break;

    default:
      self->state = FTP_QUIT;
      break;
    }
  z_proxy_return(self);
}

gchar *
ftp_answer_setup(FtpProxy *self, gchar *answer_c, gchar *answer_p)
{
  gchar *tmp;
  GString *newline;

  z_proxy_enter(self);
  newline = g_string_sized_new(self->max_line_length);
  tmp = strchr(answer_p, '\n');
  if(!tmp)
    {
      g_string_append_printf(newline, "%s %s", answer_c, answer_p);
    }
  else
    {
      gboolean first_line = TRUE;

      while (tmp)
        {
          *tmp = 0;

          if (first_line)
            g_string_append_printf(newline, "%s-%s\r\n", answer_c, answer_p);
          else
            g_string_append_printf(newline, " %s\r\n", answer_p);

          *tmp = '\n';
          answer_p = tmp + 1;
          tmp = strchr(answer_p, '\n');
          first_line = FALSE;
        }
        
      if (*answer_p)
        g_string_append_printf(newline, "%s %s", answer_c, answer_p);
      else
        g_string_append_printf(newline, "%s ", answer_c);
    }
  z_proxy_return(self, g_string_free(newline, FALSE));
}

gboolean
ftp_answer_write_with_setup(FtpProxy *self, gchar *answer_c, gchar *answer_p)
{
  gchar *newline;
  gboolean res = TRUE;

  z_proxy_enter(self);
  newline = ftp_answer_setup(self, answer_c, answer_p);
  res = ftp_answer_write(self,newline);
  g_free(newline);
  z_proxy_return(self, res);
}
  
gboolean
ftp_answer_write(FtpProxy *self, gchar *msg)
{
  guint bytes_to_write;
  gboolean back = TRUE;

  z_proxy_enter(self);
  if (!self->drop_answer)
    {
      /* TODO PASV doesn't work!!!! */
      if (self->response_strip_msg)
        bytes_to_write = 4;
      else
        bytes_to_write = strlen(msg);
        
      back = ftp_stream_write(self, 'C', msg, bytes_to_write);
    }
  self->drop_answer = FALSE;
  z_proxy_return(self, back);
}

gboolean
ftp_command_fetch(FtpProxy *self)
{
  guint res;
  gint error_value;

  z_proxy_enter(self);  
  res = ftp_read_line_get(self, EP_CLIENT, &error_value);
  if (res == G_IO_STATUS_EOF)
    z_proxy_return(self, FALSE); /* read EOF */

  if (res != G_IO_STATUS_NORMAL)
    {
      /*LOG
        This message indicates that Zorp was unable to read from the client side.
       */
      z_proxy_log(self, FTP_ERROR, 2, "Error reading from client; error='%s'", strerror(error_value));
      if (errno == ETIMEDOUT)
        SET_ANSWER(MSG_TIMED_OUT)
      else
        SET_ANSWER(MSG_LINE_TERM_CRLF)

      ftp_command_reject(self);
      z_proxy_return(self, FALSE);
    }
  z_proxy_return(self, TRUE);
}

gboolean
ftp_command_parse(FtpProxy *self)
{
  gchar *src = self->line;
  guint i = 0;

  z_proxy_enter(self);
  g_string_assign(self->request_cmd, "");
  while ((*src != ' ') && (i < self->line_length))
    {
      g_string_append_c(self->request_cmd, *src++);
      i++;
    }
  src++;
  i++;

  if (i < self->line_length)
    g_string_assign(self->request_param, src);
  else
    g_string_assign(self->request_param, "");

  /*LOG
    This message reports that a valid request is fetched from the client.
   */
  z_proxy_log(self, FTP_REQUEST, 6, "Request fetched; req='%s' req_prm='%s'", self->request_cmd->str, self->request_param->str);
  g_string_up(self->request_cmd);
  self->command_desc = ftp_command_hash_get(self->request_cmd->str);

  if (!self->request_cmd->len && !self->permit_empty_command)
    {
      /*LOG
        This message indicates that an empty command is received, and policy does
        not permit it.
       */
      z_proxy_log(self, FTP_VIOLATION, 1, "Empty command. Aborting;");
      z_proxy_return(self, FALSE);
    }
  if (!self->command_desc && !self->permit_unknown_command && !ftp_policy_command_hash_search(self, self->request_cmd->str))
    {
      /*LOG
        This message indicates that an unknown command is received and policy does
        not permit it.
       */
      z_proxy_log(self, FTP_VIOLATION, 1, "Unknown command. Aborting; req='%s'", self->request_cmd->str);
      z_proxy_return(self, FALSE);
    }
  z_proxy_return(self, TRUE);
}

/**
 * ftp_command_process:
 *
 * This function processes the parsed command, and decides what to do. It
 * then either forwards or drops the command.
 */ 
void
ftp_command_process(FtpProxy *self) 
{
  FtpInternalCommand *command = self->command_desc;
  int res;

  z_proxy_enter(self);  
  SET_ANSWER(MSG_ERROR_PARSING_COMMAND);
  res = ftp_policy_command_hash_do(self);
  if (res == FTP_REQ_ACCEPT)
    {
      if (command)
        {
          if (!command->parse)
            {
              /*LOG
                This message indicates an internal error, please contact the BalaBit QA team.
               */
              z_proxy_log(self, FTP_ERROR, 1, "Internal error, known command but command parse is unset; req='%s'", self->request_cmd->str);
              assert(0);
            }
          res = command->parse(self);
        }
    }

  if (res == FTP_REQ_ACCEPT && self->state == FTP_NT_CLIENT_TO_PROXY)
    {
      /*LOG
        This message indicates that the given request was not permitted in
        non-transparent mode before the sever connection was established. It
        is likely caused by an AUTH command.
       */
      z_proxy_log(self, FTP_ERROR, 3, "This command not allowed in non-transparent mode; req='%s'", self->request_cmd->str);
      res = FTP_REQ_REJECT;
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
    }
    
  switch (res)
    {
    case FTP_REQ_ACCEPT:
      if (command && command->need_data)
        ftp_data_start(self);
      ftp_command_write_setup(self, self->request_cmd->str, self->request_param->str);
      break;
      
    case FTP_REQ_REJECT:
      ftp_command_reject(self);
      if (self->state == FTP_SERVER_TO_CLIENT)
        {
          ftp_state_set(self, EP_CLIENT);
          self->state = FTP_CLIENT_TO_SERVER;
        }
      else if (self->state == FTP_NT_SERVER_TO_PROXY)
        {
          ftp_state_set(self, EP_CLIENT);
          self->state = FTP_NT_CLIENT_TO_PROXY;
        }
      /*LOG
        This message indicates that the given request was rejected by the policy.
       */
      z_proxy_log(self, FTP_POLICY, 3, "Request rejected; req='%s'", self->request_cmd->str);
      break;
      
    case FTP_PROXY_ANS:
      ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);
      if (self->state == FTP_SERVER_TO_CLIENT)
        {
          ftp_state_set(self, EP_CLIENT);
          self->state = FTP_CLIENT_TO_SERVER;
        }
      else if (self->state == FTP_NT_SERVER_TO_PROXY)
        {
          ftp_state_set( self, EP_CLIENT);
          self->state = FTP_NT_CLIENT_TO_PROXY;
        }
      /*LOG
        This message reports that the given request is answered by Zorp
        without sending the request to the server.
       */
      z_proxy_log(self, FTP_POLICY, 4, "Proxy answer; rsp='%s' rsp_prm='%s'", self->answer_cmd->str, self->answer_param->str);
      break;
      
    case FTP_REQ_ABORT:
      SET_ANSWER(MSG_CONNECTION_ABORTED);
      ftp_command_reject(self);
      /*LOG
        This message indicates that the given request is rejected and the connection
        is aborted by Zorp.
       */
      z_proxy_log(self, FTP_POLICY, 2, "Rejected command (aborting); line='%s'", self->line);
      self->state = FTP_QUIT;
      break;
      
    case FTP_NOOP:
      break;
      
    default:
      /*LOG
        This message indicates an internal error, please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_POLICY, 1, "Bad policy type, aborting; line='%s', policy='%d'", self->line, res);
      self->state = FTP_QUIT;
    }  
  z_proxy_return(self);  
}

void
ftp_command_reject(FtpProxy *self)
{
  z_proxy_enter(self);
  ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);
  z_proxy_return(self);  
}

gboolean
ftp_command_write(FtpProxy *self, char *msg)
{
  gint bytes_to_write = strlen(msg);
  gboolean back;
  
  z_proxy_enter(self);
  back = ftp_stream_write(self, 'S', msg, bytes_to_write);
  z_proxy_return(self, back);
}

gboolean
ftp_command_write_setup(FtpProxy *self, gchar *answer_c, gchar *answer_p)
{
  gchar newline[self->max_line_length];
  gboolean vissza = TRUE;

  z_proxy_enter(self);  
  if (strlen(answer_p) > 0)
    g_snprintf(newline, sizeof(newline), "%s %s", answer_c, answer_p);
  else
    g_snprintf(newline, sizeof(newline), "%s", answer_c);

  vissza = ftp_command_write(self,newline);
  z_proxy_return(self, vissza);
}


void
ftp_proto_nt_init(FtpProxy *self)
{
  z_proxy_enter(self);

  ftp_proto_state_set(self, FTP_STATE_PRECONNECT);

  if (self->auth)
    SET_ANSWER(MSG_NON_TRANSPARENT_GREETING_WITH_INBAND_AUTH)
  else
    SET_ANSWER(MSG_NON_TRANSPARENT_GREETING);
  ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);
  self->state = FTP_NT_CLIENT_TO_PROXY;
  z_proxy_return(self);  
}

void
ftp_proto_nt_client_to_proxy(FtpProxy *self)
{
  z_proxy_enter(self);
  if (!ftp_command_fetch(self) ||
      !ftp_command_parse(self))
    {
      self->state = FTP_QUIT;
      z_proxy_return(self);
    }

  if (!self->request_cmd->len)
    z_proxy_return(self);
  ftp_command_process(self);

  switch (self->ftp_state)
    {
    case FTP_STATE_PRECONNECT_LOGIN_P:
      /* by this time login creditentials, and host name is received,
         try to connect to the remote server */

      if (self->auth && !self->auth_done)
        {
          z_proxy_log(self, FTP_ERROR, 3, "Inband authentication is required but wasn't completed;");
          self->state = FTP_QUIT;
          break;
        }

      if (ftp_connect_server_event(self, self->hostname->str, self->hostport) &&
          ftp_stream_server_init(self))
        {
          self->state = FTP_NT_SERVER_TO_PROXY;
          ftp_proto_state_set(self, FTP_STATE_PRECONNECT);
          g_string_assign(self->request_cmd, "");
        }
      else
        {
          self->state = FTP_QUIT;
        }
      break;

    case FTP_STATE_PRECONNECT_QUIT:
      self->state = FTP_QUIT;
      break;

    default:
      /* nothing to do */
      break;
    }
  z_proxy_return(self);  
}

static void
ftp_proto_nt_send_USER(FtpProxy *self)
{
  gchar user_line[self->username->len + 6];

  z_proxy_enter(self);

  g_snprintf(user_line, sizeof(user_line), "USER %s", self->username->str);
  g_string_assign(self->request_cmd, "USER");
  ftp_command_write(self, user_line);
  ftp_proto_state_set(self, FTP_STATE_PRECONNECT_LOGIN_U);

  z_proxy_leave(self);
}

static gboolean
ftp_nt_check_cert_subject(FtpProxy *self)
{
  ZProxyHostIface *host_iface;
  gboolean res = TRUE;

  z_proxy_enter(self);

  host_iface = Z_CAST(z_proxy_find_iface(&self->super, Z_CLASS(ZProxyHostIface)), ZProxyHostIface);

  if (host_iface)
    {
      gchar error_reason[256];

      if (!z_proxy_host_iface_check_name(host_iface, self->hostname->str, error_reason, sizeof(error_reason)))
        {
          z_proxy_log(self, FTP_ERROR, 3, "Error checking hostname; error='%s'", error_reason);
          res = FALSE;
        }

      z_object_unref(&host_iface->super);
    }

  z_proxy_return(self, res);
}

void
ftp_proto_nt_server_to_proxy(FtpProxy *self)
{
  guint line_numbers = 0;

  z_proxy_enter(self);
  g_string_assign(self->answer_cmd, "");
  self->answer_code = 0;
  self->answer_cont = 0;
  do
    {
      if (!ftp_answer_fetch(self, &self->answer_cont))
        {
          self->state = FTP_QUIT;
          z_proxy_return(self);
        }
      line_numbers++;
    }
  while (self->answer_cont && line_numbers <= self->max_continuous_line);

  if (line_numbers > self->max_continuous_line)
    {
      /*LOG
       * This message reports that the server send an answer
       * which have too many lines. Increase the self.max_continuous_line variable
       * if this is not a security incident.
       */
      z_proxy_log(self, FTP_POLICY, 3, "Too many continuous lines in the answer; max_continuous_line='%d'", self->max_continuous_line);
      self->state = FTP_QUIT;
      z_proxy_return(self);
    }

  switch (self->ftp_state)
    {
    case FTP_STATE_PRECONNECT:
      if (strcmp(self->answer_cmd->str, "220") == 0)
        {
          if (self->auth_tls_ok[EP_CLIENT]
              && (self->super.ssl_opts.security[EP_SERVER] == PROXY_SSL_SEC_FORWARD_STARTTLS))
            {
              /* send AUTH TLS */
              g_string_assign(self->request_cmd, "AUTH");
              ftp_command_write(self, "AUTH TLS");
              ftp_proto_state_set(self, FTP_STATE_PRECONNECT_AUTH);
            }
          else
            ftp_proto_nt_send_USER(self);
        }
      break;
      
    case FTP_STATE_PRECONNECT_AUTH:
      if (strcmp(self->answer_cmd->str, "234") == 0)
        {
          gboolean res;

          /* AUTH TLS accepted by server, do handshake */
          res = z_proxy_ssl_request_handshake(&self->super, EP_SERVER, TRUE);

          if (!res)
            {
              z_proxy_log(self, FTP_ERROR, 2, "Server-side SSL handshake failed, terminating session;");
              self->auth_tls_ok[EP_SERVER] = FALSE;

              SET_ANSWER(MSG_NT_SERVER_HANDSHAKE_FAILED);
              ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);

              self->state = FTP_QUIT;
              break;
            }
          else
            self->auth_tls_ok[EP_SERVER] = TRUE;

          if (!ftp_nt_check_cert_subject(self))
            {
              z_proxy_log(self, FTP_ERROR, 2, "Server-side SSL certificate subject does not match inband hostname, terminating session;");

              SET_ANSWER(MSG_NT_SERVER_CERT_INVALID_SUBJECT);
              ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);

              self->state = FTP_QUIT;
              break;
            }

          if (self->client_sent_pbsz)
            {
              g_string_assign(self->request_cmd, "PBSZ");
              ftp_command_write(self, "PBSZ 0");
              ftp_proto_state_set(self, FTP_STATE_PRECONNECT_PBSZ);
            }
          else
            ftp_proto_nt_send_USER(self);
        }
      else
        {
          z_proxy_log(self, FTP_ERROR, 3, "Server did not accept AUTH TLS in non-transparent mode, aborting;");

          SET_ANSWER(MSG_NT_SERVER_AUTH_REJECT);
          ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);

          self->state = FTP_QUIT;
          z_proxy_return(self);
        }
      break;

    case FTP_STATE_PRECONNECT_PBSZ:
      if (strcmp(self->answer_cmd->str, "200") == 0)
        {
          /* server accepted PBSZ 0: if PROT wasn't C, send prot;
           * otherwise send USER */
          if (self->data_protection_enabled[EP_CLIENT])
            {
              g_string_assign(self->request_cmd, "PROT");
              ftp_command_write(self, "PROT P");
              ftp_proto_state_set(self, FTP_STATE_PRECONNECT_PROT);
            }
          else
            ftp_proto_nt_send_USER(self);
        }
      else
        {
          z_proxy_log(self, FTP_ERROR, 3, "Server did not accept PBSZ in non-transparent mode, aborting;");

          SET_ANSWER(MSG_NT_SERVER_PBSZ_REJECT);
          ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);

          self->state = FTP_QUIT;
          z_proxy_return(self);
        }
      break;

    case FTP_STATE_PRECONNECT_PROT:
      if (strcmp(self->answer_cmd->str, "200") == 0)
        ftp_proto_nt_send_USER(self);
      else
        {
          z_proxy_log(self, FTP_ERROR, 3, "Server did not accept PROT in non-transparent mode, aborting;");

          SET_ANSWER(MSG_NT_SERVER_PROT_REJECT);
          ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);

          self->state = FTP_QUIT;
          z_proxy_return(self);
        }
      break;

    case FTP_STATE_PRECONNECT_LOGIN_U:
      if (strcmp(self->answer_cmd->str, "331") == 0)
        {
          gchar pass_line[self->password->len + 6];

          /* send password */
          g_snprintf(pass_line, sizeof(pass_line), "PASS %s", self->password->str);
          g_string_assign(self->request_cmd, "PASS");
          ftp_command_write(self, pass_line);
          ftp_proto_state_set(self, FTP_STATE_LOGIN_P);
          self->state = FTP_SERVER_TO_CLIENT;
          ftp_state_set(self, EP_SERVER);
        }
      else if (strcmp(self->answer_cmd->str, "230") == 0)
        {
          /* no password required */
          ftp_answer_write(self, self->line);
          ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
          ftp_state_set(self, EP_CLIENT);
          self->state = FTP_CLIENT_TO_SERVER;
        }
      break;

    default:
      /* invalid state */
      z_proxy_log(self, FTP_ERROR, 1, "Internal error while in non-transparent mode, proxy is in invalid state; state='%s'",
                  ftp_proto_state_name(self->ftp_state));
      self->state = FTP_QUIT;
      break;
    }
  z_proxy_return(self);  
}

void
ftp_proto_client_to_server(FtpProxy *self)
{
  z_proxy_enter(self);
  if (!ftp_command_fetch(self) ||
      !ftp_command_parse(self))
    {
      self->state = FTP_QUIT;
      z_proxy_return(self);
    }

  if (!self->request_cmd->len)
    z_proxy_return(self);

  self->state = FTP_SERVER_TO_CLIENT;
  ftp_state_set(self, EP_SERVER);
  ftp_command_process(self);
  z_proxy_return(self);  
}

void
ftp_proto_server_to_client(FtpProxy *self)
{
  guint line_numbers = 0;

  z_proxy_enter(self);
  g_string_assign(self->answer_cmd, "");
  self->answer_code = 0;
  self->answer_cont = 0;
  do
    {
      if (!ftp_answer_fetch(self, &self->answer_cont))
        {
          self->state = FTP_QUIT;
          z_proxy_return(self);
        }
      line_numbers++;
    }
  while (self->answer_cont && line_numbers <= self->max_continuous_line);
  
  if (line_numbers > self->max_continuous_line)
    {
      self->state = FTP_QUIT;
      z_proxy_return(self);
    }
    
  self->state = FTP_CLIENT_TO_SERVER;
  ftp_state_set(self, EP_CLIENT);
  ftp_answer_process(self);
  z_proxy_return(self);  
}

static gboolean
ftp_server_data(ZStream *stream G_GNUC_UNUSED,
           GIOCondition  cond G_GNUC_UNUSED,
               gpointer  user_data)
{
  FtpProxy *self = (FtpProxy *) user_data;

  z_proxy_enter(self);
  ftp_proto_server_to_client(self);
  if (self->state == FTP_QUIT && self->transfer)
    {
      z_transfer2_cancel(self->transfer);
      self->transfer = NULL;
    }
  z_proxy_return(self, TRUE);
}

static gboolean
ftp_client_data(ZStream *stream G_GNUC_UNUSED,
           GIOCondition  cond G_GNUC_UNUSED,
               gpointer  user_data)
{
  FtpProxy *self = (FtpProxy *) user_data;

  z_proxy_enter(self);
  ftp_proto_client_to_server(self);
  if (self->state == FTP_QUIT && self->transfer)
    {
      z_transfer2_cancel(self->transfer);
      self->transfer = NULL;
    }
  z_proxy_return(self, TRUE);
}

void
ftp_listen_both_side(FtpProxy *self)
{
  guint rc;
  
  z_proxy_enter(self);
  if (!(self->data_state & FTP_DATA_CONVERSATION))
    {
      rc = z_poll_iter_timeout(self->poll, self->timeout);
      if (!rc)
        {
          if (errno == ETIMEDOUT)
            {
              SET_ANSWER(MSG_TIMED_OUT);
              ftp_command_reject(self);
            }
          self->state = FTP_QUIT;
        }
    }
  else
    {
      rc = z_poll_iter_timeout(self->poll, -1);
    }

  if (self->data_state && self->state != FTP_QUIT)
    {
      if (rc)
        ftp_data_next_step(self);

      if (self->data_state && self->state != FTP_QUIT)
        self->state = FTP_BOTH_SIDE;
    }
  z_proxy_return(self);  
}

gboolean
ftp_config(ZProxy *s)
{
  FtpProxy *self = Z_CAST(s, FtpProxy);
   
  ftp_config_set_defaults(self);
  ftp_proxy_regvars(self);
  if (Z_SUPER(s, ZProxy)->config(s))
    {
      return ftp_config_init(self);
    }
  return FALSE;

}

void
ftp_main(ZProxy *s)
{
  FtpProxy *self = Z_CAST(s, FtpProxy);

  z_proxy_enter(self);
  if (!ftp_stream_client_init(self))
    z_proxy_return(self);
  
  if (self->transparent_mode)
    self->state = FTP_INIT_TRANSPARENT;
  else
    self->state = FTP_INIT_NONTRANSPARENT;

  while (self->state != FTP_QUIT)
    {
      if (!z_proxy_loop_iteration(s))
        {
          self->state = FTP_QUIT;
          break;
        }
      
      switch (self->state)
        {
          case FTP_INIT_TRANSPARENT:
            if (!ftp_connect_server_event(self, NULL, 0) ||
                !ftp_stream_server_init(self))
              {
                      self->state = FTP_QUIT;
              }
            else
              {
                self->state = FTP_SERVER_TO_CLIENT;
                ftp_state_set(self, EP_SERVER);
                ftp_proto_state_set(self, FTP_STATE_LOGIN);
              }
            break;

          case FTP_INIT_NONTRANSPARENT:
            ftp_proto_nt_init(self);
            break;

          case FTP_NT_CLIENT_TO_PROXY:
            ftp_proto_nt_client_to_proxy(self);
            break;

          case FTP_NT_SERVER_TO_PROXY:
            ftp_proto_nt_server_to_proxy(self);
            break;

          case FTP_SERVER_TO_CLIENT:
          case FTP_CLIENT_TO_SERVER:
          case FTP_BOTH_SIDE:
            /*LOG
              This message reports that Zorp is reading from it's peers on the given side.
             */
            z_proxy_log(self, FTP_DEBUG, 8, "Reading from peer; side='%s'",
                        self->state == FTP_SERVER_TO_CLIENT ? "server" :
                        self->state == FTP_CLIENT_TO_SERVER ? "client" :
                        self->state == FTP_BOTH_SIDE ? "both" : "unknown");
            ftp_listen_both_side(self);
            break;
        }
    }
  ftp_data_reset(self);
  ftp_deinit_streams(self);
  z_proxy_return(self);
}

ZProxy *
ftp_proxy_new(ZProxyParams *params)
{
  FtpProxy *self;

  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(FtpProxy), params), FtpProxy);
  z_return(&self->super);
}

void
ftp_proxy_free(ZObject *s)
{
  guint i;
  FtpProxy *self = Z_CAST(s, FtpProxy);

  z_enter();
  z_poll_quit(self->poll);
  z_poll_unref(self->poll);
  g_free(self->line);
  g_mutex_free(self->lock);
  if (self->preamble)
    g_free(self->preamble);
  for (i = 0; i < EP_MAX; i++)
    {
      z_sockaddr_unref(self->data_local_buf[i]);
      self->data_local_buf[i] = NULL;
    }
  z_proxy_free_method(s);
  z_return();
}

ZProxyFuncs ftp_proxy_funcs =
{
  { 
    Z_FUNCS_COUNT(ZProxy),
    ftp_proxy_free,
  },
  .config = ftp_config,
  .main = ftp_main,
  NULL
};

ZClass FtpProxy__class = 
{
  Z_CLASS_HEADER,
  &ZProxy__class,
  "FtpProxy",
  sizeof(FtpProxy),
  &ftp_proxy_funcs.super
};


/*+ Zorp initialization function +*/
gint
zorp_module_init (void)
{
  ftp_command_hash_create();
  z_registry_add ("ftp", ZR_PROXY, ftp_proxy_new);
  return TRUE;
}
