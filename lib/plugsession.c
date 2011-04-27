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
 * $Id: plugsession.c,v 1.18 2004/07/01 16:55:25 bazsi Exp $
 *
 * Author  : bazsi
 * Auditor : 
 * Last audited version: 1.1
 * Notes:
 *   
 ***************************************************************************/

#include <zorp/plugsession.h>

#include <zorp/log.h>
#include <zorp/stream.h>
#include <zorp/source.h>

/* FIXME: should be run-time configurable */
#define MAX_READ_AT_A_TIME 30

typedef struct _ZPlugIOBuffer
{
  gchar *buf;
  gsize ofs, end;
  gsize packet_count, packet_bytes;
} ZPlugIOBuffer;

struct _ZPlugSession
{
  ZRefCount ref_count;
  ZPlugSessionData *session_data;
  ZPoll *poll;
  ZStream *endpoints[EP_MAX];
  ZStackedProxy *stacked;
  ZPlugIOBuffer buffers[EP_MAX];
  ZPlugIOBuffer downbufs[EP_MAX];
  gint eofmask;
  GSource *timeout;
  GSource *stats_timeout;
  GTimeVal started_time;
  guint global_packet_count;
  gpointer *user_data;
  gboolean started;
};

/* possible eofmask values */
#define EOF_CLIENT_R         0x0001
#define EOF_SERVER_R         0x0002
#define EOF_CLIENT_W         0x0004
#define EOF_SERVER_W         0x0008
#define EOF_CLIENT_REMOVED   0x0010
#define EOF_SERVER_REMOVED   0x0020
#define EOF_DESTROYED        0x0040

#define EOF_ALL              0x000f

static void
z_plug_update_eof_mask(ZPlugSession *self, guint add_mask)
{
  guint old_mask = self->eofmask;
  
  self->eofmask |= add_mask;
  
  if ((self->eofmask & (EOF_CLIENT_R | EOF_CLIENT_W | EOF_CLIENT_REMOVED)) == (EOF_CLIENT_R | EOF_CLIENT_W))
    {
      z_poll_remove_stream(self->poll, self->endpoints[EP_CLIENT]);
      self->eofmask |= EOF_CLIENT_REMOVED;
    }

  if ((self->eofmask & (EOF_SERVER_R | EOF_SERVER_W | EOF_SERVER_REMOVED)) == (EOF_SERVER_R | EOF_SERVER_W))
    {
      z_poll_remove_stream(self->poll, self->endpoints[EP_SERVER]);
      self->eofmask |= EOF_SERVER_REMOVED;
    }
  
  if ((self->eofmask & (EOF_DESTROYED | EOF_CLIENT_REMOVED | EOF_SERVER_REMOVED)) == (EOF_CLIENT_REMOVED | EOF_SERVER_REMOVED))
    {
      z_plug_session_cancel(self);
      self->eofmask |= EOF_DESTROYED;
    }

  /*LOG
    This message reports that the end-of-file status has been updated.
   */
  z_log(NULL, CORE_DEBUG, 7, "eofmask updated; old_mask='%04x', eof_mask='%04x'", old_mask, self->eofmask);

  if (!(old_mask & EOF_DESTROYED) && (self->eofmask & EOF_DESTROYED))
    {
      /* WARNING: calling ->finish() may have freed _this_ PlugSession
         instance! It's forbidden to touch self after this call! */
      if (self->session_data->finish)
        self->session_data->finish(self, self->user_data);
    }
}


static guint
z_plug_read_input(ZPlugSession *self, ZStream *input, ZPlugIOBuffer *buf)
{
  GIOStatus rc;

  z_enter();
  rc = z_stream_read(input, buf->buf, self->session_data->buffer_size, &buf->end, NULL);
  if (rc == G_IO_STATUS_NORMAL)
    {
      buf->packet_bytes += buf->end;
      buf->packet_count++;
      self->global_packet_count++;
      if (self->session_data->packet_stats_interval_packet &&
         (self->global_packet_count % self->session_data->packet_stats_interval_packet) == 0)
        {
          if (!self->session_data->packet_stats(self,
                                                self->buffers[EP_CLIENT].packet_bytes, 
                                                self->buffers[EP_CLIENT].packet_count,
                                                self->buffers[EP_SERVER].packet_bytes,
                                                self->buffers[EP_SERVER].packet_count,
                                                self->user_data))
            z_plug_update_eof_mask(self, EOF_ALL);
        }
    }
  z_return(rc);
}

static GIOStatus
z_plug_write_output(ZPlugSession *self G_GNUC_UNUSED, ZPlugIOBuffer *buf, ZStream *output)
{
  GIOStatus rc;
  gsize bytes_written;
  
  z_enter();
  if (buf->ofs != buf->end)
    {
      /* buffer not empty */
      rc = z_stream_write(output, &buf->buf[buf->ofs], buf->end - buf->ofs, &bytes_written, NULL);
      switch (rc) 
        {
        case G_IO_STATUS_NORMAL:
          buf->ofs += bytes_written;
          break;

        case G_IO_STATUS_AGAIN:
          break;

        default:
          z_return(rc);
        }

      if (buf->ofs != buf->end)
        {
          z_stream_set_cond(output, G_IO_OUT, TRUE);
          z_leave();
          z_return(G_IO_STATUS_AGAIN);
        }
    }
  z_return(G_IO_STATUS_NORMAL);
}

static GIOStatus
z_plug_copy_data(ZPlugSession *self, ZStream *from, ZStream *to, ZPlugIOBuffer *buf)
{
  GIOStatus rc = G_IO_STATUS_ERROR;
  int pkt_count = 0;

  z_enter();
  
  if (self->timeout)
    z_timeout_source_set_timeout(self->timeout, self->session_data->timeout);
  
  if (!from || !buf)
    z_return(G_IO_STATUS_ERROR);
  
  z_stream_set_cond(from, G_IO_IN, FALSE);

  if (to)
    {
      z_stream_set_cond(to, G_IO_OUT, FALSE);
      rc = z_plug_write_output(self, buf, to);
      if (rc != G_IO_STATUS_NORMAL)
        z_return(rc);
    }

  while (pkt_count < MAX_READ_AT_A_TIME)
    {  
      buf->ofs = buf->end = 0;
      rc = z_plug_read_input(self, from, buf);
      if (rc == G_IO_STATUS_NORMAL)
        {
          if (to)
            {
              rc = z_plug_write_output(self, buf, to);
              if (rc == G_IO_STATUS_AGAIN)
                break;
              else if (rc != G_IO_STATUS_NORMAL)
                z_return(rc);
            }
        }
      else if (rc == G_IO_STATUS_AGAIN)
        break;
      else if (rc == G_IO_STATUS_EOF)
        z_return(rc);
      else
        z_return(G_IO_STATUS_ERROR);
      pkt_count++;
    }

  if (buf->ofs == buf->end)
    z_stream_set_cond(from, G_IO_IN, TRUE);

  z_return(rc);
}


/* callbacks when no stacking is made */
static gboolean
z_plug_copy_client_to_server(ZStream *stream G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  ZPlugSession *self = (ZPlugSession *) user_data;
  gboolean ret;

  z_enter();
  if (self->session_data->copy_to_server)
    ret = z_plug_copy_data(self,
                         self->endpoints[EP_CLIENT],
                         self->endpoints[EP_SERVER],
                         &self->buffers[EP_SERVER]);
  else
    ret = z_plug_copy_data(self,
                         self->endpoints[EP_CLIENT],
                         NULL,
                         &self->buffers[EP_SERVER]);

  switch (ret)
    {
    case G_IO_STATUS_NORMAL:
    case G_IO_STATUS_AGAIN:
      break;
      
    case G_IO_STATUS_EOF:
      if (self->session_data->shutdown_soft)
        {
          z_stream_shutdown(self->endpoints[EP_CLIENT], SHUT_RD, NULL);
          z_stream_shutdown(self->endpoints[EP_SERVER], SHUT_WR, NULL);
          z_plug_update_eof_mask(self, EOF_CLIENT_R | EOF_SERVER_W);
        }
      else
        {
          z_plug_update_eof_mask(self, EOF_ALL);
        }
      break;
      
    default:
      z_plug_update_eof_mask(self, EOF_ALL);
      z_return(FALSE);
    }
  z_return(TRUE);
}

static gboolean
z_plug_copy_server_to_client(ZStream *stream G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  ZPlugSession *self = (ZPlugSession *) user_data;
  GIOStatus ret;

  z_enter();
  if (self->session_data->copy_to_client)
    ret = z_plug_copy_data(self,
                         self->endpoints[EP_SERVER],
                         self->endpoints[EP_CLIENT],
                         &self->buffers[EP_CLIENT]);
  else
    ret = z_plug_copy_data(self,
                         self->endpoints[EP_SERVER],
                         NULL,
                         &self->buffers[EP_CLIENT]);

  switch (ret)
    {
    case G_IO_STATUS_NORMAL:
    case G_IO_STATUS_AGAIN:
      break;

    case G_IO_STATUS_EOF:
      if (self->session_data->shutdown_soft)
        {
          z_stream_shutdown(self->endpoints[EP_SERVER], SHUT_RD, NULL);
          z_stream_shutdown(self->endpoints[EP_CLIENT], SHUT_WR, NULL);
          z_plug_update_eof_mask(self, EOF_SERVER_R | EOF_CLIENT_W);
        }
      else
        {
          z_plug_update_eof_mask(self, EOF_ALL);
        }
      break;
      
    default:
      z_plug_update_eof_mask(self, EOF_ALL);
      z_return(FALSE);
    }
  z_return(TRUE);
}

/* callbacks when a stacked module exists */
static gboolean
z_plug_copy_client_to_down(ZStream *stream G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  ZPlugSession *self = (ZPlugSession *) user_data;
  GIOStatus ret;

  z_enter();
  if (self->session_data->copy_to_server)
    ret = z_plug_copy_data(self,
                         self->endpoints[EP_CLIENT],
                         self->stacked->downstreams[EP_CLIENT],
                         &self->downbufs[EP_CLIENT]);
  else
    ret = z_plug_copy_data(self,
                         self->endpoints[EP_CLIENT],
                         NULL,
                         &self->downbufs[EP_CLIENT]);

  switch (ret)
    {
    case G_IO_STATUS_NORMAL:
    case G_IO_STATUS_AGAIN:
      break;
      
    case G_IO_STATUS_EOF:
      if (self->session_data->shutdown_soft)
        {
          z_stream_shutdown(self->endpoints[EP_CLIENT], SHUT_RD, NULL);
          z_stream_shutdown(self->stacked->downstreams[EP_CLIENT], SHUT_WR, NULL);
          z_plug_update_eof_mask(self, EOF_CLIENT_R);
        }
      else
        {
          z_plug_update_eof_mask(self, EOF_ALL);
        }
      break;

    default:
      z_plug_update_eof_mask(self, EOF_ALL);
      z_return(FALSE);
    }
  z_return(TRUE);
}

static gboolean
z_plug_copy_down_to_client(ZStream *stream G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  ZPlugSession *self = (ZPlugSession *) user_data;
  GIOStatus ret;

  z_enter();
  ret = z_plug_copy_data(self,
                       self->stacked->downstreams[EP_CLIENT],
                       self->endpoints[EP_CLIENT],
                       &self->buffers[EP_CLIENT]);
  switch (ret)
    {
    case G_IO_STATUS_NORMAL:
    case G_IO_STATUS_AGAIN:
      break;
      
    case G_IO_STATUS_EOF:
      if (self->session_data->shutdown_soft)
        {
          z_stream_shutdown(self->stacked->downstreams[EP_CLIENT], SHUT_RD, NULL);
          z_stream_shutdown(self->endpoints[EP_CLIENT], SHUT_WR, NULL);
          z_plug_update_eof_mask(self, EOF_CLIENT_W);
        }
      else
        {
          z_plug_update_eof_mask(self, EOF_ALL);
        }
      break;
      
    default:
      z_plug_update_eof_mask(self, EOF_ALL);
      z_return(FALSE);
    }
  z_return(TRUE);
}

static gboolean
z_plug_copy_server_to_down(ZStream *stream G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  ZPlugSession *self = (ZPlugSession *) user_data;
  GIOStatus ret;

  z_enter();
  if (self->session_data->copy_to_client)
    ret = z_plug_copy_data(self,
                         self->endpoints[EP_SERVER],
                         self->stacked->downstreams[EP_SERVER],
                         &self->downbufs[EP_SERVER]);
  else
    ret = z_plug_copy_data(self,
                         self->endpoints[EP_SERVER],
                         NULL,
                         &self->downbufs[EP_SERVER]);
  switch (ret)
    {
    case G_IO_STATUS_NORMAL:
    case G_IO_STATUS_AGAIN:
      break;
      
    case G_IO_STATUS_EOF:
      if (self->session_data->shutdown_soft)
        {
          z_stream_shutdown(self->endpoints[EP_SERVER], SHUT_RD, NULL);
          z_stream_shutdown(self->stacked->downstreams[EP_SERVER], SHUT_WR, NULL);
          z_plug_update_eof_mask(self, EOF_SERVER_R);
        }
      else
        {
          z_plug_update_eof_mask(self, EOF_ALL);
        }
      break;
      
    default:
      z_plug_update_eof_mask(self, EOF_ALL);
      z_return(FALSE);
    }
  z_return(TRUE);
}

static gboolean
z_plug_copy_down_to_server(ZStream *stream G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  ZPlugSession *self = (ZPlugSession *) user_data;
  GIOStatus ret;

  z_enter();
  ret = z_plug_copy_data(self,
                       self->stacked->downstreams[EP_SERVER],
                       self->endpoints[EP_SERVER],
                       &self->buffers[EP_SERVER]);
  switch (ret)
    {
    case G_IO_STATUS_NORMAL:
    case G_IO_STATUS_AGAIN:
      z_return(TRUE);

    case G_IO_STATUS_EOF:
      if (self->session_data->shutdown_soft)
        {
          z_stream_shutdown(self->stacked->downstreams[EP_SERVER], SHUT_RD, NULL);
          z_stream_shutdown(self->endpoints[EP_SERVER], SHUT_WR, NULL);
          z_plug_update_eof_mask(self, EOF_SERVER_W);
        }
      else
        {
          z_plug_update_eof_mask(self, EOF_ALL);
        }
      break;

    default:
      z_plug_update_eof_mask(self, EOF_ALL);
      z_return(FALSE);
    }
  z_return(TRUE);
}

gboolean
z_plug_timeout(gpointer user_data)
{
  ZPlugSession *self = (ZPlugSession *) user_data;
  
  z_enter();
  z_plug_update_eof_mask(self, EOF_ALL);
  z_return(FALSE);
}

/* FIXME: merge these two functions */
gboolean
z_plug_session_init_streams(ZPlugSession *self)
{
  z_enter();
  self->buffers[EP_CLIENT].buf = g_new0(char, self->session_data->buffer_size);
  self->buffers[EP_SERVER].buf = g_new0(char, self->session_data->buffer_size);
  
  z_stream_set_nonblock(self->endpoints[EP_CLIENT], TRUE);
  z_stream_set_callback(self->endpoints[EP_CLIENT], G_IO_IN, z_plug_copy_client_to_server, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);
  z_stream_set_callback(self->endpoints[EP_CLIENT], G_IO_OUT, z_plug_copy_server_to_client, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);
  z_stream_set_cond(self->endpoints[EP_CLIENT], G_IO_IN, TRUE);
  z_stream_set_timeout(self->endpoints[EP_CLIENT], -2);
  
  z_stream_set_nonblock(self->endpoints[EP_SERVER], TRUE);
  z_stream_set_callback(self->endpoints[EP_SERVER], G_IO_IN, z_plug_copy_server_to_client, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);
  z_stream_set_callback(self->endpoints[EP_SERVER], G_IO_OUT, z_plug_copy_client_to_server, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);
  z_stream_set_cond(self->endpoints[EP_SERVER], G_IO_IN, TRUE);
  z_stream_set_timeout(self->endpoints[EP_SERVER], -2);

  z_poll_add_stream(self->poll, self->endpoints[EP_CLIENT]);
  z_poll_add_stream(self->poll, self->endpoints[EP_SERVER]);
  z_return(TRUE);
}

static gboolean
z_plug_session_init_stacked_streams(ZPlugSession *self)
{
  z_enter();
  
  if (self->stacked)
    {
      self->downbufs[EP_CLIENT].buf = g_new0(char, self->session_data->buffer_size);
      self->downbufs[EP_SERVER].buf = g_new0(char, self->session_data->buffer_size);

      z_stream_set_callback(self->endpoints[EP_CLIENT], G_IO_IN, z_plug_copy_client_to_down, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);
      z_stream_set_callback(self->endpoints[EP_CLIENT], G_IO_OUT, z_plug_copy_down_to_client, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);

      z_stream_set_callback(self->endpoints[EP_SERVER], G_IO_IN, z_plug_copy_server_to_down, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);
      z_stream_set_callback(self->endpoints[EP_SERVER], G_IO_OUT, z_plug_copy_down_to_server, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);

      z_stream_set_callback(self->stacked->downstreams[EP_CLIENT], G_IO_IN, z_plug_copy_down_to_client, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);
      z_stream_set_callback(self->stacked->downstreams[EP_CLIENT], G_IO_OUT, z_plug_copy_client_to_down, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);
      z_stream_set_cond(self->stacked->downstreams[EP_CLIENT], G_IO_IN, TRUE);

      z_stream_set_callback(self->stacked->downstreams[EP_SERVER], G_IO_IN, z_plug_copy_down_to_server, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);
      z_stream_set_callback(self->stacked->downstreams[EP_SERVER], G_IO_OUT, z_plug_copy_server_to_down, z_plug_session_ref(self), (GDestroyNotify) z_plug_session_unref);
      z_stream_set_cond(self->stacked->downstreams[EP_SERVER], G_IO_IN, TRUE);

      z_poll_add_stream(self->poll, self->stacked->downstreams[EP_CLIENT]);
      z_poll_add_stream(self->poll, self->stacked->downstreams[EP_SERVER]);
    }
  z_return(TRUE);
}

static gboolean
z_plug_session_stats_timeout(gpointer user_data)
{
  ZPlugSession *self = (ZPlugSession *) user_data;
  
  if (self->session_data->packet_stats)
    {
      if (!self->session_data->packet_stats(self,
                                            self->buffers[EP_CLIENT].packet_bytes,
                                            self->buffers[EP_CLIENT].packet_count,
                                            self->buffers[EP_SERVER].packet_bytes,
                                            self->buffers[EP_SERVER].packet_count,
                                            self->user_data))
        {
          z_plug_update_eof_mask(self, EOF_ALL);
        }
      z_return(TRUE);
    }
  /*LOG
    This message indicates that packet stats interval was specified, but no action was configured to handle the event.
    Check your policy for packetStats event.
   */
  z_log(NULL, CORE_ERROR, 3, "Packet stats timeout elapsed, and no timeout callback specified;");
  z_return(FALSE);
}

static ZPolicyObj *
z_plug_session_query_bandwidth(ZPlugSession *self, gchar *name, gpointer value G_GNUC_UNUSED)
{
  GTimeVal now, spent;
  double bandwidth = 0.0;
  
  g_get_current_time(&now);
  spent.tv_sec = now.tv_sec - self->started_time.tv_sec;
  spent.tv_usec = now.tv_usec - self->started_time.tv_usec;
  if (spent.tv_usec < -500000)
    spent.tv_sec++;
    
  if (strcmp(name, "bandwidth_to_client") == 0)
    {
      bandwidth = (double) self->buffers[EP_CLIENT].packet_bytes / spent.tv_sec;
    }
  else if (strcmp(name, "bandwidth_to_server") == 0)
    {
      bandwidth = (double) self->buffers[EP_SERVER].packet_bytes / spent.tv_sec;
    }
  return z_policy_var_build("d", bandwidth);
}

void
z_plug_session_register_vars(ZPlugSession *self, ZPolicyDict *dict)
{
  z_policy_dict_register(dict, Z_VT_CUSTOM, "bandwidth_to_client", Z_VF_READ,
                                 /* value, get, set, free, userdata, destroy-notify */
                                 NULL, z_plug_session_query_bandwidth, NULL, NULL, self, NULL);

  z_policy_dict_register(dict, Z_VT_CUSTOM, "bandwidth_to_server", Z_VF_READ, 
                                 NULL, z_plug_session_query_bandwidth, NULL, NULL, self, NULL);
                                 
}


gboolean
z_plug_session_start(ZPlugSession *self, ZPoll *poll)
{
  if (self->started)
    g_assert_not_reached();
    
  z_poll_ref(poll);
  self->poll = poll;
  
  if (z_plug_session_init_streams(self) && z_plug_session_init_stacked_streams(self))
    {
      g_get_current_time(&self->started_time);
      if (self->session_data->packet_stats_interval_time > 0)
        {
          GMainContext *context;
         
          self->stats_timeout = g_timeout_source_new(self->session_data->packet_stats_interval_time);
          g_source_set_callback(self->stats_timeout, z_plug_session_stats_timeout, self, NULL);
          context = z_poll_get_context(self->poll);
          g_source_attach(self->stats_timeout, context);
        }
      if (self->session_data->timeout > 0)
        {
          GMainContext *context;
         
          self->timeout = z_timeout_source_new(self->session_data->timeout);
          g_source_set_callback(self->timeout, z_plug_timeout, self, NULL);
          context = z_poll_get_context(self->poll);
          g_source_attach(self->timeout, context);
        }
      self->started = TRUE;
      return TRUE;
    }
  return FALSE;
}

void
z_plug_session_cancel(ZPlugSession *self)
{
  gint i;
  
  if (!self->started)
    return;
    
  for (i = EP_CLIENT; i < EP_MAX; i++)
    {
      if (self->stacked)
        {
          z_poll_remove_stream(self->poll, self->stacked->downstreams[i]);
        }
      z_poll_remove_stream(self->poll, self->endpoints[i]);
    }
  
  if (self->stacked)
    {
      z_stacked_proxy_destroy(self->stacked);
      self->stacked = NULL;
    }
    
  if (self->stats_timeout)
    {
      g_source_destroy(self->stats_timeout);
      g_source_unref(self->stats_timeout);
      self->stats_timeout = NULL;
    }
  if (self->timeout)
    {
      g_source_destroy(self->timeout);
      g_source_unref(self->timeout);
      self->timeout = NULL;
    }
  self->started = FALSE;
}

static void
z_plug_session_free(ZPlugSession *self)
{
  g_free(self);
}

ZPlugSession *
z_plug_session_ref(ZPlugSession *self)
{
  z_refcount_inc(&self->ref_count);
  return self;
}

void
z_plug_session_unref(ZPlugSession *self)
{
  if (z_refcount_dec(&self->ref_count))
    z_plug_session_free(self);
}

ZPlugSession *
z_plug_session_new(ZPlugSessionData *session_data, ZStream *client_stream, ZStream *server_stream, ZStackedProxy *stacked, gpointer user_data)
{
  ZPlugSession *self = g_new0(ZPlugSession, 1);
  gchar buf[Z_STREAM_MAX_NAME];
  
  self->user_data = user_data;
  z_stream_ref(client_stream);
  z_stream_ref(server_stream);
  
  if (!client_stream->name[0])
    {
      g_snprintf(buf, sizeof(buf), "%s/%s", fake_session_id, "client");
      z_stream_set_name(client_stream, buf);
    }
  if (!server_stream->name[0])
    {
      g_snprintf(buf, sizeof(buf), "%s/%s", fake_session_id, "server");
      z_stream_set_name(server_stream, buf);
    }

  self->endpoints[EP_CLIENT] = client_stream;
  self->endpoints[EP_SERVER] = server_stream;
  self->stacked = stacked;
  self->session_data = session_data;
  z_refcount_set(&self->ref_count, 1);
  return self;
}

void
z_plug_session_destroy(ZPlugSession *self)
{
  gint i;
  
  if (self)
    {
      g_assert(!self->started);
      
      for (i = EP_CLIENT; i < EP_MAX; i++)
        {
          if (self->downbufs[i].buf)
            {
              g_free(self->downbufs[i].buf);
              self->downbufs[i].buf = NULL;
            }
          g_free(self->buffers[i].buf);
          self->buffers[i].buf = NULL;
          
          z_stream_unref(self->endpoints[i]);
          self->endpoints[i] = NULL;
        }
      
      z_poll_unref(self->poll);
      self->poll = NULL;
      z_plug_session_unref(self);
    }
}

