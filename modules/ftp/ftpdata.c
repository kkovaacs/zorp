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
 *
 * Author: Balazs Scheidler <bazsi@balabit.hu>
 * Auditor: 
 * Last audited version: 
 * Notes:
 *
 ***************************************************************************/
 
#include "ftp.h"

/* transfer states */

#define FTP_DW_INITIAL            0
#define FTP_DW_WRITE_PREAMBLE     1
#define FTP_DW_WRITE_DATA         2

typedef struct _FtpTransfer
{
  ZTransfer2 super;
  
  guint dst_write_state;
} FtpTransfer;

extern ZClass FtpTransfer__class;

/* FtpTransfer implementation */

static GIOStatus 
ftp_transfer_src_read(ZTransfer2 *s, ZStream *stream, gchar *buf, gsize count, gsize *bytes_read, GError **err)
{
  FtpProxy *owner = (FtpProxy *) s->owner;
  GIOStatus res;

  z_proxy_enter(owner);
  res = z_stream_read(stream, buf, count, bytes_read, err);
  z_proxy_return(owner, res);
}

static GIOStatus
ftp_transfer_dst_write_preamble(FtpTransfer *self G_GNUC_UNUSED, ZStream *stream G_GNUC_UNUSED, GError **err G_GNUC_UNUSED)
{
  GIOStatus res = G_IO_STATUS_NORMAL;
  FtpProxy *owner = (FtpProxy *) self->super.owner;

  if (owner->preamble)
    {
      if (!ftp_answer_write(owner, owner->preamble))
        res = G_IO_STATUS_ERROR;
      g_free(owner->preamble);
      owner->preamble = NULL;
    }
  return res;
}

static GIOStatus 
ftp_transfer_dst_write(ZTransfer2 *s, ZStream *stream, const gchar *buf, gsize count, gsize *bytes_written, GError **err)
{
  FtpTransfer *self = Z_CAST(s, FtpTransfer);
  GIOStatus res = G_IO_STATUS_NORMAL;
  
  *bytes_written = 0;
  
  if (self->dst_write_state == FTP_DW_INITIAL)
    self->dst_write_state = FTP_DW_WRITE_PREAMBLE;

  if (self->dst_write_state == FTP_DW_WRITE_PREAMBLE)
    {
      /* take care about the preamble (request/response itself) */
      res = ftp_transfer_dst_write_preamble(self, stream, err);
      if (res != G_IO_STATUS_NORMAL)
        {
          goto propagate_exit;
        }
      self->dst_write_state = FTP_DW_WRITE_DATA;
    }

  res = z_stream_write(stream, buf, count, bytes_written, err);

 propagate_exit:
  return res;
}

GIOStatus
ftp_transfer_dst_shutdown(ZTransfer2 *s, ZStream *stream, GError **err)
{
  FtpTransfer *self = Z_CAST(s, FtpTransfer);
  GIOStatus res = G_IO_STATUS_NORMAL;
  
  if (self->dst_write_state == FTP_DW_INITIAL)
    self->dst_write_state = FTP_DW_WRITE_PREAMBLE;

  if (self->super.stack_decision == Z_ACCEPT)
    {
      if (self->dst_write_state == FTP_DW_WRITE_PREAMBLE)
        {
          /* take care about the preamble (request/response itself) */
          res = ftp_transfer_dst_write_preamble(self, stream, err);
          self->dst_write_state = FTP_DW_WRITE_DATA;
        }
    }
  
  return res;
}

static gboolean
ftp_transfer_stack_proxy(ZTransfer2 *s, ZStackedProxy **stacked)
{
  FtpTransfer *self = Z_CAST(s, FtpTransfer);
  ZPolicyObj *proxy_stack_tuple = NULL, *stack_object = NULL;
  gint stack_type = FTP_STK_NONE;
  gboolean called;
  gboolean success = FALSE;
  
  /* query python for a stacked proxy */

  z_policy_lock(self->super.owner->thread);
  
  proxy_stack_tuple = z_policy_call(self->super.owner->handler, "requestStack", NULL, &called, self->super.owner->session_id);
  if (called && !proxy_stack_tuple)
    {
      goto unref_unlock;
    }
  if (!z_policy_var_parse(proxy_stack_tuple, "(iO)", &stack_type, &stack_object))
    {
      /*LOG
        This message indicates that the request_stack or response_stack hash
	contains an invalid stacking tuple. It should contain a (stack_type, proxy_class) tuple.
	Check your Zorp configuration.
       */
      z_proxy_log(self->super.owner, FTP_POLICY, 3, "Invalid stacking tuple returned by policy;");
      goto unref_unlock;
    }
  if (stack_type < FTP_STK_NONE || stack_type > FTP_STK_DATA)
    {
      /*LOG
        This message indicates that the request_stack or response_stack hash
	contains an invalid stacking type. Check your Zorp configuration.
       */
      z_proxy_log(self->super.owner, FTP_POLICY, 3, "Invalid stacking type; type='%d'", stack_type);
      stack_type = FTP_STK_NONE;
      goto unref_unlock;
    }
    
  /* NOTE: FTP_STK_POLICY is never returned here, it is handled by the policy layer */
  success = TRUE;
  switch (stack_type)
    {
    case FTP_STK_NONE:
      break;
    case FTP_STK_DATA:
    default:
      success = z_proxy_stack_object(s->owner, stack_object, stacked, NULL);
      break;
    }
 unref_unlock:
  z_policy_var_unref(proxy_stack_tuple);
  z_policy_unlock(self->super.owner->thread);
  return success;
}

static FtpTransfer *
ftp_transfer_new(FtpProxy *owner, ZStream *from_stream, ZStream *to_stream)
{
  FtpTransfer *self;
  
  z_proxy_enter(owner);
  self = Z_CAST(z_transfer2_new(Z_CLASS(FtpTransfer), 
                               &owner->super, owner->poll, 
                               from_stream, to_stream, 
                               owner->buffer_size, 
                               owner->timeout, 
                               0), 
                FtpTransfer);
  z_proxy_return(owner, self);
}


ZTransfer2Funcs ftp_transfer_funcs =
{
  {
    Z_FUNCS_COUNT(ZTransfer2),
    NULL,
  },
  .src_read = ftp_transfer_src_read,
  .dst_write = ftp_transfer_dst_write,
  .src_shutdown = NULL,
  .dst_shutdown = ftp_transfer_dst_shutdown,
  .stack_proxy = ftp_transfer_stack_proxy,
  .setup = NULL,
  .run = NULL,
  .progress = NULL
};

ZClass FtpTransfer__class =
{
  Z_CLASS_HEADER,
  &ZTransfer2__class,
  "FtpTransfer",
  sizeof(FtpTransfer),
  &ftp_transfer_funcs.super
};

gboolean
ftp_data_transfer(FtpProxy *self, ZStream *from_stream, ZStream *to_stream)
{
  FtpTransfer *t;
  gboolean res = TRUE;
  ZTransfer2Result tr;

  z_proxy_enter(self);
  t = ftp_transfer_new(self, from_stream, to_stream);
  if (!t || !z_transfer2_start(&t->super))
    {
      /*LOG
        This message indicates that the processed request was invalid, and
	the data transfer failed.
       */
      z_proxy_log(self, FTP_ERROR, 2, "Invalid request, data transfer failed;");
      SET_ANSWER(MSG_DATA_TRANSFER_FAILED);
      res = FALSE;
      goto exit;
    }

  self->transfer = &t->super;
  do
    {
      tr = z_transfer2_run(&t->super);
    }
  while (tr == ZT2_RESULT_SUSPENDED);
  self->transfer = NULL;

  res = (tr != ZT2_RESULT_FAILED) && (tr != ZT2_RESULT_ABORTED);
  if (!res)
    {
      /* transfer was not successful */
      /*LOG
        This message reports that the data transfer failed.
       */
      z_proxy_log(self, FTP_ERROR, 2, "Data transfer failed;");
      SET_ANSWER(MSG_DATA_TRANSFER_FAILED);
    }
  
  /* transfer was successful, check if the stacked proxy told us something important */
  if (t->super.stack_decision != Z_ACCEPT)
    {
      res = FALSE;
      /*LOG
        This message indicates that the stacked proxy returned the
        specified verdict about the content. Check the stacked proxy log
        for further information.
       */
      z_proxy_log(self, FTP_ERROR, 2, "Stacked proxy decision; verdict='%d', info='%s'", t->super.stack_decision, t->super.stack_info->str);
      SET_ANSWER(MSG_DATA_TRANSFER_FAILED);
      if (t->super.stack_info->len)
        g_string_append_printf(self->answer_param, " (%s)", t->super.stack_info->str);
      
    }
  else if (res)
    {
      /*LOG
        This message indicates that the stacked proxy accepted the
        content. 
       */
      z_proxy_log(self, FTP_DEBUG, 6, "Stacked proxy accepted data;");
    }
  
 exit:

  z_stream_shutdown(from_stream, SHUT_RDWR, NULL);
  z_stream_close(from_stream, NULL);
  z_stream_unref(from_stream);

  z_stream_shutdown(to_stream, SHUT_RDWR, NULL);
  z_stream_close(to_stream, NULL);
  z_stream_unref(to_stream);

  if (t)
    z_object_unref(&t->super.super);
  
  z_proxy_return(self, res);
}
