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
 * $Id: dottransfer.c,v 1.11 2004/07/28 16:32:45 bazsi Exp $
 * 
 * Author:  Attila SZALAY <sasa@balabit.hu>
 * Auditor:
 * Last audited version:
 * Notes:
 *  This is a generalized ZTransfer derived class which can be used to
 *  transfer dot terminated data streams like in the POP3 and SMTP protocols.
 *  It assumes that the client side is ZStreamLine compatible.
 *
 ***************************************************************************/

#include <zorp/proxy/dottransfer.h>
#include <zorp/log.h>
#include <zorp/proxy/transfer2.h>
#include <zorp/streamline.h>

/* ZDotTransfer implementation */

extern ZClass ZDotTransfer__class;

/**
 * z_dot_transfer_src_read:
 * @s: ZDotTransfer instance
 * @stream: stream to read data from
 * @buf: buffer to store data into
 * @count: number of bytes to read
 * @bytes_read: the number of actually read bytes
 * @err: error details
 *
 * This function is registered as the virtual src_read() function for
 * ZDotTransfer. It effectively reads lines from its input, and indicates EOF
 * when a '.' is encountered in line on its own.
 **/
static GIOStatus 
z_dot_transfer_src_read(ZTransfer2 *s, ZStream *stream, gchar *buf, gsize count, gsize *bytes_read, GError **err)
{
  ZDotTransfer *self = Z_CAST(s, ZDotTransfer);
  GError *local_error = NULL;
  GIOStatus res;
  gsize read_len;

  z_proxy_enter(self->super.owner);
  *bytes_read = 0;

  if (count < 2)
    {
      z_proxy_leave(self->super.owner);
      return G_IO_STATUS_AGAIN;
    }

  read_len = count - 2;
  res = z_stream_line_get_copy(stream, buf, &read_len, &local_error);

  switch (res)
    {
    case G_IO_STATUS_NORMAL:
      if (!self->previous_line_split && read_len > 0 && buf[0] == '.')
        {
          if (read_len == 1)
            {
              res = G_IO_STATUS_EOF;
              break;
            }
          else
            {
              memmove(buf, &buf[1], read_len - 1);
              read_len = read_len - 1;
            }
        }
      buf[read_len] = '\r';
      buf[read_len + 1] = '\n';
      *bytes_read = read_len + 2;
      self->previous_line_split = FALSE;
      break;
    case G_IO_STATUS_AGAIN:
      *bytes_read = read_len;
      if (read_len > 0)
        {
          self->previous_line_split = TRUE;
          res = G_IO_STATUS_NORMAL;
        }
      break;
    case G_IO_STATUS_EOF:
      /*LOG
	This message indicates that server unexpectedly closed its connection.
       */
      z_log(NULL, CORE_ERROR, 4, "Unexpected EOF while transferring from server;");
      res = G_IO_STATUS_ERROR;
      break;
    case G_IO_STATUS_ERROR:
    default:
      res = G_IO_STATUS_ERROR;
    }

  if (local_error)
    g_propagate_error(err, local_error);

  z_proxy_leave(self->super.owner);
  return res;
}

/**
 * z_dot_transfer_dst_write_preamble:
 * @self: ZDotTransfer instance
 * @stream: stream to write to
 * @err: error details
 *
 * This function is called to flush the preamble right before the first byte to the
 * target stream would be written. Using a preamble makes it possible to conditionally
 * prefix the data stream with some protocol information, which is only needed when
 * our child proxy actually sent us something. 
 **/
static GIOStatus
z_dot_transfer_dst_write_preamble(ZDotTransfer *self, ZStream *stream, GError **err)
{
  GIOStatus res = G_IO_STATUS_NORMAL;
  GError *local_error = NULL;
  gsize bw;
  
  z_proxy_enter(self->super.owner);
  res = z_stream_write(stream, &self->preamble->str[self->preamble_ofs], self->preamble->len - self->preamble_ofs, &bw, &local_error);
  if (res == G_IO_STATUS_NORMAL)
    {
      self->preamble_ofs += bw;
      if (self->preamble_ofs != self->preamble->len)
        res = G_IO_STATUS_AGAIN;
    }
  if (local_error)
    g_propagate_error(err, local_error);
  
  z_proxy_leave(self->super.owner);
  return res;
}

/**
 * z_dot_transfer_dst_write:
 * @s: ZDotTransfer passed as a ZTransfer2
 * @stream: stream to write data into
 * @buf: data to write
 * @count: size of data in @buf to write
 * @bytes_written: number of bytes actually written
 * @err: error details
 *
 * This function is registered as the virtual dst_write() function of
 * ZTransfer2. It basically send the contents of @buf to @stream, escaping
 * '.' characters when encountered as the first character in a line as it
 * goes.
 **/
static GIOStatus 
z_dot_transfer_dst_write(ZTransfer2 *s, ZStream *stream, const gchar *buf, gsize count, gsize *bytes_written, GError **err)
{
  ZDotTransfer *self = Z_CAST(s, ZDotTransfer);
  GError *local_error = NULL;
  GIOStatus res = G_IO_STATUS_NORMAL;
  gsize i, bw;

  z_proxy_enter(self->super.owner);
  *bytes_written = 0;
  
  switch (self->dst_write_state)
    {
    case DOT_DW_PREAMBLE:
      res = z_dot_transfer_dst_write_preamble(self, stream, &local_error);
      if (res != G_IO_STATUS_NORMAL)
        {
          break;
        }
      self->dst_write_state = DOT_DW_DATA_LF;
      /* fallthrough */

    data_state:

    case DOT_DW_DATA:
    case DOT_DW_DATA_LF:
      for (i = *bytes_written; i < count; i++)
        {
          if (self->dst_write_state == DOT_DW_DATA)
            {
              if (buf[i] == '\n')
                {
                  self->dst_write_state = DOT_DW_DATA_LF;
                }
            }
          else if (self->dst_write_state == DOT_DW_DATA_LF)
            {
              if (buf[i] == '.')
                {
                  /* we need to escape this '.' */
                                                                                                                                          
                  /* first, write buf up to this '.' */
                  res = z_stream_write(stream, buf + *bytes_written, i - *bytes_written, &bw, &local_error);
                  if (res == G_IO_STATUS_NORMAL && i == bw)
                    {
                      *bytes_written += bw;
                      self->dst_write_state = DOT_DW_DATA_DOT;
                      goto dot_state;
                    }
                  else
                    {
                      /* we wrote less bytes, go back to the original state */
                      self->dst_write_state = DOT_DW_DATA;
                      *bytes_written += bw;
                      break;
                    }
                }
              self->dst_write_state = DOT_DW_DATA;
            }
        }
      if (i == count)
        {
          /* no need to escape */
          res = z_stream_write(stream, buf + *bytes_written, count - *bytes_written, &bw, &local_error);
          *bytes_written += bw;
        }
      break;

    dot_state:
    case DOT_DW_DATA_DOT:
      res = z_stream_write(stream, ".", 1, &bw, &local_error);
      if (res == G_IO_STATUS_NORMAL && bw == 1)
        {
          self->dst_write_state = DOT_DW_DATA;
          goto data_state;
        }

      break;
    }
    
  if (local_error)
    g_propagate_error(err, local_error);
  
  z_proxy_leave(self->super.owner);
  return res;
}

/**
 * z_dot_transfer_dst_shutdown:
 * @s: ZDotTransfer passed as a ZTransfer2
 * @stream: stream to shut down
 * @err: error details
 *
 * This function is registered as the virtual dst_shutdown() function for
 * ZTransfer2. It basically checks whether the transfer actually terminated the
 * data stream by CRLF, and terminates it that was not the case. This is required
 * by for example mail transfers when mail bodies must end in CRLF in order 
 * to correctly interpret the closing '.'.
 **/
static GIOStatus 
z_dot_transfer_dst_shutdown(ZTransfer2 *s, ZStream *stream, GError **err)
{
  ZDotTransfer *self = Z_CAST(s, ZDotTransfer);
  GIOStatus res = G_IO_STATUS_NORMAL;
  
  /* NOTE: this code ensures that our output to the server side is
   * terminated by a CRLF before the last '.' is written.
   */
  if (self->dst_write_state == DOT_DW_DATA && ((self->super.status & (ZT2S_FAILED+ZT2S_TIMEDOUT+ZT2S_ABORTED)) == 0))
    {
      gsize bw;
      
      res = z_stream_write(stream, "\r\n", 2, &bw, err);
    }
  return res;
}

/**
 * z_dot_transfer_new:
 * @class: class to instantiate
 * @owner: owner proxy
 * @poll: ZPoll instance
 * @client: client stream
 * @server: server stream
 * @buffer_size: buffer size
 * @timeout: inactivity timeout
 * @flags: bit combination of ZT2F_*
 * @preamble: string to send before the first byte is actually written to the destination
 *
 * This function is the constructor for ZDotTransfer a '.' terminated bulk transfer method,
 * used by POP3 for example. (or NNTP, or SMTP)
 * SMTP does not use this one, as it needs to send NOOPs to the server while transferring.
 **/
ZDotTransfer *
z_dot_transfer_new(ZClass *class,
                   ZProxy *owner,
                   ZPoll *poll,
                   ZStream *client, ZStream *server,
                   gsize buffer_size,
                   glong timeout,
                   gulong flags,
                   GString *preamble)
{
  ZDotTransfer *self;
  
  z_proxy_enter(owner);
  
  self = Z_CAST(z_transfer2_new(class,
                               owner, poll,
                               client, server, 
                               buffer_size,
                               timeout,
                               ZT2F_COMPLETE_COPY | flags),
                ZDotTransfer);

  self->preamble = preamble;
  z_proxy_leave(owner);
  return self;
}

/**
 * z_dot_transfer_free_method:
 * @s: ZDotTransfer passed as a ZObject
 *
 * Destructor function for ZDotTransfer instances, frees self->preamble and
 * calls the inherited free method.
 **/
static void
z_dot_transfer_free_method(ZObject *s)
{
  ZDotTransfer *self = Z_CAST(s, ZDotTransfer);
  
  g_string_free(self->preamble, TRUE);
  z_transfer2_free_method(s);
}


ZTransfer2Funcs z_dot_transfer_funcs =
{
  {
    Z_FUNCS_COUNT(ZTransfer2),
    z_dot_transfer_free_method,
  },
  z_dot_transfer_src_read,
  z_dot_transfer_dst_write,
  NULL, /* src_shutdown */
  z_dot_transfer_dst_shutdown,
  NULL, /* stack_proxy */
  NULL, /* setup */
  NULL,
  NULL  /* progress */
};

ZClass ZDotTransfer__class =
{
  Z_CLASS_HEADER,
  &ZTransfer2__class,
  "ZDotTransfer",
  sizeof(ZDotTransfer),
  &z_dot_transfer_funcs.super
};
