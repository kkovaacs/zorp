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
 * $Id: httpfltr.c,v 1.83 2004/07/26 11:45:57 bazsi Exp $
 *
 * Author: Balazs Scheidler <bazsi@balabit.hu>
 * Auditor: 
 * Last audited version: 
 * Notes:
 *
 ***************************************************************************/
 
#include "http.h"

#include <zorp/log.h>
#include <zorp/io.h>
#include <zorp/proxy/transfer2.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

/* transfer states */

#define HTTP_SR_INITIAL           0
#define HTTP_SR_PUSH_HEADERS	  10
#define HTTP_SR_PUSH_HEADERS_MAX  10

#define HTTP_SR_READ_INITIAL      20
#define HTTP_SR_READ_CHUNK_LENGTH 21
#define HTTP_SR_READ_CHUNK        22
#define HTTP_SR_READ_FOOTER       23
#define HTTP_SR_READ_ENTITY       24     /* reading content-length or EOF terminated entity */

#define HTTP_DW_INITIAL            0

#define HTTP_DW_POP_HEADERS        10
#define HTTP_DW_POP_HEADERS_CR     11
#define HTTP_DW_POP_HEADERS_LF     12
#define HTTP_DW_POP_HEADERS_MAX    12


#define HTTP_DW_WRITE_PREAMBLE     20
#define HTTP_DW_WRITE_INITIAL      21
#define HTTP_DW_FORMAT_CHUNK_LENGTH 22
#define HTTP_DW_WRITE_CHUNK_LENGTH 23
#define HTTP_DW_WRITE_CHUNK        24
#define HTTP_DW_WRITE_FOOTER       25

struct _HttpTransfer
{
  ZTransfer2 super;
  
  GString *preamble;
  guint preamble_ofs;
  
  /* whether to actually suppress DATA even if they seem to be some (e.g. response HEAD request) */
  gboolean suppress_data;
  
  /* whether to expect data if there is nothing explicit indicating it (e.g. response entities) */
  gboolean expect_data;

  /* transfer endpoints */
  gint transfer_from, transfer_to;
  gint transfer_type;
  
  /* the headers to send to the downstream proxy */
  GString *stacked_preamble;
  /* offset within mime_headers if writing blocked */
  guint stacked_preamble_ofs;
  guint stacked_preamble_read_bytes;
  
  /* function used to format the preamble to stacked proxy/peer */
  HttpTransferPreambleFunc format_preamble_func;
  
  /* whether to push mime headers to the downstream proxy */
  gboolean push_mime_headers;
  
  /* whether to force the end of the connection */
  gboolean force_nonpersistent_mode;
  /* we can stay persisent, but only if we receive a content-length hint from downstream proxy */
  gboolean persistent_with_cl_hint_only;
  
  HttpHeader *transfer_encoding_hdr, *content_length_hdr;
  
  /* used while stripping off MIME headers returned by the downstream proxy */
  gint dst_eol_count;
  
  /* complete content_length, -2 if no entity, -1 if length unknown, otherwise the exact length */
  gint64 content_length;
  
  /* indicates whether source is chunked */
  gboolean src_chunked;
  
  /* source read state */
  guint src_read_state;
  
  /* indicates that the current chunk is an EOF chunk */
  gboolean src_last_chunk; 
  
  /* indicates that this is the last chunk and that it was truncated 
   * because the body was over max_body_length */
  gboolean src_chunk_truncated;
  
  /* the number of bytes waiting to be read in the current chunk */
  guint64 src_chunk_left;
  
  /* the total number of bytes read during this transfer */
  guint64 src_whole_length;
  
  gboolean dst_chunked;
  guint dst_write_state;
  
  /* the number of bytes still to be written to the destination */
  guint64 dst_chunk_left;
  
  gchar dst_chunk_length_buf[32];
  guint dst_chunk_length_ofs;
  guint dst_chunk_length_end;
  guint dst_footer_ofs;
  
  /* the total number of bytes in the chunk being written */
  guint64 dst_chunk_length;
  
  /* the total number of transferred bytes on the write side */
  guint64 dst_whole_length;
  
};

extern ZClass HttpTransfer__class;


/* HttpTransfer implementation */

static GIOStatus 
http_transfer_src_read(ZTransfer2 *s, ZStream *stream, gchar *buf, gsize count, gsize *bytes_read, GError **err)
{
  HttpTransfer *self = Z_CAST(s, HttpTransfer);
  HttpProxy *owner = (HttpProxy *) s->owner;
  GError *local_error = NULL;
  gsize br;
  GIOStatus res = G_IO_STATUS_NORMAL;

  if (self->src_read_state == HTTP_SR_INITIAL)
    self->src_read_state = HTTP_SR_PUSH_HEADERS;
  if (self->src_read_state >= HTTP_SR_PUSH_HEADERS && self->src_read_state <= HTTP_SR_PUSH_HEADERS_MAX)
    {
      if (self->push_mime_headers && self->stacked_preamble->len > 0)
        {
          gint move;
          
          *bytes_read = 0;
          
          move = MIN(count, self->stacked_preamble->len - self->stacked_preamble_ofs);
          memmove(buf, self->stacked_preamble->str + self->stacked_preamble_ofs, move);
          self->stacked_preamble_ofs += move;
          *bytes_read = move;

          if (self->stacked_preamble_ofs == self->stacked_preamble->len)
            {
              z_transfer2_set_proxy_out(s, FALSE);
              self->src_read_state = HTTP_SR_READ_INITIAL;
            }
          return G_IO_STATUS_NORMAL;
        }
      else
        {
          self->src_read_state = HTTP_SR_READ_INITIAL;
        }
    }
  *bytes_read = 0;
  if (self->src_chunked)
    {
      /* read as a chunked stream */
      switch (self->src_read_state)
        {
        case HTTP_SR_READ_INITIAL:
          self->src_whole_length = 0;
          self->src_read_state = HTTP_SR_READ_CHUNK_LENGTH;
          /* fallthrough */
        case HTTP_SR_READ_CHUNK_LENGTH:
          {
            gchar line_buf[32], *line;
            gsize line_length;
            guint32 chunk_length;
            gchar *end;
            
            z_stream_line_set_poll_partial(stream, FALSE);
            res = z_stream_line_get(stream, &line, &line_length, NULL);
            z_stream_line_set_poll_partial(stream, TRUE);
            if (res == G_IO_STATUS_NORMAL)
              {
                /* a complete line was read, check if it is a valid chunk length */
                if (line_length >= sizeof(line_buf) - 1)
                  {
		    /*LOG
		      This message indicates that the chunk length line is too long.
		      It is likely caused by a buggy client or server.
		     */
                    z_proxy_log(self->super.owner, HTTP_VIOLATION, 1, "Chunk length line too long; line='%.*s'", (gint) line_length, line);
                    res = G_IO_STATUS_ERROR;
                    break;
                  }
                /* we already checked that line_buf is large enough */
                memcpy(line_buf, line, line_length);
                line_buf[line_length] = 0;
                chunk_length = strtoul(line_buf, &end, 16);
                
                if (end == line_buf)
                  {
                    /* hmm... invalid chunk length */
		    /*LOG
		      This message indicates that the chunk length is invalid.
		      It is likely caused by a buggy client or server.
		     */
                    z_proxy_log(self->super.owner, HTTP_VIOLATION, 1, "Invalid chunk length; line='%s'", line_buf);
                    res = G_IO_STATUS_ERROR;
                    break;
                  }
                
                /* 
                 * NOTE: the string  pointed by end is NUL terminated, thus
                 * we will not overflow our buffer
                 */
                
                while (*end == ' ')
                  end++;
                if (*end == ';')
                  {
                    /* ignore and strip chunk extensions */
                    *end = 0;
                  }
                if (*end)
                  {
                    /* hmm... invalid chunk length */
		    /*LOG
		      This message indicates that the chunk length is invalid.
		      It is likely caused by a buggy client or server.
		     */
                    z_proxy_log(self->super.owner, HTTP_VIOLATION, 1, "Invalid chunk length; line='%s'", line_buf);
                    res = G_IO_STATUS_ERROR;
                    break;
                  }
                
                if ((owner->max_chunk_length && chunk_length > owner->max_chunk_length) ||
                    (chunk_length & 0x80000000))
                  {
		    /*LOG
		      This message indicates that the length of the chunk is larger than allowed 
		      or is a negative number. Check the 'max_chunk_length' attribute.
		     */
                    z_proxy_log(self->super.owner, HTTP_POLICY, 2, "Chunk too large; length='%d', max_chunk_length='%d'", chunk_length, owner->max_chunk_length);
                    res = G_IO_STATUS_ERROR;
                    break;
                  }
                  
                if (owner->max_body_length && (guint) self->src_whole_length + chunk_length > owner->max_body_length)
                  {
                    /* this chunk would be over body_length limit */
                    
                    chunk_length = owner->max_body_length - self->src_whole_length;
                    self->src_chunk_left = chunk_length;
                    self->force_nonpersistent_mode = TRUE;
                    self->src_chunk_truncated = TRUE;
                  }
                self->src_chunk_left = chunk_length;
                self->src_last_chunk = chunk_length == 0;
                self->src_read_state = HTTP_SR_READ_CHUNK;
                /* fall through */
              }
            else
              break;
          }
        case HTTP_SR_READ_CHUNK:
          if (!self->src_last_chunk)
            {
              res = z_stream_read(stream, buf, MIN(self->src_chunk_left, count), &br, &local_error);
              if (res == G_IO_STATUS_NORMAL)
                {
                  self->src_whole_length += br;
                  self->src_chunk_left -= br;
                  *bytes_read = br;
                }
              else if (res == G_IO_STATUS_EOF)
                {
                  /* unexpected eof */
		  /*LOG
		    This message indicates that Zorp unexpectedly got EOF during
		    chunk encoded data transfer. It is likely a caused by a buggy client
		    or server.
		   */
                  z_proxy_log(self->super.owner, HTTP_VIOLATION, 1, "Unexpected EOF while dechunking stream;");
                  res = G_IO_STATUS_ERROR;
                  break;
                }
              if (self->src_chunk_left == 0)
                {
                  self->src_read_state = HTTP_SR_READ_FOOTER;
                }
              break;
            }
          else
            {
              self->src_read_state = HTTP_SR_READ_FOOTER;
              /* fallthrough */
            }
        case HTTP_SR_READ_FOOTER:
          {
            gchar *line;
            gsize line_length;
            
            if (!self->src_chunk_truncated)
              {
                z_stream_line_set_poll_partial(stream, FALSE);
                res = z_stream_line_get(stream, &line, &line_length, NULL);
                z_stream_line_set_poll_partial(stream, TRUE);
              }
            else
              {
                res = G_IO_STATUS_EOF;
              }
            if (res == G_IO_STATUS_NORMAL)
              {
                if (line_length != 0)
                  {
		    /*LOG
		      This message indicates that the chunk footer contains data.
		      It is likely caused by a buggy client or server.
		     */
                    z_proxy_log(self->super.owner, HTTP_VIOLATION, 1, "Chunk footer is not an empty line;");
                    res = G_IO_STATUS_ERROR;
                    break;
                  }
                if (self->src_last_chunk)
                  {
                    res = G_IO_STATUS_EOF;
                  }
                else
                  {
                    self->src_read_state = HTTP_SR_READ_CHUNK_LENGTH;
                    /* come back later */
                    res = G_IO_STATUS_AGAIN;
                  }
                break;
              }
            break;
          }
        }
    }
  else
    {
      /* copy until EOF or self->content_length bytes */
      if (self->content_length == HTTP_LENGTH_NONE)
        {
          res = G_IO_STATUS_EOF;
        }
      else
        {
          if (self->src_read_state == HTTP_SR_INITIAL)
            {
              self->src_whole_length = 0;
              self->src_read_state = HTTP_SR_READ_ENTITY;
            }
          
          if (self->content_length == HTTP_LENGTH_UNKNOWN)
            {
              if (owner->max_body_length && self->src_whole_length + count >= owner->max_body_length)
                {
                  count = owner->max_body_length - self->src_whole_length;
                }
              if (count == 0)
                {
                  self->force_nonpersistent_mode = TRUE;
                  res = G_IO_STATUS_EOF;
                }
              else
                res = z_stream_read(stream, buf, count, &br, &local_error);
            }
          else
            {
              /* for specified content-length, max_body_length has already
                 been processed, and content_length contains the number of
                 bytes to be transferred, but maximum max_body_length */                 
              if (self->content_length >= 0 && (guint64) self->content_length == self->src_whole_length)
                res = G_IO_STATUS_EOF;
              else
                res = z_stream_read(stream, buf, MIN(count, self->content_length - self->src_whole_length), &br, &local_error);
            }
          
          if (res == G_IO_STATUS_NORMAL)
            {
              self->src_whole_length += br;
              *bytes_read = br;
            }
        }
    }
  if (local_error)
    g_propagate_error(err, local_error);
  return res;
}

static GIOStatus
http_transfer_src_shutdown(ZTransfer2 *self G_GNUC_UNUSED, ZStream *s G_GNUC_UNUSED, GError **err G_GNUC_UNUSED)
{
  /* do nothing */
  return G_IO_STATUS_NORMAL;
}

static GIOStatus
http_transfer_dst_write_preamble(HttpTransfer *self, ZStream *stream, GError **err)
{
  GIOStatus res = G_IO_STATUS_NORMAL;
  GError *local_error = NULL;
  gsize bw;

  http_log_headers((HttpProxy *) self->super.owner, self->transfer_from, "postfilter");
  res = z_stream_write(stream, &self->preamble->str[self->preamble_ofs], self->preamble->len - self->preamble_ofs, &bw, &local_error);
  if (res == G_IO_STATUS_NORMAL)
    {
      self->preamble_ofs += bw;
      if (self->preamble_ofs != self->preamble->len)
        {
          res = G_IO_STATUS_AGAIN;
        }
    }
  else if (self->src_read_state == HTTP_SR_INITIAL && g_error_matches(local_error, G_IO_CHANNEL_ERROR, G_IO_CHANNEL_ERROR_PIPE))
    {
      /* we can only reattempt a connection if nothing was read from the
       * client, that's the reason behind src_read_state == INITIAL above */
      
      /* FIXME: this is a hack. A better solution would be to propagate
       * GError to the proxy so this case can be handled there cleanly */
       
      ((HttpProxy *) self->super.owner)->reattempt_connection = TRUE;
    }
  if (local_error)
    g_propagate_error(err, local_error);
  return res;
}

/* NOTE: this function assumes that ZTransfer2 does not change the buffer
 * between successive calls when an G_IO_STATUS_AGAIN is returned. This is
 * required for performance reasons, as otherwise this function would have
 * to copy the buffer contents to a private buffer and return
 * G_IO_STATUS_AGAIN while it is being flushed.*/
static GIOStatus 
http_transfer_dst_write(ZTransfer2 *s, ZStream *stream, const gchar *buf, gsize count, gsize *bytes_written, GError **err)
{
  HttpTransfer *self = Z_CAST(s, HttpTransfer);
  HttpProxy *owner = (HttpProxy *) self->super.owner;
  GError *local_error = NULL;
  gsize bw;
  GIOStatus res = G_IO_STATUS_NORMAL;
  
  *bytes_written = 0;
  
  if (self->dst_write_state == HTTP_DW_INITIAL)
    self->dst_write_state = HTTP_DW_POP_HEADERS;

  if (self->dst_write_state >= HTTP_DW_POP_HEADERS && self->dst_write_state <= HTTP_DW_POP_HEADERS_MAX)
    {
      if (self->push_mime_headers)
        {
          gsize i;
          
          for (i = 0; i < count; i++)
            {
              switch (self->dst_write_state)
                {
                case HTTP_DW_POP_HEADERS:
                  switch (buf[i])
                    {
                    case '\r':
                      self->dst_write_state = HTTP_DW_POP_HEADERS_CR;
                      break;
                    case '\n':
                      self->dst_write_state = HTTP_DW_POP_HEADERS_LF;
                      break;
                    default:
                      break;
                    }
                  break;
                case HTTP_DW_POP_HEADERS_CR:
                  switch (buf[i])
                    {
                    case '\n':
                      self->dst_write_state = HTTP_DW_POP_HEADERS_LF;
                      break;
                    default:
                      self->dst_write_state = HTTP_DW_POP_HEADERS;
                      break;
                    }
                  break;
                }
              if (self->dst_write_state == HTTP_DW_POP_HEADERS_LF)
                {
                  /* new line found */
                  self->dst_eol_count++;
                  if (self->dst_eol_count == 2)
                    {
                      /* end of headers */
                      i++;
                      self->dst_write_state = HTTP_DW_WRITE_PREAMBLE;
                      break;
                    }
                  else
                    {
                      self->dst_write_state = HTTP_DW_POP_HEADERS;
                    }
                }
              else if (self->dst_write_state == HTTP_DW_POP_HEADERS)
                self->dst_eol_count = 0;
                  
            }
          /* at this point we have either processed the whole buffer (i ==
           * count), or a small chunk of data is at the tail of our headers
           * to be ignored. In either case return G_IO_STATUS_NORMAL and the
           * number of processed bytes. */
           
          *bytes_written = i;
          self->stacked_preamble_read_bytes += i;
          return G_IO_STATUS_NORMAL;
        }
      else
        self->dst_write_state = HTTP_DW_WRITE_PREAMBLE;
    }

  if (self->dst_write_state == HTTP_DW_WRITE_PREAMBLE)
    {
      gboolean reformat_preamble = FALSE;
      
      if (self->super.child_content_length_hint_set)
        {
          /* we stay in persistent mode if possible */
	  /*LOG
	    This message reports that the stacked proxy sent a content-length hint on how much
	    data will be sent and the http proxy is using it to set the Content-Length header.
	   */
          z_proxy_log(owner, HTTP_DEBUG, 6, "Stacked proxy sent a content-length hint, using it; expected_content_length='%" G_GINT64_FORMAT "'", self->super.child_content_length_hint);
          g_string_sprintf(self->content_length_hdr->value, "%" G_GINT64_FORMAT, self->super.child_content_length_hint - self->stacked_preamble_read_bytes);
          self->content_length_hdr->present = TRUE;
          self->transfer_encoding_hdr->present = FALSE;
          self->dst_chunked = FALSE;
          reformat_preamble = TRUE;
        }
      else if (self->persistent_with_cl_hint_only)
        {
          /* when we require content-length hint to remain persistent and we
             have no content-length hint, we force ourselves to
             non-persistent mode */             
          self->force_nonpersistent_mode = TRUE;
          self->content_length_hdr->present = FALSE;
          reformat_preamble = TRUE;
        }
        
      if (self->force_nonpersistent_mode && owner->connection_mode == HTTP_CONNECTION_KEEPALIVE)
        {
          owner->connection_mode = owner->server_connection_mode = HTTP_CONNECTION_CLOSE;
          
          /* we must change our connection header right here as our core has
           * already made its decision, but we must override that */
          
          if (owner->connection_hdr)
            {
              g_string_assign(owner->connection_hdr->value, "close");
              reformat_preamble = TRUE;
            }
        }
      if (reformat_preamble)
        self->format_preamble_func(owner, FALSE, self->preamble);

      /* take care about the preamble (request/response itself) */
      res = http_transfer_dst_write_preamble(self, stream, &local_error);
      if (res != G_IO_STATUS_NORMAL)
        {
          goto propagate_exit;
        }
      self->dst_write_state = HTTP_DW_WRITE_INITIAL;
    }

    
  /* ok, now take care about the data, and possibly enchunk it on the way */
  if (self->dst_chunked)
    {
      switch (self->dst_write_state)
        {
        case HTTP_DW_WRITE_INITIAL:
          self->dst_write_state = HTTP_DW_FORMAT_CHUNK_LENGTH;
          self->dst_whole_length = 0;
          /* fallthrough */
        case HTTP_DW_FORMAT_CHUNK_LENGTH:
          {
            if (count == 0)
              { 
                res = G_IO_STATUS_NORMAL;
                break;
              }
            self->dst_chunk_length = 0;
            self->dst_chunk_left = count;
            g_snprintf(self->dst_chunk_length_buf, sizeof(self->dst_chunk_length_buf), "%" G_GINT64_MODIFIER "x\r\n", self->dst_chunk_left);
            self->dst_chunk_length_ofs = 0;
            self->dst_chunk_length_end = strlen(self->dst_chunk_length_buf);
            self->dst_write_state = HTTP_DW_WRITE_CHUNK_LENGTH;
          }
        case HTTP_DW_WRITE_CHUNK_LENGTH:
          {
            res = z_stream_write(stream, &self->dst_chunk_length_buf[self->dst_chunk_length_ofs], self->dst_chunk_length_end - self->dst_chunk_length_ofs, &bw, &local_error);
            if (res == G_IO_STATUS_NORMAL)
              {
                self->dst_chunk_length_ofs += bw;
                if (self->dst_chunk_length_ofs == self->dst_chunk_length_end)
                  self->dst_write_state = HTTP_DW_WRITE_CHUNK;
              }
            else
              {
                break;
              }
          /* fallthrough */
          }
        case HTTP_DW_WRITE_CHUNK:
          {
            /* NOTE: here lies the assumptions that ZTransfer2 neither
             * changes the buffer nor count when G_IO_STATUS_AGAIN
             * is returned */
            res = z_stream_write(stream, &buf[count - self->dst_chunk_left], self->dst_chunk_left, &bw, &local_error);
            if (res == G_IO_STATUS_NORMAL)
              {
                self->dst_chunk_length += bw;
                self->dst_chunk_left -= bw;
                if (self->dst_chunk_left == 0)
                  {
                    self->dst_write_state = HTTP_DW_WRITE_FOOTER;
                  }
                else
                  {
                    *bytes_written = 0;
                    res = G_IO_STATUS_AGAIN;
                    break;
                  }
              }
            else
              {
                break;
              }
          }
          self->dst_footer_ofs = 0;
        case HTTP_DW_WRITE_FOOTER:
          {
            gchar line_buf[] = "\r\n";
            g_assert(self->dst_footer_ofs < 2);
            res = z_stream_write(stream, &line_buf[self->dst_footer_ofs], 2 - self->dst_footer_ofs, &bw, &local_error);
            if (res == G_IO_STATUS_NORMAL)
              {
                self->dst_footer_ofs += bw;
                if (self->dst_footer_ofs == 2)
                  {
                    self->dst_whole_length += self->dst_chunk_length;
                    *bytes_written = self->dst_chunk_length;
                    self->dst_write_state = HTTP_DW_FORMAT_CHUNK_LENGTH;
                  }
              }
            else
              {
                break;
              }
          }
        }
    }
  else
    {
      res = z_stream_write(stream, buf, count, bytes_written, &local_error);
    }
 propagate_exit:
  if (local_error)
    g_propagate_error(err, local_error);
  return res;
}

static GIOStatus
http_transfer_dst_shutdown(ZTransfer2 *s, ZStream *stream, GError **err)
{
  HttpTransfer *self = Z_CAST(s, HttpTransfer);
  GIOStatus res = G_IO_STATUS_NORMAL;
  GError *local_error = NULL;
  gsize bw;
  gboolean delay_transfer;
  
  /* delay preamble and closing chunk if we want to write an error page, we can do this if:
   * 
   * - we are not suppressing data entity (e.g. HEAD)
   * - we are expecting data (e.g. response) or the request contains data (e.g. POST)
   */
  delay_transfer = (self->dst_write_state == HTTP_DW_INITIAL && 
                    (!!(s->status & (ZT2S_FAILED+ZT2S_ABORTED)) || (self->super.stack_decision != Z_ACCEPT))) && 
                    !self->suppress_data &&
                    (self->expect_data || self->content_length != HTTP_LENGTH_NONE);
  if (!delay_transfer)
    {
      if (self->dst_write_state == HTTP_DW_INITIAL || self->dst_write_state == HTTP_DW_WRITE_PREAMBLE)
        {
          self->dst_write_state = HTTP_DW_WRITE_PREAMBLE;
          res = http_transfer_dst_write_preamble(self, stream, &local_error);
        }
      if (res == G_IO_STATUS_NORMAL)
        {
          if (self->content_length != HTTP_LENGTH_NONE && self->dst_chunked)
            {
              gchar line_buf[] = "0\r\n\r\n";
              
              res = z_stream_write(stream, line_buf, 5, &bw, &local_error);
              if (bw != 5)
                {
                  res = G_IO_STATUS_ERROR;
                }
            }
        }
    }
  if (local_error)
    g_propagate_error(err, local_error);
  return res;
}

static gboolean
http_transfer_stack_proxy(ZTransfer2 *s, ZStackedProxy **stacked)
{
  HttpTransfer *self = Z_CAST(s, HttpTransfer);
  ZPolicyObj *proxy_stack_tuple = NULL, *stack_object = NULL;
  gint side = self->transfer_from;
  gint stack_type = HTTP_STK_NONE;
  gboolean called;
  gboolean success = FALSE;
  HttpProxy *owner = Z_CAST(s->owner, HttpProxy);
  HttpHeaders *headers = &owner->headers[self->transfer_from];
  HttpHeader *hdr;
  
  /* query python for a stacked proxy */

  if (self->suppress_data || (self->transfer_type != HTTP_TRANSFER_NORMAL && self->transfer_type != HTTP_TRANSFER_TO_BLOB))
    {
      *stacked = NULL;
      return TRUE;
    }

  
  z_policy_lock(self->super.owner->thread);
  
  proxy_stack_tuple = z_policy_call(self->super.owner->handler, "requestStack", z_policy_var_build("(i)", side), &called, self->super.owner->session_id);
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
      z_proxy_log(self->super.owner, HTTP_POLICY, 3, "Invalid stacking tuple returned by policy; side='%d'", side);
      goto unref_unlock;
    }
  if (stack_type < HTTP_STK_NONE || stack_type > HTTP_STK_MIME)
    {
      /*LOG
        This message indicates that the request_stack or response_stack hash
	contains an invalid stacking type. Check your Zorp configuration.
       */
      z_proxy_log(self->super.owner, HTTP_POLICY, 3, "Invalid stacking type; type='%d'", stack_type);
      stack_type = HTTP_STK_NONE;
      goto unref_unlock;
    }
    
  success = TRUE;
  if (stack_type == HTTP_STK_MIME)
    self->push_mime_headers = TRUE;

  /* we don't stack anything, if
     1) we suppress data
     2) data is not indicated by either the presence of some header fields nor do we expect data
  */
  if (!(self->expect_data || self->push_mime_headers || http_lookup_header(headers, "Transfer-Encoding", &hdr) || http_lookup_header(headers, "Content-Length", &hdr)))
    {
      *stacked = NULL;
      goto unref_unlock;
    }
  
  if (stack_type != HTTP_STK_NONE)
    success = z_proxy_stack_object(s->owner, stack_object, stacked, NULL);
 unref_unlock:
  z_policy_var_unref(proxy_stack_tuple);
  z_policy_unlock(self->super.owner->thread);
  return success;
}

static gboolean
http_transfer_setup(ZTransfer2 *s)
{
  HttpTransfer *self = Z_CAST(s, HttpTransfer);
  HttpProxy *owner = Z_CAST(s->owner, HttpProxy);
  HttpHeaders *headers = &owner->headers[self->transfer_from];
  gboolean chunked; /* original entity is chunked */
  
  z_proxy_enter(owner);
  if (!self->suppress_data)
    {
      if (http_lookup_header(headers, "Transfer-Encoding", &self->transfer_encoding_hdr))
        {
          chunked = self->transfer_encoding_hdr->present && strcasecmp(self->transfer_encoding_hdr->value->str, "chunked") == 0;
        }
      else
        {
          chunked = FALSE;
          self->transfer_encoding_hdr = http_add_header(headers, "Transfer-Encoding", 17, "", 0);
        }
        
      if (http_lookup_header(headers, "Content-Length", &self->content_length_hdr))
        {
          gchar *end;
          
          if (self->content_length_hdr->present)
            {
              self->content_length = strtoll(self->content_length_hdr->value->str, &end, 10);
              if (self->content_length < 0)
                {
                  self->content_length = self->expect_data ? HTTP_LENGTH_UNKNOWN : HTTP_LENGTH_NONE;
                }
              if ((guint) (end - self->content_length_hdr->value->str) != self->content_length_hdr->value->len)
                {  
                  /* content-length not a number */
                  /*LOG
                    This message indicates that the Content-Length headers value
                    is not a valid number. It is likely caused by a buggy client or server.
                   */
                  z_proxy_log(owner, HTTP_VIOLATION, 1, "The header 'Content-Length' was present, but is not a number; content_length='%s'", self->content_length_hdr->value->str);
                  z_proxy_return(owner, FALSE);
                }
            }
          else
            {
              self->content_length = self->expect_data || chunked ? HTTP_LENGTH_UNKNOWN : HTTP_LENGTH_NONE;
            }
        }
      else
        {
          self->content_length_hdr = http_add_header(headers, "Content-Length", 14, "", 0);
          self->content_length = self->expect_data || chunked ? HTTP_LENGTH_UNKNOWN : HTTP_LENGTH_NONE;
        }
        
      self->transfer_encoding_hdr->present = FALSE;
      self->content_length_hdr->present = FALSE;
      
      if (self->push_mime_headers)
        {
          self->format_preamble_func((HttpProxy *) self->super.owner, TRUE, self->stacked_preamble);
          g_string_append(self->stacked_preamble, "\r\n");
          z_transfer2_set_proxy_out(s, TRUE);
        }
      
      self->src_chunked = FALSE;
      self->dst_chunked = FALSE;

      if (self->transfer_type != HTTP_TRANSFER_NORMAL)
        {
          if (self->transfer_type == HTTP_TRANSFER_TO_BLOB)
            {
              /* we are transferring into the request_data blob, we don't want chunking in the destination  */
              if (chunked)
                self->src_chunked = TRUE;
            }
          else
            {
              /* we are transferring from the request_data blob to the
               * server, we don't need chunking as we know the exact size of
               * the data */
              self->content_length = owner->request_data->size;
              g_string_sprintf(self->content_length_hdr->value, "%" G_GINT64_FORMAT, owner->request_data->size);
              self->content_length_hdr->present = TRUE;
            }
        }
      else if (self->super.stacked)
        {
          if (chunked && (self->transfer_to == EP_SERVER || (owner->proto_version[self->transfer_to] > 0x0100)))
            {
              self->src_chunked = TRUE;
              self->dst_chunked = TRUE;
            }
          else if (self->transfer_to == EP_CLIENT && self->expect_data)
            {
              if (owner->max_body_length && self->content_length != HTTP_LENGTH_UNKNOWN && 
                  (guint) self->content_length > owner->max_body_length)
                {
                  self->content_length = owner->max_body_length;
                  self->force_nonpersistent_mode = TRUE;
                }
              if (owner->proto_version[self->transfer_to] > 0x0100 && owner->proto_version[self->transfer_from] >= 0x0100)
                {
                  /* The original entity is not chunked, we enchunk it to
                   * avoid bufferring and keeping the connection open. For
                   * this we need HTTP/1.1 on the client and at least
                   * HTTP/1.0 on the server to be able to transmit headers.
                   *
                   * Transfer-Encoding is added, Content-Length is removed,
                   * version is bumped to HTTP/1.1
                   */
                  self->src_chunked = FALSE;
                  self->dst_chunked = TRUE;
                  owner->proto_version[self->transfer_from] = 0x0101;
                }
              else
                {
                  /* chunking is not supported, the entity's end is indicated by an EOF
                   * neither Content-Length nor Transfer-Encoding is added, persisency
                   * is retained only if a content-length hint is received.
                   */
                  if (owner->proto_version[self->transfer_from] >= 0x0100)                    
                    self->persistent_with_cl_hint_only = TRUE;
                  else
                    self->force_nonpersistent_mode = TRUE;
                  self->src_chunked = self->dst_chunked = FALSE;

                }
            }
          else
            {
              /* sending to the server, the client sends it unchunked, but we add chunking to avoid buffering */
              
              /* NOTE: some servers do not accept chunked data for methods other
               * than POST, but those do not usually have entity either */
              
              if (self->content_length > 0 || (self->expect_data && self->content_length == HTTP_LENGTH_UNKNOWN))
                {
                  self->src_chunked = FALSE;
                  self->dst_chunked = TRUE;
                  
                  /* NOTE: we only change server protocol version as
                   * otherwise some defaults might change (e.g. connection
                   * mode) */
                  if (self->transfer_from == EP_SERVER)
                    owner->proto_version[self->transfer_from] = 0x0101;
                }
              else if (self->content_length != 0)
                {
                  self->content_length = HTTP_LENGTH_NONE;
                }
            }
          
        }
      else
        {
          /* there's no stacked proxy */
          if (chunked)
            {
              self->src_chunked = TRUE;
              self->dst_chunked = TRUE;
            }
          else if (self->content_length >= 0)
            {
              /* entity with specified length */
              if (owner->max_body_length && self->content_length != HTTP_LENGTH_UNKNOWN && 
                  (guint) self->content_length > owner->max_body_length)
                {
                  self->content_length = owner->max_body_length;
                  self->force_nonpersistent_mode = TRUE;
                }
            }
          else if (self->content_length == HTTP_LENGTH_UNKNOWN)
            {
              /* EOF terminated entity, can only happen for server->client direction */
              
              g_assert(self->transfer_from == EP_SERVER);
              if (owner->keep_persistent && owner->proto_version[self->transfer_to] > 0x0100 && owner->proto_version[self->transfer_from] >= 0x0100)
                {
                  /* client supports chunking, server can transfer headers, convert it */
                  self->src_chunked = FALSE;
                  self->dst_chunked = TRUE;
                  owner->server_connection_mode = HTTP_CONNECTION_CLOSE;
                  owner->proto_version[self->transfer_from] = 0x0101;
                }
              else if (owner->connection_mode == HTTP_CONNECTION_KEEPALIVE)
                {
                  /* client does not support chunking or we are not in keep_persistent mode, 
                   * no way to keep it persistent */
                  g_string_assign(owner->connection_hdr->value, "close");
                  owner->connection_hdr->present = TRUE;
                  owner->connection_mode = HTTP_CONNECTION_CLOSE;
                }
            }
        }
      /* NOTE: the headers here are not final, if a content-length hint is received, the
       * content-length header will be added and transfer-encoding removed */
      if (self->dst_chunked)
        {
          self->content_length_hdr->present = FALSE;
          self->transfer_encoding_hdr->present = TRUE;
          g_string_assign(self->transfer_encoding_hdr->value, "chunked");
        }
      else if (self->content_length >= 0)
        {
          self->transfer_encoding_hdr->present = FALSE;
          g_string_sprintf(self->content_length_hdr->value, "%" G_GINT64_FORMAT, self->content_length);
          self->content_length_hdr->present = TRUE;
          
        }
    }
  else
    {
      self->content_length = HTTP_LENGTH_NONE;
    }

  switch (self->content_length)
    {
    case HTTP_LENGTH_UNKNOWN:
      self->super.our_content_length_hint_set = FALSE;
      break;
      
    case HTTP_LENGTH_NONE:
    default:
      self->super.our_content_length_hint_set = TRUE;
      self->super.our_content_length_hint = self->content_length;
      if (self->super.our_content_length_hint > 0)
        self->super.our_content_length_hint += self->stacked_preamble->len;
      break;
    }
  self->format_preamble_func((HttpProxy *) self->super.owner, FALSE, self->preamble);
  z_proxy_return(owner, TRUE);
}

static ZTransfer2Result
http_transfer_run(ZTransfer2 *s)
{
  HttpTransfer *self = Z_CAST(s, HttpTransfer);
  GError *local_error = NULL;
  
  if ((self->content_length != HTTP_LENGTH_NONE || self->push_mime_headers) && self->content_length != 0)
    {
      return Z_SUPER(self, ZTransfer2)->run(&self->super);
    }
  if (z_transfer2_src_shutdown(s, z_transfer2_get_stream(s, ZT2E_SOURCE), &local_error) != G_IO_STATUS_NORMAL)
    {
      g_error_free(local_error);
      return ZT2_RESULT_ABORTED;
    }
  if (z_transfer2_dst_shutdown(s, z_transfer2_get_stream(s, ZT2E_DEST), &local_error) != G_IO_STATUS_NORMAL)
    {
      g_error_free(local_error);
      return ZT2_RESULT_ABORTED;
    }
  return ZT2_RESULT_FINISHED;
}

static HttpTransfer *
http_transfer_new(HttpProxy *owner, 
                  gint transfer_type,
                  guint from, ZStream *from_stream, 
                  guint to, ZStream *to_stream, 
                  gboolean expect_data, gboolean suppress_data, 
                  HttpTransferPreambleFunc format_preamble)
{
  HttpTransfer *self;
  
  z_proxy_enter(owner);
  self = Z_CAST(z_transfer2_new(Z_CLASS(HttpTransfer), 
                               &owner->super, owner->poll, 
                               from_stream, to_stream, 
                               owner->buffer_size, 
                               owner->timeout, 
                               0), 
                HttpTransfer);
  self->transfer_from = from;
  self->transfer_to = to;
  self->transfer_type = transfer_type;
  self->format_preamble_func = format_preamble;
  self->preamble = g_string_sized_new(0);
  self->stacked_preamble = g_string_sized_new(0);
  self->force_nonpersistent_mode = FALSE;
  self->expect_data = expect_data;
  self->suppress_data = suppress_data;
  z_proxy_return(owner, self);
}


static void
http_transfer_free_method(ZObject *s)
{
  HttpTransfer *self = Z_CAST(s, HttpTransfer);
  
  g_string_free(self->preamble, TRUE);
  g_string_free(self->stacked_preamble, TRUE);
  z_transfer2_free_method(s);
}

ZTransfer2Funcs http_transfer_funcs =
{
  {
    Z_FUNCS_COUNT(ZTransfer2),
    http_transfer_free_method,
  },
  .src_read = http_transfer_src_read,
  .dst_write = http_transfer_dst_write,
  .src_shutdown = http_transfer_src_shutdown,
  .dst_shutdown = http_transfer_dst_shutdown,
  .stack_proxy = http_transfer_stack_proxy,
  .setup = http_transfer_setup,
  .run = http_transfer_run,
  .progress = NULL
};

ZClass HttpTransfer__class =
{
  Z_CLASS_HEADER,
  &ZTransfer2__class,
  "HttpTransfer",
  sizeof(HttpTransfer),
  &http_transfer_funcs.super
};

gboolean
http_data_transfer(HttpProxy *self, gint transfer_type, guint from, ZStream *from_stream, guint to, ZStream *to_stream, gboolean expect_data, gboolean suppress_data, HttpTransferPreambleFunc format_preamble)
{
  HttpTransfer *t;
  gboolean res = TRUE;
  ZTransfer2Result tr;

  /*
   * tell transfer not to send the preamble when data is expected (e.g.
   * response & response body). This makes it possible to display an error
   * page instead 
   */
  
  if (transfer_type != HTTP_TRANSFER_TO_BLOB)
    {
      guint one = 1;
      guint fd = z_stream_get_fd(to_stream);
      setsockopt(fd, SOL_TCP, TCP_CORK, &one, sizeof(one));
    }
  t = http_transfer_new(self, transfer_type, from, from_stream, to, to_stream, expect_data, suppress_data, format_preamble);
  if (!t || !z_transfer2_start(&t->super))
    {
      /*LOG
        This message indicates that the processed request was invalid, and
	the data transfer failed.
       */
      z_proxy_log(self, HTTP_ERROR, 2, "Invalid request, data transfer failed;");
      g_string_assign(self->error_info, "Invalid request, data transfer failed;");
      if (t)
        z_object_unref(&t->super.super);
      return FALSE;
    }
  do
    {
      tr = z_transfer2_run(&t->super);
    }
  while (tr == ZT2_RESULT_SUSPENDED);

  if (transfer_type != HTTP_TRANSFER_TO_BLOB)
    {
      guint zero = 0;
      guint fd = z_stream_get_fd(to_stream);
      setsockopt(fd, SOL_TCP, TCP_CORK, &zero, sizeof(zero));
    }

  if (tr == ZT2_RESULT_FAILED)
    z_transfer2_rollback(&t->super);

  res = (tr != ZT2_RESULT_FAILED) && (tr != ZT2_RESULT_ABORTED);
  
  if (!res)
    {
      /* transfer was not successful */
      /*LOG
        This message reports that the data transfer failed.
       */
      z_proxy_log(self, HTTP_ERROR, 2, "Data transfer failed;");
      g_string_assign(self->error_info, "Data transfer failed.");
    }
  
  /* transfer was successful, check if the stacked proxy told us something important */
  if (t->super.stack_decision != Z_ACCEPT)
    {
      /*LOG
        This message indicates that the stacked proxy returned the
        specified verdict about the content. Check the stacked proxy log
        for further information.
       */
      z_proxy_log(self, HTTP_ERROR, 2, "Stacked proxy decision; verdict='%d', info='%s'", t->super.stack_decision, t->super.stack_info->str);
      if (t->super.stack_info->len)
        g_string_assign(self->error_info, t->super.stack_info->str);
      else
        g_string_sprintf(self->error_info, "Stacked proxy did not accept this content (%d).", t->super.stack_decision);
    }
  else if (res)
    {
      /*LOG
        This message indicates that the stacked proxy accepted the
        content. 
       */
      z_proxy_log(self, HTTP_DEBUG, 6, "Stacked proxy accepted data;");
    }
      

  if (t->dst_write_state == HTTP_DW_INITIAL)
    {
      /* our write state is HTTP_DW_INITIAL, this means that we never transmitted:
       *  * a request/response line
       *  * headers
       *  * data body
       * This means that we need to return with some kind of error code to ensure
       * that something gets back to the client */
       
      if (t->super.stack_decision != Z_ACCEPT)
        self->error_code = HTTP_MSG_BAD_CONTENT;
      else
        self->error_code = HTTP_MSG_IO_ERROR;
      
      res = FALSE;
    }
  else if (!res)
    {
      /* unable to write error page */
      self->error_code = 0;
    }

  z_object_unref(&t->super.super);
  return res;
}

