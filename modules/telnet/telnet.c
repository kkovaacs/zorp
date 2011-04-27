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
 * $Id: telnet.c,v 1.49 2004/08/25 12:59:31 bazsi Exp $
 *
 * Author: Hidden
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include "telnet.h"
#include "telnetpolicy.h"
#include "telnetoption.h"

#include <zorp/thread.h>
#include <zorp/registry.h>
#include <zorp/log.h>
#include <zorp/policy.h>
#include <zorp/io.h>
#include <zorp/stream.h>
#include <zorp/pystruct.h>
#include <zorp/pyaudit.h>

#include <ctype.h>
#include <netinet/in.h>

static TelnetOptions telnet_options_table[] =
{
  { TELNET_OPTION_TERMINAL_TYPE,      telnet_opt_terminal_type },
  { TELNET_OPTION_TERMINAL_SPEED,     telnet_opt_terminal_speed },
  { TELNET_OPTION_X_DISPLAY_LOCATION, telnet_opt_x_display },
  { TELNET_OPTION_ENVIRONMENT,        telnet_opt_new_env },
  { TELNET_OPTION_NAWS,               telnet_opt_naws },
  { 0,                                NULL }
};


/**
 * telnet_set_defaults:
 * @self: 
 *
 * 
 */
static void
telnet_set_defaults(TelnetProxy *self)
{
  int           i;

  z_proxy_enter(self);
  self->telnet_policy = z_dim_hash_table_new(1, 2, DIMHASH_WILDCARD, DIMHASH_WILDCARD);
  for (i = 0; i < 256; i++)
      self->telnet_options[i] = NULL;

  self->policy_name = g_string_new("");
  self->policy_value = g_string_new("");
  self->timeout = 600000;
  self->negotiation = g_hash_table_new(g_str_hash, g_str_equal);
  z_proxy_return(self);
}


/**
 * telnet_register_vars:
 * @self: 
 *
 * 
 */
static void
telnet_register_vars(TelnetProxy *self)
{
  z_proxy_enter(self);
  z_proxy_var_new(&self->super, "option",
                  Z_VAR_TYPE_DIMHASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->telnet_policy);

  z_proxy_var_new(&self->super, "negotiation",
                  Z_VAR_TYPE_HASH | Z_VAR_GET | Z_VAR_GET_CONFIG,
                  self->negotiation);

  z_proxy_var_new(&self->super, "current_var_name",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->policy_name);

  z_proxy_var_new(&self->super, "current_var_value",
                  Z_VAR_TYPE_STRING | Z_VAR_GET | Z_VAR_SET,
                  self->policy_value);

  z_proxy_var_new(&self->super, "timeout", 
                  Z_VAR_TYPE_INT | Z_VAR_GET | Z_VAR_SET_CONFIG,
                  &self->timeout);


  z_proxy_return(self);
}


/**
 * telnet_config_init:
 * @self: 
 *
 * 
 */
static void
telnet_config_init(TelnetProxy *self)
{
  int i;
  
  z_proxy_enter(self);
  for (i = 0; i < 256; i++)
    {
      self->options[i][EP_CLIENT] = 0;
      self->options[i][EP_SERVER] = 0;
    }

  for (i = 0; telnet_options_table[i].option_check != NULL; i++)
    self->telnet_options[telnet_options_table[i].option] = telnet_options_table[i].option_check;

  for (i = 0; i < EP_MAX; i++)
    {
      self->write_buffers[i].buf = g_new0(guchar, TELNET_BUFFER_SIZE);
      self->write_buffers[i].size = TELNET_BUFFER_SIZE;
      self->write_buffers[i].ofs = self->write_buffers[i].end = 0;
    }
  z_proxy_return(self);
}


/**
 * telnet_stream_read:
 * @self: 
 * @buf: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
static GIOStatus
telnet_stream_read(TelnetProxy *self, ZIOBuffer *buf, guint ep)
{
  GIOStatus     res;
  gsize         len;

  z_proxy_enter(self);
  len = 0;
  res = z_stream_read(self->super.endpoints[ep], buf->buf + buf->end, sizeof(buf->buf) - buf->end, &len, NULL);
  buf->end += len;
  switch (res)
    {
    case G_IO_STATUS_NORMAL:
      z_proxy_return(self, res);
    
    case G_IO_STATUS_EOF:
      z_proxy_return(self, res);
    
    case G_IO_STATUS_AGAIN:
      z_proxy_return(self, res);
    
    default:
    break;
    }
  z_proxy_return(self, G_IO_STATUS_ERROR);
}


/**
 * telnet_stream_write:
 * @self: 
 * @buf: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
static GIOStatus
telnet_stream_write(TelnetProxy *self, ZIOBufferDyn *buf, guint ep)
{
  GIOStatus     res;
  gsize         bytes_written;

  z_proxy_enter(self);
  if (buf->ofs != buf->end)
    {
      res = z_stream_write(self->super.endpoints[ep], &buf->buf[buf->ofs], buf->end - buf->ofs, &bytes_written, NULL);
      switch (res)
        {
        case G_IO_STATUS_NORMAL:
          buf->ofs += bytes_written;
          break;
        
        case G_IO_STATUS_AGAIN:
          break;
        
        default:
          z_proxy_return(self, G_IO_STATUS_ERROR);
        }
      
      if (buf->ofs != buf->end)
        {
          self->super.endpoints[ep]->want_write = TRUE;
          z_proxy_return(self, G_IO_STATUS_AGAIN);
        }
    }
  z_proxy_return(self, G_IO_STATUS_NORMAL);
}


/**
 * telnet_copy_buf:
 * @to: 
 * @from: 
 * @bytes: 
 *
 * 
 *
 * Returns:
 * 
 */
static gint
telnet_copy_buf(ZIOBufferDyn *to, ZIOBuffer *from, guint bytes)
{
  guint         i;

  z_enter();
  if ((i = to->size - to->end) < bytes)
    {
      /* we must allocate more buffer space */
      to->size += (1 + bytes / TELNET_BUFFER_SIZE) * TELNET_BUFFER_SIZE;
      to->buf = g_realloc(to->buf, to->size);
    }
  for (i = 0; to->end < to->size && from->ofs < from->end && i < bytes; to->end++, from->ofs++, i++)
      to->buf[to->end] = from->buf[from->ofs];
  z_return(i == bytes);
}


/**
 * telnet_check_suboption:
 * @self: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
static guint
telnet_check_suboption(TelnetProxy *self, guint ep)
{
  guint                 res;
  TelnetOptionFunction  check_func;
  ZIOBuffer             *sbuf = &self->suboptions[ep];
  guchar                buf[TELNET_BUFFER_SIZE + 1];
  guint                 i, j;

  z_proxy_enter(self);
  /* check if allowed in this session */
  if (!(self->options[self->opneg_option[ep]][OTHER_EP(ep)] & (SENT_WILL | GOT_DO)) &&
      !(self->options[self->opneg_option[ep]][ep] & (SENT_WILL | GOT_DO)))
    {
      z_proxy_log(self, TELNET_VIOLATION, 3, "Option not allowed in the session; option='%d'", self->opneg_option[ep]);
      z_proxy_return(self, TELNET_CHECK_ABORT);
    }

  /* check if valid */
  if ((check_func = self->telnet_options[self->opneg_option[ep]]) == NULL)
    {
      /* option has no suboption check function */
      /* copy suboption negotiation buffer into policy_value */
      for (j = 0, i = sbuf->ofs; i < sbuf->end; j++, i++)
          buf[j] = sbuf->buf[i];
      g_string_assign(self->policy_name, "");
      g_string_assign(self->policy_value, buf);
      /* call policy check */
      res = telnet_policy_suboption(self, buf[0], "", buf);
    }
  else
    {
      /* call check function, and check function calls policy */
      res = check_func(self, ep);
    }
  z_proxy_return(self, res);
}


/**
 * telnet_process_opneg:
 * @self: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
static guint
telnet_process_opneg(TelnetProxy *self, guint ep)
{
  guint         res;

  z_proxy_enter(self);
  /*
   * ask policy if option is enabled
   */
  res = telnet_policy_option(self);
  if (res == TELNET_CHECK_OK)
    {
      switch (self->command[ep])   
        {
        case TELNET_CMD_WILL:
          /* set flag which means this side has sent a WILL */
          self->options[self->opneg_option[ep]][ep] |= SENT_WILL;
          break;

        case TELNET_CMD_WONT:
          /* set flag which means this side has sent a WONT */
          self->options[self->opneg_option[ep]][ep] &= ~GOT_DO;
          break;

        case TELNET_CMD_DO:
          /* set the other side's flag, indicating that
           * its WILL was accepted by the other side */
          self->options[self->opneg_option[ep]][OTHER_EP(ep)] |= GOT_DO;
          break;

        case TELNET_CMD_DONT:
          /* clear the other side's WILL flag, indicating that
           * its WILL was refused */
          self->options[self->opneg_option[ep]][OTHER_EP(ep)] &= ~SENT_WILL;
          break;

        default:
          z_proxy_log(self, TELNET_VIOLATION, 2, "Unknown command; command='%d'", self->command[ep]);
          break;
        }
    }
  z_proxy_return(self, res);
}


/**
 * telnet_process_command:
 * @self: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
static guint
telnet_process_command(TelnetProxy *self, guint ep)
{
  ZPolicyObj    *res = NULL;
  guint         option_needed;
  gchar         cmd_str[5];
  guint         ret_status;

  z_proxy_enter(self);
  /* 
   * allow commands defined in RFC 854
   * these are important, and must be implemented
   */
  
  /* NOTE: this triggers a warning in gcc as the second part of the
   * condition is always TRUE as guchar is always less-or-equal than 255,
   * this is true, but I leave the condition intact as in the possible case
   * command is changed to int the condition might be perfectly valid
   */
  if (self->command[ep] >= 240)
    z_proxy_return(self, TELNET_CHECK_OK);
  /* 
   * allow negotiated commands
   * these were allowed during a negotiation
   */
  g_snprintf(cmd_str, sizeof(cmd_str), "%hu", self->command[ep]);
  z_policy_lock(self->super.thread);
  res = g_hash_table_lookup(self->negotiation, cmd_str);
  if (res != NULL)
    {
      if (!z_policy_var_parse(res, "i", &option_needed))
        {
          z_proxy_log(self, TELNET_POLICY, 2, "Value in negotiation table bad; command='%d'", self->command[ep]);
          z_policy_unlock(self->super.thread);
          z_proxy_return(self, TELNET_CHECK_REJECT); 
        }
      z_proxy_trace(self, "Changed needed negotiated option; command='%s', option='%d'", cmd_str, option_needed);
    }
  else
    {
      option_needed = self->command[ep];
    }
  z_policy_unlock(self->super.thread);
  ret_status = TELNET_CHECK_REJECT;
  if (option_needed == 255)
    {
      ret_status = TELNET_CHECK_OK;
    }
  else if (option_needed > 255)
    {
      z_proxy_log(self, TELNET_POLICY, 2, "Value in negotation table out of range; command='%d', value='%d'", self->command[ep], option_needed);
    }
  else
    {
      z_proxy_trace(self, "Option state check; option='%d', state='%d:%d'", option_needed, self->options[option_needed][ep], self->options[option_needed][OTHER_EP(ep)]);
      if (self->options[option_needed][ep] & (SENT_WILL | GOT_DO))
        ret_status = TELNET_CHECK_OK;
    } /* reject everything else */
  z_proxy_return(self, ret_status);
} 


/**
 * telnet_process_buf:
 * @self: 
 * @buf: 
 * @dbuf: 
 * @odbuf: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
static gboolean
telnet_process_buf(TelnetProxy *self, ZIOBuffer *buf, ZIOBufferDyn *dbuf, ZIOBufferDyn *odbuf, guint ep)
{
  guint         ptr;
  guint         res;
  guchar        byte;
  ZIOBuffer     *sbuf = &self->suboptions[ep];
  ZIOBuffer     tbuf;

  z_proxy_enter(self);
  z_proxy_trace(self, "telnet_process_buf called side='%s'", WHICH_EP(ep));
  dbuf->ofs = dbuf->end = 0;
  ptr = buf->ofs;
  while (ptr < buf->end)
    {   
      z_proxy_log(self, TELNET_DEBUG, 7, "Processing buffer; state='%d'", self->state[ep]);
      switch (self->state[ep])
        {
        case TELNET_DATA:
          while (ptr < buf->end && buf->buf[ptr] != TELNET_IAC)
            ptr++;
          /* if not in urgent mode, write out data */
          res = telnet_copy_buf(dbuf, buf, ptr - buf->ofs);
                                 
          if (!res)
            {
              z_proxy_log(self, TELNET_ERROR, 3, "Output buffer full; side='%s'", WHICH_EP(OTHER_EP(ep)));
              z_proxy_return(self, FALSE);
            }
          else if (ptr >= buf->end)
              buf->ofs = ptr; /* set buffer offset pointer as if data was written */

          if (ptr < buf->end)
            {
              self->state[ep] = TELNET_GOT_IAC;
              ptr++;
            }
          break;

        case TELNET_GOT_IAC:
          self->command[ep] = buf->buf[ptr++];
          /* telnet option negotiation */
          if (self->command[ep] == TELNET_CMD_WILL ||
              self->command[ep] == TELNET_CMD_WONT ||
              self->command[ep] == TELNET_CMD_DO ||
              self->command[ep] == TELNET_CMD_DONT)
            {
              self->state[ep] = TELNET_GOT_OPNEG;
            }
          /* telnet suboption negotiation */
          else if (self->command[ep] == TELNET_CMD_SB)
            {
              self->state[ep] = TELNET_GOT_SB;
            }
          /* telnet datamark */
          else if (self->command[ep] == TELNET_CMD_DATAMARK)
            {
              self->state[ep] = TELNET_DATA;
            }
          /* invalid commands in this state, drop them */
          else if (self->command[ep] == TELNET_CMD_SE)
            {
              self->state[ep] = TELNET_DATA;
              z_proxy_log(self, TELNET_VIOLATION, 2, "Illegal command in stream; command='%d'", self->command[ep]);
            }
          /* else send it to the other side */
          else
            {
              res = telnet_process_command(self, ep);
              self->state[ep] = TELNET_DATA;
              if (res == TELNET_CHECK_OK)
                {
                  res = telnet_copy_buf(dbuf, buf, ptr - buf->ofs);
                  if (!res)
                    {
                      z_proxy_log(self, TELNET_ERROR, 3, "Output buffer full; side='%s'", WHICH_EP(OTHER_EP(ep)));
                      z_proxy_return(self, FALSE);
                    }
                }
              else
                {
                  buf->ofs = ptr;
                  z_proxy_log(self, TELNET_VIOLATION, 2, "Illegal command; command='%d'", self->command[ep]);
                }
            }
          z_proxy_log(self, TELNET_DEBUG, 6, "Processing command; state='TELNET_GOT_IAC', cmd='%d'", self->command[ep]);
          break;

        case TELNET_GOT_OPNEG:
          /* get option number from buffer */
          self->opneg_option[ep] = buf->buf[ptr++];
          z_proxy_log(self, TELNET_DEBUG, 6, "Processing option negotiation; state='TELNET_GOT_OPNEG', option='%d'", self->opneg_option[ep]);

          /* check if valid and allowed */
          res = telnet_process_opneg(self, ep);
          switch (res)
            {
            case TELNET_CHECK_OK:
              res = telnet_copy_buf(dbuf, buf, ptr - buf->ofs);
              if (!res)
                {
                  z_proxy_log(self, TELNET_ERROR, 3, "Output buffer full; side='%s'", WHICH_EP(OTHER_EP(ep)));
                  z_proxy_return(self, FALSE);
                }
              break;

            case TELNET_CHECK_REJECT:
              /* create a temporary buffer */
              tbuf.ofs = 0; tbuf.end = 3; 
              tbuf.buf[0] = buf->buf[buf->ofs];
              tbuf.buf[1] = buf->buf[buf->ofs + 1];
              tbuf.buf[2] = buf->buf[buf->ofs + 2];
              switch (buf->buf[buf->ofs + 1])
                {
                case TELNET_CMD_WILL:
                  tbuf.buf[tbuf.ofs + 1] = TELNET_CMD_DONT;
                  buf->buf[buf->ofs + 1] = TELNET_CMD_WONT;
                  z_proxy_log(self, TELNET_DEBUG, 6, "WILL rejected;");
                  break;

                case TELNET_CMD_WONT:
                  tbuf.buf[tbuf.ofs + 1] = TELNET_CMD_DONT;
                  z_proxy_log(self, TELNET_DEBUG, 6, "WONT passed through;");
                  break;

                case TELNET_CMD_DO:
                  tbuf.buf[tbuf.ofs + 1] = TELNET_CMD_WONT;
                  buf->buf[buf->ofs + 1] = TELNET_CMD_DONT;
                  z_proxy_log(self, TELNET_DEBUG, 6, "DO rejected;");
                  break;

                case TELNET_CMD_DONT:
                  tbuf.buf[tbuf.ofs + 1] = TELNET_CMD_WONT;
                  z_proxy_log(self, TELNET_DEBUG, 6, "DONT passed through;");
                  break;
                }
              res = telnet_copy_buf(odbuf, &tbuf, tbuf.end);
              if (res)
                res = telnet_copy_buf(dbuf, buf, ptr - buf->ofs);
              if (!res)
                {
                  z_proxy_log(self, TELNET_DEBUG, 6, "Output buffer full; side='%s'", WHICH_EP(ep));
                  z_proxy_return(self, FALSE);
                }
              break;

            case TELNET_CHECK_ABORT:
              z_proxy_log(self, TELNET_POLICY, 2, "Session aborted during option negotiation;");
              z_proxy_return(self, FALSE);

            case TELNET_CHECK_DROP:
            default:
              z_proxy_log(self, TELNET_POLICY, 3, "Option negotiation sequence dropped;");
              break;
            }
          /* next state */
          self->state[ep] = TELNET_DATA;
          break;

        case TELNET_GOT_SB:
          /* get option number from buffer */
          self->opneg_option[ep] = buf->buf[ptr++];
          z_proxy_log(self, TELNET_DEBUG, 6, "Processing suboptions; state='TELNET_GOT_SB', option='%d'", self->opneg_option[ep]);
          /* initialize suboption buffer */
          self->suboptions[ep].ofs = 0; self->suboptions[ep].end = 0;
          self->state[ep] = TELNET_IN_SB;
          break;

        case TELNET_IN_SB:
          /* while not end of buffer and no IAC found */
          while (ptr < buf->end && buf->buf[ptr] != TELNET_IAC)
            {
              /* if the suboption buffer is already full */
              if (sbuf->end == TELNET_SUBOPTION_SIZE)
                {
                  z_proxy_log(self, TELNET_DEBUG, 6, "Suboption buffer full; side='%s'", WHICH_EP(ep));
                  z_proxy_return(self, FALSE);
                }
              /* copy byte to suboption buffer */
              sbuf->buf[sbuf->end++] = buf->buf[ptr++];
            }
          /* if IAC found, next state is TELNET_GOT_SB_IAC */
          if (ptr < buf->end)
            {
              self->state[ep] = TELNET_GOT_SB_IAC;
              ptr++;
            }
          else
            {
              self->state[ep] = TELNET_DATA;
            }
          break;

        case TELNET_GOT_SB_IAC:
          /* if suboption negotiation end found */
          if ((byte = buf->buf[ptr++]) == TELNET_CMD_SE)
            {
              res = telnet_check_suboption(self, ep);
              if (res == TELNET_CHECK_OK)
                {
                  res = telnet_copy_buf(dbuf, buf, 3);
                  if (res) telnet_copy_buf(dbuf, sbuf, sbuf->end - sbuf->ofs);
                  buf->ofs = ptr - 2;
                  if (res) telnet_copy_buf(dbuf, buf, 2);
                  if (!res)
                    {
                      z_proxy_log(self, TELNET_VIOLATION, 6, "Output buffer full; side='%s'", WHICH_EP(OTHER_EP(ep)));
                      z_proxy_leave(self);
                      return FALSE;
                    }
                }
              else
                {
                  z_proxy_log(self, TELNET_POLICY, 3, "Suboption denied by policy;");
                }
              /* data comes... */
              buf->ofs = ptr;
              self->state[ep] = TELNET_DATA;
            }
          /* otherwise it was just suboption data */
          else 
            {
              /* check if there's room for two bytes in suboption  buffer */
              if (sbuf->end + 2 > TELNET_SUBOPTION_SIZE)
                {
                  z_proxy_log(self, TELNET_ERROR, 3, "Suboption buffer full; side='%s'", WHICH_EP(ep));
                  z_proxy_return(self, FALSE);
                }
              /* put two bytes in the buffer */
              sbuf->buf[sbuf->end++] = TELNET_IAC;
              sbuf->buf[sbuf->end++] = byte;
              /* suboption negotiation data follows... */
              self->state[ep] = TELNET_IN_SB;
            }
          break;

        default:
          z_proxy_log(self, TELNET_ERROR, 2, "Internal error, unknown state;");
          z_proxy_return(self, FALSE);
        }
    }
  z_proxy_return(self, TRUE);
}


/**
 * telnet_forward:
 * @self: 
 * @from: 
 * @to: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
static gboolean
telnet_forward(TelnetProxy *self, ZStream *from, ZStream *to, guint ep)
{
  ZIOBuffer       *buf = &self->read_buffers[ep];
  ZIOBufferDyn    *dbuf = &self->write_buffers[OTHER_EP(ep)];
  ZIOBufferDyn    *odbuf = &self->write_buffers[ep];
  guint           maxiter = 5;
  GIOStatus       res;
  gboolean        rc;

  z_proxy_enter(self);
  from->want_read = FALSE;
  /* write any pending data in output buffer */
  to->want_write = FALSE;
  res = telnet_stream_write(self, dbuf, OTHER_EP(ep));
  if (res != G_IO_STATUS_NORMAL)
    z_proxy_return(self, res == G_IO_STATUS_AGAIN);

  /* read and write */
  while (maxiter)
    {
      maxiter--;
      if (buf->ofs != buf->end)
        memmove(buf->buf, buf->buf + buf->ofs, buf->end - buf->ofs);
      buf->end -= buf->ofs;
      buf->ofs = 0;

      res = telnet_stream_read(self, buf, ep);
      if (res == G_IO_STATUS_NORMAL)
        {
          /* process buffer */
          rc = telnet_process_buf(self, buf, dbuf, odbuf, ep);
          if (!rc)
            z_proxy_return(self, FALSE);
          /* write output buffer */
          if (!from->want_write)
            {
              res = telnet_stream_write(self, odbuf, ep);
              if (res != G_IO_STATUS_NORMAL && res != G_IO_STATUS_AGAIN)
                z_proxy_return(self, FALSE);
            }
          res = telnet_stream_write(self, dbuf, OTHER_EP(ep));
          if (res == G_IO_STATUS_AGAIN)
            break;
          else if (res != G_IO_STATUS_NORMAL)
            z_proxy_return(self, FALSE);
        }
      else if (res == G_IO_STATUS_AGAIN)
        {
          break;
        }
      else if (res == G_IO_STATUS_EOF)
        {
          z_proxy_log(self, TELNET_DEBUG, 6, "Connection closed by peer; side='%s'", WHICH_EP(ep));
          z_proxy_return(self, FALSE);
        }
      else if (res == G_IO_STATUS_ERROR)
        {
          z_proxy_return(self, FALSE);
        }
    }

  /* check if output buffer is empty */
  if (dbuf->ofs == dbuf->end)
    from->want_read = TRUE;
  z_proxy_return(self, TRUE);
}


/**
 * telnet_client_read:
 * @stream: not used
 * @cond: not used
 * @user_data: 
 *
 * 
 *
 * Returns:
 * 
 */
static gboolean
telnet_client_read(ZStream *stream G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  TelnetProxy   *self = (TelnetProxy *) user_data;
  gboolean      res;

  z_proxy_enter(self);
  self->ep = EP_CLIENT;
  res = telnet_forward(self,
                       self->super.endpoints[EP_CLIENT],
                       self->super.endpoints[EP_SERVER],
                       EP_CLIENT);
  if (!res)
    z_poll_quit(self->poll);
  z_proxy_return(self, res);
}


/**
 * telnet_server_read:
 * @stream: not used
 * @cond: not used
 * @user_data: 
 *
 * 
 *
 * Returns:
 * 
 */
static gboolean
telnet_server_read(ZStream *stream G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data)
{
  TelnetProxy   *self = (TelnetProxy *) user_data;
  gboolean      res;

  z_proxy_enter(self);
  self->ep = EP_SERVER;
  res = telnet_forward(self,
                       self->super.endpoints[EP_SERVER],
                       self->super.endpoints[EP_CLIENT],
                       EP_SERVER);
  if (!res)
    z_poll_quit(self->poll);
  z_proxy_return(self, res);
}

/**
 * telnet_init_streams:
 * @self: 
 *
 * 
 *
 * Returns:
 * 
 */
static gboolean
telnet_init_streams(TelnetProxy *self)
{
  gboolean ret = TRUE;

  z_proxy_enter(self);
  if (!self->super.endpoints[EP_CLIENT] ||
      !self->super.endpoints[EP_SERVER] ||
      !self->poll)
    {
      ret = FALSE;
      goto exit;
    }

  self->read_buffers[EP_SERVER].ofs = self->read_buffers[EP_SERVER].end = 0;
  self->write_buffers[EP_SERVER].ofs = self->write_buffers[EP_SERVER].end = 0;
  self->read_buffers[EP_CLIENT].ofs = self->read_buffers[EP_CLIENT].end = 0;
  self->write_buffers[EP_CLIENT].ofs = self->write_buffers[EP_CLIENT].end = 0;

  z_stream_set_nonblock(self->super.endpoints[EP_CLIENT], TRUE);
  z_stream_set_callback(self->super.endpoints[EP_CLIENT],
                        G_IO_IN,
                        telnet_client_read,
                        self,
                        NULL);
  z_stream_set_callback(self->super.endpoints[EP_CLIENT],
                        G_IO_OUT,
                        telnet_server_read,
                        self,
                        NULL);
  z_stream_set_cond(self->super.endpoints[EP_CLIENT],
                    G_IO_IN,
                    TRUE);
  self->super.endpoints[EP_CLIENT]->timeout = -2;

  z_stream_set_nonblock(self->super.endpoints[EP_SERVER], TRUE);
  z_stream_set_callback(self->super.endpoints[EP_SERVER],
                        G_IO_IN,
                        telnet_server_read,
                        self,
                        NULL);

  z_stream_set_callback(self->super.endpoints[EP_SERVER],
                        G_IO_OUT,
                        telnet_client_read,
                        self,
                        NULL);
  z_stream_set_cond(self->super.endpoints[EP_SERVER],
                    G_IO_IN,
                    TRUE);
  self->super.endpoints[EP_SERVER]->timeout = -2;

  z_poll_add_stream(self->poll, self->super.endpoints[EP_CLIENT]);
  z_poll_add_stream(self->poll, self->super.endpoints[EP_SERVER]);
  

 exit:
  z_proxy_return(self, ret);
}

static void
telnet_deinit_streams(TelnetProxy *self)
{
  z_poll_remove_stream(self->poll, self->super.endpoints[EP_SERVER]);
  z_poll_remove_stream(self->poll, self->super.endpoints[EP_CLIENT]);
}

/**
 * telnet_config:
 * @s: 
 *
 * 
 *
 * Returns:
 * 
 */
static gboolean
telnet_config(ZProxy *s)
{
  TelnetProxy   *self = Z_CAST(s, TelnetProxy);
  gboolean      success = FALSE;

  z_proxy_enter(self);
  self->poll = z_poll_new();
  telnet_set_defaults(self);
  telnet_register_vars(self);
  if (Z_SUPER(self, ZProxy)->config(s))
    {
      telnet_config_init(self);
      success = TRUE;
    }
  z_proxy_return(self, success);
}


/**
 * telnet_main:
 * @s: 
 *
 * 
 */
static void
telnet_main(ZProxy *s)
{
  TelnetProxy   *self = Z_CAST(s, TelnetProxy);

  z_proxy_enter(self);

  if (!z_proxy_connect_server(&self->super, NULL, 0) ||
      !telnet_init_streams(self))
    {
      z_proxy_leave(self);
      return;
    }

  self->state[EP_CLIENT] = TELNET_DATA;
  self->state[EP_SERVER] = TELNET_DATA;

  while (z_poll_iter_timeout(self->poll, self->timeout))
    {
      if (!z_proxy_loop_iteration(s))
        break;
    }

  telnet_deinit_streams(self);
  z_proxy_leave(self);
}


/**
 * telnet_proxy_free:
 * @s: 
 *
 * 
 */
static void
telnet_proxy_free(ZObject *s)
{
  gint          i;
  TelnetProxy   *self = Z_CAST(s, TelnetProxy);

  z_enter();
  for (i = 0; i < EP_MAX; i++)
    g_free(self->write_buffers[i].buf);
  z_poll_unref(self->poll);
  self->poll = NULL;
  z_proxy_free_method(s);
  z_return();
}


/**
 * telnet_proxy_new:
 * @params: 
 *
 * 
 *
 * Returns:
 * 
 */
static ZProxy *
telnet_proxy_new(ZProxyParams *params)
{
  TelnetProxy   *self;

  z_enter();
  self = Z_CAST(z_proxy_new(Z_CLASS(TelnetProxy), params), TelnetProxy);
  z_return((ZProxy *) self);
}


static void telnet_proxy_free(ZObject *s);

ZProxyFuncs telnet_proxy_funcs =
{
  { 
    Z_FUNCS_COUNT(ZProxy),
    telnet_proxy_free,
  },
  .config = telnet_config,
  .main = telnet_main,
};

ZClass TelnetProxy__class = 
{
  Z_CLASS_HEADER,
  &ZProxy__class,
  "TelnetProxy",
  sizeof(TelnetProxy),
  &telnet_proxy_funcs.super
};


/**
 * zorp_module_init:
 *
 * 
 *
 * Returns:
 * 
 */
gint
zorp_module_init(void)
{
  z_registry_add("telnet", ZR_PROXY, telnet_proxy_new);
  return TRUE;
}
