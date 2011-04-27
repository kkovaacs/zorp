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
 * $Id: telnetoption.c,v 1.10 2004/07/22 10:48:46 bazsi Exp $
 *
 * Author: Hidden
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include "telnet.h"
#include "telnetpolicy.h"

#include <zorp/log.h>

#include <string.h>
#include <ctype.h>

#define TELNET_POLICY                   "telnet.policy"
#define TELNET_DEBUG                    "telnet.debug"

/* virtual variable names */
#define TELNET_POLICY_TERMTYPE_NAME     "TERMINAL_TYPE"
#define TELNET_POLICY_TERMSPEED_NAME    "TERMINAL_SPEED"
#define TELNET_POLICY_XDISPLAY_NAME     "X_DISPLAY_LOCATION"
#define TELNET_POLICY_NAWS_NAME         "WINDOW_SIZE"

/* size of buffers used in suboption processing functions */
#define SB_BUF_SIZE                     512

/**
 * telnet_opt_terminal_type:
 * @self: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
guint
telnet_opt_terminal_type(TelnetProxy *self, guint ep)
{
  ZIOBuffer     *sbuf = &self->suboptions[ep];
  guint         ptr, i;
  guchar        buf[SB_BUF_SIZE];
  guint         res;

  z_proxy_enter(self);
  ptr = sbuf->ofs;
  if (sbuf->buf[ptr] == TELNET_SB_TERMINAL_TYPE_IS)
    {
      /* check if this side sent WILL */
      if (!(self->options[self->opneg_option[ep]][ep] & SENT_WILL))
        {
          z_proxy_log(self, TELNET_POLICY, 3, "TERMINAL TYPE IS option not allowed from this side; side='%s'", WHICH_EP(ep));
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }

      /* check if valid */
      for (ptr++; ptr < sbuf->end; ptr++)
          if (!isalnum(sbuf->buf[ptr]) && sbuf->buf[ptr] != '-')
            {
              /* FIXME: the value should be logged */
              z_proxy_log(self, TELNET_VIOLATION, 3, "Invalid TERMINAL TYPE value, it contains invalid characters;");
              z_proxy_return(self, TELNET_CHECK_ABORT);
            }

      /* copy to buf */
      for (i = 0, ptr = sbuf->ofs + 1; ptr < sbuf->end && i < sizeof(buf); ptr++, i++)
          buf[i] = sbuf->buf[ptr];

      if (i >= sizeof(buf))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "Invalid TERMINAL TYPE value, it is too long;");
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }

      buf[i] = 0;
      z_proxy_log(self, TELNET_DEBUG, 6, "TERMINAL TYPE option; value='%s'", buf);
      g_string_assign(self->policy_name, TELNET_POLICY_TERMTYPE_NAME);
      g_string_assign(self->policy_value, buf);
      res = telnet_policy_suboption(self, 0, TELNET_POLICY_TERMTYPE_NAME, buf);
      if (res == TELNET_CHECK_OK)
        {
          for (i = 0, ptr = sbuf->ofs + 1; i < self->policy_value->len; i++, ptr++)
              sbuf->buf[ptr] = self->policy_value->str[i];
          sbuf->end = ptr;
        }
    }
  else if (sbuf->buf[ptr] == TELNET_SB_TERMINAL_TYPE_SEND && sbuf->end == ptr + 1)
    {
      /* check if this side sent DO */
      if (!(self->options[self->opneg_option[ep]][OTHER_EP(ep)] & GOT_DO))
        {
          z_proxy_log(self, TELNET_POLICY, 3, "TERMINAL TYPE SEND option not allowed from this side; side='%s'", WHICH_EP(ep));
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }

      g_string_assign(self->policy_name, TELNET_POLICY_TERMTYPE_NAME);
      g_string_assign(self->policy_value, "");
      res = telnet_policy_suboption(self, 1, TELNET_POLICY_TERMTYPE_NAME, "");
    }
  else /* suboption code is  INVALID */
    {
      z_proxy_log(self, TELNET_VIOLATION, 3, "TERMINAL TYPE option, invalid subcommand or invalid suboption length;");
      z_proxy_return(self, TELNET_CHECK_ABORT);
    }
  z_proxy_return(self, res);
}

/**
 * telnet_opt_terminal_speed:
 * @self: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
guint
telnet_opt_terminal_speed(TelnetProxy *self, guint ep)
{
  ZIOBuffer     *sbuf = &self->suboptions[ep];
  guint         ptr, i;
  guchar        buf[SB_BUF_SIZE];
  guint         res;

  z_proxy_enter(self);
  ptr = sbuf->ofs;
  if (sbuf->buf[ptr] == TELNET_SB_TERMINAL_SPEED_IS)
    {
      /* check if this side sent WILL */
      if (!(self->options[self->opneg_option[ep]][ep] & SENT_WILL))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "TERMINAL SPEED IS option not allowed from this side; side='%s'", WHICH_EP(ep));
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }

      for (ptr++; ptr < sbuf->end; ptr++)
        {
          if (!isdigit(sbuf->buf[ptr]) && sbuf->buf[ptr] != ',')
            {
              z_proxy_log(self, TELNET_VIOLATION, 3, "TERMINAL SPEED IS option, invalid speed string;");
              z_proxy_return(self, TELNET_CHECK_ABORT);
            }
        }

      for (i = 0, ptr = sbuf->ofs + 1; ptr < sbuf->end && i < sizeof(buf); ptr++, i++)
          buf[i] = sbuf->buf[ptr];

      if (i >= sizeof(buf))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "TERMINAL SPEED IS option, value too long");
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }

      buf[i] = 0;
      z_proxy_log(self, TELNET_DEBUG, 6, "TERMINAL SPEED IS option; value='%s'", buf);
      g_string_assign(self->policy_name, TELNET_POLICY_TERMSPEED_NAME);
      g_string_assign(self->policy_value, buf);
      res = telnet_policy_suboption(self, 0, TELNET_POLICY_TERMSPEED_NAME, buf);
      if (res == TELNET_CHECK_OK)
        {
          for (i = 0, ptr = sbuf->ofs + 1; i < self->policy_value->len; i++, ptr++)
              sbuf->buf[ptr] = self->policy_value->str[i];
          sbuf->end = ptr;
        }
    }
  else if (sbuf->buf[ptr] == TELNET_SB_TERMINAL_SPEED_SEND && sbuf->end == ptr + 1)
    {
      /* check if this side sent DO */
      if (!(self->options[self->opneg_option[ep]][OTHER_EP(ep)] & GOT_DO))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "TERMINAL SPEED SEND option not allowed from this side; side='%s'", WHICH_EP(ep));
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }
      g_string_assign(self->policy_name, TELNET_POLICY_TERMSPEED_NAME);
      g_string_assign(self->policy_value, "");
      res = telnet_policy_suboption(self, 1, TELNET_POLICY_TERMSPEED_NAME, "");
    }
  else /* suboption code is INVALID */
    {
      z_proxy_log(self, TELNET_VIOLATION, 3, "TERMINAL SPEED option, invalid subcommand;");
      z_proxy_return(self, TELNET_CHECK_ABORT);
    }
  z_proxy_return(self, res);
}

/**
 * telnet_opt_x_display:
 * @self: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
guint
telnet_opt_x_display(TelnetProxy *self, guint ep)
{
  ZIOBuffer     *sbuf = &self->suboptions[ep];
  guint         ptr, i;
  guchar        buf[SB_BUF_SIZE];
  guint         res;

  z_proxy_enter(self);
  ptr = sbuf->ofs;
  if (sbuf->buf[ptr] == TELNET_SB_X_DISPLAY_LOCATION_IS)
    {
      /* check if this side sent WILL */
      if (!(self->options[self->opneg_option[ep]][ep] & SENT_WILL))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "X DISPLAY LOCATION IS option not allowed from this side; side='%s'", WHICH_EP(ep));
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }

      for (ptr++; ptr < sbuf->end; ptr++)
        {
          if (!isalnum(sbuf->buf[ptr]) && strchr(".:_-", sbuf->buf[ptr]) == NULL)
            {
              z_proxy_log(self, TELNET_VIOLATION, 3, "X DISPLAY LOCATION IS option, it contains invalid characters; value='%.*s'",
                          (gint) (sbuf->end - (sbuf->ofs + 1)), &sbuf->buf[sbuf->ofs + 1]);
              z_proxy_return(self, TELNET_CHECK_ABORT);
            }
        }

      for (i = 0, ptr = sbuf->ofs + 1; ptr < sbuf->end && i < sizeof(buf); ptr++, i++)
          buf[i] = sbuf->buf[ptr];

      if (i >= sizeof(buf))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "X DISPLAY LOCATION IS option, value too long;");
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }

      buf[i] = 0;
      z_proxy_log(self, TELNET_DEBUG, 6, "X DISPLAY LOCATION IS option; value='%s'", buf);

      g_string_assign(self->policy_name, TELNET_POLICY_XDISPLAY_NAME);
      g_string_assign(self->policy_value, buf);
      res = telnet_policy_suboption(self, 0, TELNET_POLICY_XDISPLAY_NAME, buf);
      if (res == TELNET_CHECK_OK)
        {
          for (i = 0, ptr = sbuf->ofs + 1; i < self->policy_value->len; i++, ptr++)
              sbuf->buf[ptr] = self->policy_value->str[i];
          sbuf->end = ptr;
        }
    }
  else if (sbuf->buf[ptr] == TELNET_SB_X_DISPLAY_LOCATION_SEND && sbuf->end == ptr + 1)
    {
      /* check if this side sent DO */
      if (!(self->options[self->opneg_option[ep]][OTHER_EP(ep)] & GOT_DO))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "X DISPLAY LOCATION SEND option is not allowed from this side;");
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }

      g_string_assign(self->policy_name, TELNET_POLICY_XDISPLAY_NAME);
      g_string_assign(self->policy_value, "");
      res = telnet_policy_suboption(self, 1, TELNET_POLICY_XDISPLAY_NAME, "");
    }
  else /* suboption code is INVALID */
    {
      z_proxy_log(self, TELNET_VIOLATION, 3, "X DISPLAY LOCATION option, invalid subcommand or invalid suboption length;");
      z_proxy_return(self, TELNET_CHECK_ABORT);
    }
  z_proxy_return(self, res);
}

/**
 * telnet_opt_new_env:
 * @self: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
guint
telnet_opt_new_env(TelnetProxy *self, guint ep)
{
  ZIOBuffer     *sbuf = &self->suboptions[ep];
  ZIOBuffer     cbuf;
  guint         ptr, i;
  guint         res;
  guchar        name[SB_BUF_SIZE], value[SB_BUF_SIZE];
  guchar        command, type;
  gboolean      valid = FALSE; /* TRUE if there was anything accepted by policy */

  z_proxy_enter(self);
  ptr = sbuf->ofs++;
  command = sbuf->buf[ptr++];
  /* initialize cbuf */
  cbuf.ofs = 0;
  cbuf.end = 1;
  cbuf.buf[0] = command;
  if (command == TELNET_SB_ENVIRONMENT_IS || command == TELNET_SB_ENVIRONMENT_INFO)
    {
      /* check if this side sent WILL */
      if (!(self->options[self->opneg_option[ep]][ep] & SENT_WILL))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "NEW ENVIRON IS or INFO option not allowed from this side; side='%s'", WHICH_EP(ep));
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }

      if (ptr == sbuf->end)
        {
          /* if this was an empty IS or INFO reply */
          g_string_assign(self->policy_name, "");
          g_string_assign(self->policy_value, "");
          res = telnet_policy_suboption(self, command, "", "");
          if (res == TELNET_CHECK_OK) 
            valid = TRUE;
        }
      else while (ptr < sbuf->end)
        {
          switch (type = sbuf->buf[ptr++])
            {
            case TELNET_OPTARG_ENVIRONMENT_VAR:
            case TELNET_OPTARG_ENVIRONMENT_USERVAR:
              /* initialize variable name and value buffers */
              name[0] = '\0'; value[0] = '\0';
              for (i = 0; ptr < sbuf->end && i < sizeof(name); ptr++, i++)
                {
                  if (sbuf->buf[ptr] == TELNET_OPTARG_ENVIRONMENT_VAR || 
                      sbuf->buf[ptr] == TELNET_OPTARG_ENVIRONMENT_VALUE || 
                      sbuf->buf[ptr] == TELNET_OPTARG_ENVIRONMENT_USERVAR)
                    break;  /* got VAR, VALUE, or USERVAR, here ends variable name */

                  if (sbuf->buf[ptr] == TELNET_OPTARG_ENVIRONMENT_ESC || 
                      sbuf->buf[ptr] == TELNET_IAC)
                    ptr++;  /* got ESC or IAC, these are followed by the real byte */

                  if (i < sizeof(name))
                    name[i] = sbuf->buf[ptr];
                }
              /* terminate name */
              if (i < sizeof(name))
                name[i] = '\0';
              else
                {
                  z_proxy_log(self, TELNET_VIOLATION, 3, "NEW-ENVIRON option, variable name too long;");
                  ptr = sbuf->end;
                  break; /* switch */
                }

              if (ptr < sbuf->end && sbuf->buf[ptr++] == TELNET_OPTARG_ENVIRONMENT_VALUE)
                { /* if next byte is VALUE */
                  for (i = 0; ptr < sbuf->end && i < sizeof(value); ptr++, i++)
                    {
                      if (sbuf->buf[ptr] == TELNET_OPTARG_ENVIRONMENT_VAR || 
                          sbuf->buf[ptr] == TELNET_OPTARG_ENVIRONMENT_VALUE || 
                          sbuf->buf[ptr] == TELNET_OPTARG_ENVIRONMENT_USERVAR)
                        break;  /* got VAR, VALUE or USERVAR, here ends value */

                      if (sbuf->buf[ptr] == TELNET_OPTARG_ENVIRONMENT_ESC || 
                          sbuf->buf[ptr] == TELNET_IAC) 
                        ptr++;  /* got ESC or IAC, these are followed by the real byte */

                      if (ptr < sbuf->end)
                        value[i] = sbuf->buf[ptr];
                    }
                  /* terminate value */
                  if (i < sizeof(value)) 
                    {
                      value[i] = '\0';
                    }
                  else
                    {
                      z_proxy_log(self, TELNET_VIOLATION, 3, "NEW-ENVIRON option, variable value too long;");
                      ptr = sbuf->end;
                      break; /* switch */
                    }
                }
              z_proxy_log(self, TELNET_DEBUG, 6, "NEW-ENVIRON; subopt='%s', name='%s', value='%s'",
                          (command == TELNET_SB_ENVIRONMENT_IS) ? "IS" : "INFO", name, value);

              g_string_assign(self->policy_name, name);
              g_string_assign(self->policy_value, value);
              res = telnet_policy_suboption(self, command, name, value);
              if (res == TELNET_CHECK_OK)
                {
                  valid = TRUE;
                  /* we may forward variable, so copy it */
                  cbuf.buf[cbuf.end++] = type;
                  if (cbuf.end < sizeof(cbuf.buf))
                    {
                      for (i = 0; cbuf.end < sizeof(cbuf.buf) && i < self->policy_name->len; i++, cbuf.end++)
                        cbuf.buf[cbuf.end] = self->policy_name->str[i];
                    }
                  
                  if (cbuf.end < sizeof(cbuf.buf))
                    cbuf.buf[cbuf.end++] = 1;
                  
                  if (cbuf.end < sizeof(cbuf.buf))
                    {
                      for (i = 0; cbuf.end < sizeof(cbuf.buf) && i < self->policy_value->len; i++, cbuf.end++)
                        cbuf.buf[cbuf.end] = self->policy_value->str[i];
                    }
                  
                  if (cbuf.end >= sizeof(cbuf.buf))
                    {
                      z_proxy_log(self, TELNET_VIOLATION, 3, "NEW-ENVIRON option, variable buffer full;");
                      res = TELNET_CHECK_DROP;
                      valid = FALSE;
                      break;
                    }
                }
              sbuf->ofs = ptr;
            break;

            default: /* not VAR or USERVAR, invalid */
              z_proxy_log(self, TELNET_VIOLATION, 5, "NEW-ENVIRON IS or INFO option, invalid reply;");
              /* set pointer to the end of sbuf, so that while terminates */
              ptr = sbuf->end;
            break;
            } /* switch */
        } /* while */
    } /* if */
  else if (command == TELNET_SB_ENVIRONMENT_SEND)
    {
      /* check if this side sent DO */
      if (!(self->options[self->opneg_option[ep]][OTHER_EP(ep)] & GOT_DO))
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "NEW-ENVIRON SEND otpion not allowed from this side; side='%s'", WHICH_EP(ep));
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }

      if (ptr == sbuf->end)
        {
          /* if this was an empty SEND request */
          g_string_assign(self->policy_name, "");
          g_string_assign(self->policy_value, "");
          res = telnet_policy_suboption(self, command, "", "");
          if (res == TELNET_CHECK_OK)
            valid = TRUE;
        }
      else while (ptr < sbuf->end)
        {
          switch (type = sbuf->buf[ptr++])
            {
            case TELNET_OPTARG_ENVIRONMENT_VAR:
            case TELNET_OPTARG_ENVIRONMENT_USERVAR:
              /* initialize variable name */
              name[0] = '\0';
              for (i = 0; ptr < sbuf->end && i < sizeof(name); ptr++, i++)
                {
                  if (sbuf->buf[ptr] == TELNET_OPTARG_ENVIRONMENT_VAR ||
                      sbuf->buf[ptr] == TELNET_OPTARG_ENVIRONMENT_USERVAR)
                    break;  /* got VAR or USERVAR, here ends variable name */

                  if (sbuf->buf[ptr] == TELNET_OPTARG_ENVIRONMENT_ESC ||
                      sbuf->buf[ptr] == TELNET_IAC)
                    ptr++;  /* got ESC or IAC, these are followed by the real byte */

                  if (i < sizeof(name))
                    name[i] = sbuf->buf[ptr];
                }
              /* terminate name */
              if (i < sizeof(name)) 
                {
                  name[i] = '\0';
                }
              else
                {
                  z_proxy_log(self, TELNET_VIOLATION, 3, "NEW-ENVIRON SEND option, variable name too long");
                  ptr = sbuf->end;
                  break;
                }
              z_proxy_log(self, TELNET_DEBUG, 6, "NEW-ENVIRON SEND option; value='%s'", name);

              g_string_assign(self->policy_name, name);
              g_string_assign(self->policy_value, "");
              res = telnet_policy_suboption(self, command, name, "");
              if (res == TELNET_CHECK_OK)
                {
                  valid = TRUE;
                  /* we may forward option, so copy it */
                  for (; sbuf->ofs < ptr; sbuf->ofs++, cbuf.end++)
                    cbuf.buf[cbuf.end] = sbuf->buf[sbuf->ofs];
                }
              else 
                {
                  sbuf->ofs = ptr;
                }
            break;

            default: /* not VAR or USERVAR, invalid */
              z_proxy_log(self, TELNET_VIOLATION, 3, "NEW-ENVIRON option, invalid SEND request;");
              ptr = sbuf->end;
            break;
            }
        } /* while */
    }
  else /* suboption code is INVALID */
    {
      z_proxy_log(self, TELNET_VIOLATION, 3, "NEW-ENVIRON option, invalid subcommand;");
    }

  /* if there wasn't any accepted variable, return DENY */
  if (!valid) 
    z_proxy_return(self, TELNET_CHECK_ABORT);

  /* else copy accepted bytes to suboption buffer */
  for (i = 0; i < cbuf.end; i++)
    sbuf->buf[i] = cbuf.buf[i];

  sbuf->ofs = 0;
  sbuf->end = cbuf.end;
  z_proxy_return(self, TELNET_CHECK_OK);
}

/**
 * telnet_opt_naws:
 * @self: 
 * @ep: 
 *
 * 
 *
 * Returns:
 * 
 */
guint
telnet_opt_naws(TelnetProxy *self, guint ep)
{
  ZIOBuffer     *sbuf = &self->suboptions[ep];
  guint         ptr, i;
  guchar        buf[SB_BUF_SIZE];
  guint         res;
  guchar        value[SB_BUF_SIZE];
  guint16       width, height;
  gchar         width_cols[256], height_rows[256];

  z_proxy_enter(self);
  /* check if this side sent WILL */
  if (!(self->options[self->opneg_option[ep]][ep] & SENT_WILL))
    {
      z_proxy_log(self, TELNET_DEBUG, 5, "NAWS option not allowed from this side; side='%s'", WHICH_EP(ep));
      z_proxy_return(self, TELNET_CHECK_ABORT);
    }

  if (sbuf->end - sbuf->ofs != 4)
    {
      for (ptr = sbuf->ofs, i = 0; ptr < sbuf->end && i < sizeof(buf); ptr++, i++)
        {
          buf[i] = sbuf->buf[ptr];
          if (sbuf->buf[ptr] == TELNET_IAC) 
            ptr++;
        }
      if (i != 4)
        {
          z_proxy_log(self, TELNET_VIOLATION, 3, "NAWS option, invalid length");
          z_proxy_return(self, TELNET_CHECK_ABORT);
        }
    }
  else 
    {
      for (ptr = sbuf->ofs, i = 0; i < 4; ptr++, i++)
        buf[i] = sbuf->buf[ptr];
    }

  width = (buf[0] << 8) + buf[1];
  height = (buf[2] << 8) + buf[3];
  g_string_assign(self->policy_name, TELNET_POLICY_NAWS_NAME);
  g_string_sprintf(self->policy_value, "%hd,%hd", width, height);
  snprintf(value, sizeof(value), "%hd,%hd", width, height);
  res = telnet_policy_suboption(self, 0, TELNET_POLICY_NAWS_NAME, value);
  if (res == Z_ACCEPT)
    {
      g_snprintf(width_cols, sizeof(width_cols), "%hd", width);
      g_snprintf(height_rows, sizeof(height_rows), "%hd", height);
      
    }
  z_proxy_return(self, res);
}
