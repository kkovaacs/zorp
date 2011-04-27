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
 * $Id: telnetpolicy.c,v 1.14 2004/07/28 14:36:07 sasa Exp $
 *
 * Author: Hidden
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/zorp.h>
#include <zorp/policy.h>
#include <zorp/thread.h>
#include <zorp/zpython.h>
#include <zorp/log.h>

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "telnet.h"

#define TELNET_POLICY   "telnet.policy"
#define TELNET_DEBUG    "telnet.debug"

/**
 * telnet_hash_get_type:
 * @tuple: 
 * @filter_type: 
 *
 * 
 *
 * Returns:
 * 
 */
gboolean
telnet_hash_get_type(ZPolicyObj *tuple, guint *filter_type)
{
  ZPolicyObj    *tmp;
  gboolean      res;

  if (!z_policy_seq_check(tuple))
    {
      res = z_policy_var_parse(tuple, "i", filter_type);
    }
  else
    {
      tmp = z_policy_seq_getitem(tuple, 0);
      res = z_policy_var_parse(tmp, "i", filter_type);  /* FALSE -> policy syntax error */
      z_policy_var_unref(tmp);
    }
  return res;
}

/**
 * telnet_policy_option:
 * @self: 
 *
 * 
 *
 * Returns:
 * 
 */
guint
telnet_policy_option(TelnetProxy *self)
{
  guint         res;
  ZPolicyObj    *pol_res;
  ZPolicyObj    *tmp;
  ZPolicyObj    *command_where = NULL;
  guint         command_do;
  gchar         lookup_str[10];
  gchar         *keys[1];
  gboolean      type_found;

  z_proxy_enter(self);
  z_proxy_log(self, TELNET_DEBUG, 8, "Policy option negotiation check; option='%d'", self->opneg_option[self->ep]);
  g_snprintf(lookup_str, sizeof(lookup_str), "%d", self->opneg_option[self->ep]);
  keys[0] = lookup_str;
  tmp = z_dim_hash_table_search(self->telnet_policy, 1, keys);
  if (!tmp)
    {
      z_proxy_log(self, TELNET_POLICY, 2, "Option not found in policy; option='%s'", lookup_str);
      z_proxy_return(self, TELNET_CHECK_DROP);
    }

  z_policy_lock(self->super.thread);
  type_found = telnet_hash_get_type(tmp, &command_do);
  z_policy_unlock(self->super.thread);
  if (!type_found )
    {
      z_proxy_log(self, TELNET_POLICY, 2, "Policy type invalid; option='%s'", lookup_str);
      z_proxy_return(self, TELNET_CHECK_ABORT);
    }

  switch (command_do)
    {
    case TELNET_OPTION_DROP:
      z_proxy_log(self, TELNET_POLICY, 3, "Policy denied option; option='%s'", lookup_str);
      res = TELNET_CHECK_DROP;
      break;

    case TELNET_OPTION_ACCEPT:
      z_proxy_log(self, TELNET_POLICY, 6, "Policy accepted option; option='%s'", lookup_str);
      res = TELNET_CHECK_OK;
      break;

    case TELNET_OPTION_POLICY:
      z_policy_lock(self->super.thread);
      if (!z_policy_var_parse(tmp, "(iO)", &command_do, &command_where))
        {
          z_proxy_log(self, TELNET_POLICY, 2, "Cannot parse policy line; option='%s'", lookup_str);
          res = TELNET_CHECK_ABORT;
        }
      else 
        {
          pol_res = z_policy_call_object(command_where, z_policy_var_build("(i)", &self->opneg_option[self->ep]), self->super.session_id);
          if (pol_res == NULL)
            {
              z_proxy_log(self, TELNET_POLICY, 2, "Error in policy calling; option='%s'", lookup_str);
              res = TELNET_CHECK_ABORT;
            }
          else if (!z_policy_var_parse(pol_res, "i", &res))
            {
              z_proxy_log(self, TELNET_POLICY, 1, "Can't parse return verdict; option='%s'", lookup_str);
              res = TELNET_CHECK_ABORT;
            }
          else
            {
              switch (res)
                {
                case Z_ACCEPT:
                  z_proxy_log(self, TELNET_POLICY, 6, "Policy function accepted option; option='%s'", lookup_str);
                  res = TELNET_CHECK_OK;
                  break;

                case Z_UNSPEC:
                case Z_DROP:
                  z_proxy_log(self, TELNET_POLICY, 3, "Policy function drop option; option='%s'", lookup_str);
                  res = TELNET_CHECK_DROP;
                  break;

                case TELNET_OPTION_REJECT:
                  z_proxy_log(self, TELNET_POLICY, 3, "Policy function reject option; option='%s'", lookup_str);
                  res = TELNET_CHECK_REJECT;
                  break;

                case Z_ABORT:
                default:
                  z_proxy_log(self, TELNET_POLICY, 1, "Policy function aborted session; option='%s'", lookup_str);
                  res = TELNET_CHECK_ABORT;
                  break;
                }
            }
        }
      z_policy_unlock(self->super.thread);
      break;

    case TELNET_OPTION_REJECT:
      z_proxy_log(self, TELNET_POLICY, 3, "Policy rejected option; option='%s'", lookup_str);
      res = TELNET_CHECK_REJECT;
      break;

    case TELNET_OPTION_ABORT:
    default:
      z_proxy_log(self, TELNET_POLICY, 3, "Policy aborted session; option='%s'", lookup_str);
      res = TELNET_CHECK_ABORT;
      break;
    }
  z_proxy_return(self, res);
}

/**
 * telnet_policy_suboption:
 * @self: 
 * @command: 
 * @name: 
 * @value: 
 *
 * 
 *
 * Returns:
 * 
 */
guint
telnet_policy_suboption(TelnetProxy *self, guchar command, gchar *name, gchar *value)
{
  guint         res;
  ZPolicyObj    *pol_res;
  ZPolicyObj    *tmp;
  ZPolicyObj    *command_where = NULL;
  guint         command_do;
  gchar         lookup_str[2][10];
  gchar         *keys[2];
  gboolean      type_found;

  z_proxy_enter(self);
  z_proxy_log(self, TELNET_DEBUG, 8, "Policy suboption negotiation check;");
  g_snprintf(lookup_str[0], sizeof(lookup_str[0]), "%d", self->opneg_option[self->ep]);
  g_snprintf(lookup_str[1], sizeof(lookup_str[1]), "%d", command);
  keys[0] = lookup_str[0];
  keys[1] = lookup_str[1];
  tmp = z_dim_hash_table_search(self->telnet_policy, 2, keys);
  if (!tmp)
    {
      z_proxy_log(self, TELNET_POLICY, 1, "Option not found in policy hash, dropping; command=`%s', option=`%s'", lookup_str[1], lookup_str[0]);
      z_proxy_return(self, TELNET_CHECK_DROP);
    }

  z_policy_lock(self->super.thread);
  type_found = telnet_hash_get_type(tmp, &command_do);
  z_policy_unlock(self->super.thread);
  if (!type_found)
    {
      z_proxy_log(self, TELNET_POLICY, 2, "Policy type invalid!");
      z_proxy_return(self, TELNET_CHECK_ABORT);
    }

  switch (command_do)
    {
    case TELNET_OPTION_DROP:
      z_proxy_log(self, TELNET_POLICY, 6, "Policy denied suboption; command=`%s', option=`%s'", lookup_str[1], lookup_str[0]);
      res = TELNET_CHECK_DROP;
      break;

    case TELNET_OPTION_ACCEPT:
      z_proxy_log(self, TELNET_POLICY, 6, "Policy accepted suboption; command=`%s', option=`%s'", lookup_str[1], lookup_str[0]);
      res = TELNET_CHECK_OK;
      break;

    case TELNET_OPTION_POLICY:
      z_policy_lock(self->super.thread);
      if (!z_policy_var_parse(tmp, "(iO)", &command_do, &command_where))
        {
          z_proxy_log(self, TELNET_POLICY, 2, "Cannot parse policy line for option; command=`%s', option=`%s'", lookup_str[1], lookup_str[0]);
          res = TELNET_CHECK_ABORT;
        }
      else 
        {
          /* call Python method with appropriate parameters */
          switch (self->opneg_option[self->ep])
            {
            case TELNET_OPTION_TERMINAL_TYPE:
            case TELNET_OPTION_TERMINAL_SPEED:
            case TELNET_OPTION_X_DISPLAY_LOCATION:
            case TELNET_OPTION_ENVIRONMENT:
            case TELNET_OPTION_NAWS:
              pol_res = z_policy_call_object(command_where, z_policy_var_build("(iss)", &self->opneg_option[self->ep], name, value), self->super.session_id);
              break;

            default:
              pol_res = z_policy_call_object(command_where, z_policy_var_build("(i)", &self->opneg_option[self->ep]), self->super.session_id);
              break;
            }

          if (pol_res == NULL)
            {
              z_proxy_log(self, TELNET_POLICY, 2, "Error in policy calling; command=`%s', option=`%s'", lookup_str[1], lookup_str[0]);
              res = TELNET_CHECK_ABORT;
            }
          else if (!z_policy_var_parse(pol_res, "i", &res))
            {
              z_proxy_log(self, TELNET_POLICY, 2, "Can't parse return verdict; command=`%s', option=`%s'", lookup_str[1], lookup_str[0]);
              res = TELNET_CHECK_ABORT;
            }
          else
            {
              switch (res)
                {
                case Z_ACCEPT:
                  z_proxy_log(self, TELNET_POLICY, 6, "Policy function accepted suboption; command=`%s', option=`%s'", lookup_str[1], lookup_str[0]);
                  res = TELNET_CHECK_OK;
                  break;

                case Z_UNSPEC:
                case Z_REJECT:
                case Z_DROP:
                  z_proxy_log(self, TELNET_POLICY, 3, "Policy function denied suboption; command=`%s', option=`%s'", lookup_str[1], lookup_str[0]);
                  res = TELNET_CHECK_DROP;
                  break;

                case Z_ABORT:
                default:
                  z_proxy_log(self, TELNET_POLICY, 3, "Policy function aborted suboption; command=`%s', option=`%s'", lookup_str[1], lookup_str[0]);
                  res = TELNET_CHECK_ABORT;
                  break;
                }
            }
        }
      z_policy_unlock(self->super.thread);
      break;

    case TELNET_OPTION_ABORT:
    default:
      z_proxy_log(self, TELNET_POLICY, 3, "Policy aborted session; command=`%s', option=`%s'", lookup_str[1], lookup_str[0]);
      res = TELNET_CHECK_ABORT;
      break;
    }
  z_proxy_return(self, res);
}

