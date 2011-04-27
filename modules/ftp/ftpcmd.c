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
 * $Id: ftpcmd.c,v 1.93 2004/08/16 09:59:10 sasa Exp $
 *
 * Author:  Andras Kis-Szabo <kisza@sch.bme.hu>
 * Author:  Attila SZALAY <sasa@balabit.hu>
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include <zorp/zorp.h>
#include <zorp/stream.h>
#include <zorp/proxy.h>
#include <zorp/policy.h>
#include <zorp/thread.h>
#include <zorp/zpython.h>
#include <zorp/log.h>
#include <zorp/pysockaddr.h>

#include "ftp.h"
#include "ftphash.h"
#include "ftpcmd.h"

#include <assert.h>
#include <arpa/inet.h>

/**
 * Parse numeric parameters from an FTP command.
 *
 * @param[in]  src parameter string
 * @param[in]  length length of src
 * @param[out] nums array of numbers to hold the parameters
 *
 * This function is depend on the behaviour that in FTP protocol
 * the numbers are send in bytes. So it check that the numbers is between
 * 0 and 255.
 * If length is 0, this will return FALSE.
 *
 * @returns TRUE if the parameter string could be parsed correctly and completely
 **/
gboolean
ftp_parse_nums(gchar *src, gint length, unsigned char *nums)
{
  int i = 0;
  gchar *newsrc;
  
  z_enter();
  if (length == 0)
    z_return(FALSE);
  while (length > 0 && i < 6)
    {
      unsigned int tmp;
      
      errno = 0;
      tmp = strtoul(src, &newsrc, 10);
      /* tmp is unsigned, so cannot be less than zero */
      if (tmp > 255 || errno == ERANGE)
        z_return(FALSE);
      nums[i] = tmp;
      if (i < 5 && *newsrc != ',')
        z_return(FALSE);
      length -= (newsrc - src + 1);
      src = newsrc + 1;
      i++;
    }
  z_return(length <= 0);
}

gboolean
ftp_parse_search_nums(gchar *src, gint length, unsigned char *nums)
{
  gchar *left, *right;

  z_enter();
  left = strchr(src,'(');
  if (left)
    {
      right = strrchr(src,')');
      if (right)
        {
          left++;
          length = right - left;
          if (length > 0)
            z_return((ftp_parse_nums(left, length, nums)));
        }
    }
  z_return(FALSE);
}

/**
 * If the Python code told us to and we're actually using inband authentication, try to authenticate
 * using the provided proxy_username and proxy_password.
 *
 * @param[in] self FtpProxy instance.
 *
 * @returns FALSE if authentication was attempted and it failed
 **/
static gboolean
ftp_do_inband_auth(FtpProxy *self)
{
  if (!self->proxy_auth_needed)
    return TRUE;

  /* only attempt to authenticate if we're using inband authentication at all */
  if (self->auth)
    {
      gboolean res;
      gchar **groups = NULL;

      z_policy_lock(self->super.thread);
      res = z_auth_provider_check_passwd(self->auth, self->super.session_id,
                                         self->proxy_username->str, self->proxy_password->str, &groups, &self->super);
      z_policy_unlock(self->super.thread);
      if (res)
        res = z_proxy_user_authenticated(&self->super, self->proxy_username->str, (gchar const **) groups);

      g_strfreev(groups);

      if (!res)
        {
          self->proxy_auth_needed = 0;
          return FALSE;                 /* authentication failed */
        }
    }

  self->proxy_auth_needed = 0;          /* reset the flag */
  self->auth_done = TRUE;
  return TRUE;
}

guint
ftp_command_parse_USER(FtpProxy *self)
{
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_PRECONNECT:
    case FTP_STATE_PRECONNECT_FEAT:
    case FTP_STATE_PRECONNECT_AUTH:
    case FTP_STATE_PRECONNECT_PBSZ:
    case FTP_STATE_PRECONNECT_PROT:
    case FTP_STATE_PRECONNECT_LOGIN_U:
    case FTP_STATE_PRECONNECT_LOGIN_P:
      /* USER in non transparent mode, we'll need to find out destination hostname */

      /* parse auth information */
      if (!ftp_policy_parse_authinfo(self, "USER", self->request_param))
        {
          SET_ANSWER(MSG_USERNAME_FORMAT_INVALID);
          z_proxy_return(self, FTP_REQ_REJECT);
        }

      /* perform checks */
      if (!z_port_enabled(self->target_port_range->str, self->hostport))
        {
          SET_ANSWER(MSG_USERNAME_FORMAT_INVALID);
          /*LOG
            This message indicates that the port part of the username in non-transparent mode
            is not permitted by the policy and Zorp rejects the request. Check the
            'target_port_range' attribute.
            */
          z_proxy_log(self, FTP_POLICY, 3, "Invalid port specified in non-transparent destination; username='%s', "
                      "port='%d', target_port_range='%s'",
                      self->request_param->str, self->hostport, self->target_port_range->str);
          z_proxy_return(self, FTP_REQ_REJECT);
        }

      if (!z_charset_is_string_valid(&self->username_charset, self->username->str, self->username->len))
        {
          /*LOG
            This message indicates that the username sent by the client contains invalid characters and Zorp
            rejects the request. Check the 'valid_chars_username' attribute.
            */
          z_proxy_log(self, FTP_POLICY, 3, "Invalid character in username; username='%s', valid_chars_username='%s'",
                      self->username->str, self->valid_chars_username->str);
          z_proxy_return(self, FTP_REQ_REJECT);
        }

      if (self->hostname->len > self->max_hostname_length)
        {
          SET_ANSWER(MSG_HOSTNAME_TOO_LONG);
          /*LOG
            This message indicates that the hostname part of the username in non-transparent mode
            is too long and Zorp rejects the request. Check the 'max_hostname_length' attribute.
            */
          z_proxy_log(self, FTP_POLICY, 3, "Hostname specified in username is too long; username='%s', length='%zd', max_hostname_length='%d'",
                      self->request_param->str, self->hostname->len, self->max_hostname_length);
          z_proxy_return(self, FTP_REQ_REJECT);
        }

      if (self->username->len > self->max_username_length)
        {
          SET_ANSWER(MSG_USERNAME_TOO_LONG);
          /*LOG
            This message indicates that the username is too long and Zorp rejects the request. Check the
            'max_username_length' attribute.
            */
          z_proxy_log(self, FTP_POLICY, 3, "Username too long; username='%s', length='%zd', max_username_length='%d'",
                      self->request_param->str, self->username->len, self->max_username_length);
          z_proxy_return(self, FTP_REQ_REJECT);
        }

      /* do proxy authentication (inband) if necessary */
      if (!ftp_do_inband_auth(self))
        {
          SET_ANSWER(MSG_CONNECTION_ABORTED);
          z_proxy_log(self, FTP_ERROR, 3, "Authentication failed; proxy_username='%s'", self->proxy_username->str);
          z_proxy_return(self, FTP_REQ_ABORT);
        }

      if (self->proxy_username->len > 0
          && self->proxy_password->len > 0
          && self->username->len > 0
          && self->password->len > 0)
        {
          /* the USER command supplied required data, no need to ask for password */
          ftp_proto_state_set(self, FTP_STATE_PRECONNECT_LOGIN_P);
          z_proxy_return(self, FTP_NOOP);
        }
      else
        {
          ftp_proto_state_set(self, FTP_STATE_PRECONNECT_LOGIN_U);
          SET_ANSWER(MSG_USER_OKAY);
          z_proxy_trace(self, "USER Command ok;");
          z_proxy_return(self, FTP_PROXY_ANS);
        }

    case FTP_STATE_LOGIN:
    case FTP_STATE_LOGIN_U:
    case FTP_STATE_LOGIN_P:
    case FTP_STATE_LOGIN_A:
    case FTP_STATE_LOGINAUTH:

      if (!self->transparent_mode)
        {
          /* The proxy is in non-transparent mode, but we received a second USER
           * request from the client: we have to be careful here, since the argument
           * might contain inband routing and authentication info. If that's the case,
           * we parse the argument and check that the destination server matches the
           * one we're connected to and re-do the inband authentication. */

          self->proxy_auth_needed = FALSE;

          /* copy current inband routing data */
          GString *old_hostname = g_string_new(self->hostname->str);

          if (ftp_policy_parse_authinfo(self, "USER", self->request_param))
            {
              /* parsing succeeded, check that hostname is the same */
              if (!g_string_equal(old_hostname, self->hostname))
                {
                  g_string_assign(self->hostname, old_hostname->str);
                  SET_ANSWER(MSG_USER_INBAND_INFO_INVALID);
                  z_proxy_log(self, FTP_POLICY, 3, "Re-sent username contains different inband "
                              "routing information; old_hostname='%s', new_hostname='%s'",
                              old_hostname->str, self->hostname->str);
                  z_proxy_return(self, FTP_REQ_REJECT);
                }

              /* re-do inband authentication */
              if (!ftp_do_inband_auth(self))
                {
                  SET_ANSWER(MSG_CONNECTION_ABORTED);
                  z_proxy_log(self, FTP_ERROR, 3, "Authentication failed; proxy_username='%s'", self->proxy_username->str);
                  z_proxy_return(self, FTP_REQ_ABORT);
                }

              /* send only the username part to the server */
              g_string_assign(self->request_param, self->username->str);
            }

          g_string_assign(self->hostname, old_hostname->str);
          g_string_free(old_hostname, TRUE);
        }

      if (self->request_param->len > self->max_username_length)
        {
          SET_ANSWER(MSG_USERNAME_TOO_LONG);
          /*LOG
            This message indicates that the username is too long and Zorp rejects the request. Check the
            'max_username_length' attribute.
           */
          z_proxy_log(self, FTP_POLICY, 3, "Username too long; username='%s', length='%" G_GSIZE_FORMAT "', max_username_length='%d'",
              self->request_param->str, self->request_param->len, self->max_username_length);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      if (!z_charset_is_string_valid(&self->username_charset, self->request_param->str, self->request_param->len))
        {
          /*LOG
            This message indicates that the username sent by the client contains invalid characters and Zorp
            rejects the request. Check the 'valid_chars_username' attribute.
           */
          z_proxy_log(self, FTP_POLICY, 3, "Invalid character in username; username='%s', valid_chars_username='%s'",
              self->request_param->str, self->valid_chars_username->str);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      g_string_assign(self->username, self->request_param->str);
      ftp_proto_state_set(self, FTP_STATE_LOGIN_U);
      break;
      
    case FTP_STATE_CONVERSATION:
    case FTP_STATE_DATA:
      SET_ANSWER(MSG_USER_ALREADY_LOGGED_IN);
      z_proxy_return(self, FTP_REQ_REJECT);

    default:
      /*LOG
        This message indicates an internal error, please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 1, "Internal error, proxy in unknown state; cmd='USER', state='%s'",
                  ftp_proto_state_name(self->ftp_state));
      z_proxy_return(self, FTP_REQ_ABORT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_answer_USER(FtpProxy *self)
{
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_LOGIN_U:
    case FTP_STATE_LOGIN_P:
      switch(self->answer_cmd->str[0])
        {
        case '2':
          ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
          break;

        case '3':
          switch(self->answer_code)
            {
            case 331:
              break;

            case 332:
              ftp_proto_state_set(self, FTP_STATE_LOGIN_A);
              break;
            }
          break;
        }
      break;

    case FTP_STATE_CONVERSATION:
      /* do nothing, but accept response */
      break;

    default:
      /*LOG
        This message indicates an internal error, please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 1, "Internal error, proxy in unknown state; cmd='USER', rsp='%u', state='%s'",
                  self->answer_code, ftp_proto_state_name(self->ftp_state));
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_proxy_leave(self);
  return FTP_RSP_ACCEPT;
}

guint
ftp_command_parse_PASS(FtpProxy *self)
{
  guint clen;

  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_PRECONNECT:
    case FTP_STATE_PRECONNECT_LOGIN_P:
      /* PASS in non-transparent startup */
      SET_ANSWER(MSG_USER_FIRST);
      z_proxy_return(self, FTP_REQ_REJECT);

    case FTP_STATE_PRECONNECT_LOGIN_U:
      if (self->request_param->len > self->max_password_length)
        {
          SET_ANSWER(MSG_PASSWORD_TOO_LONG);
          /*LOG
            This message indicates that the password is too long and Zorp rejects the request. Check the
            'max_password_length' attribute.
           */
          z_proxy_log(self, FTP_POLICY, 3, "Password too long; length='%" G_GSIZE_FORMAT "', max_password_length='%d'",
              self->request_param->len, self->max_password_length);
          z_proxy_return(self, FTP_REQ_REJECT);
        }

      /* parse auth information */
      if (!ftp_policy_parse_authinfo(self, "PASS", self->request_param))
        {
          SET_ANSWER(MSG_PASSWORD_FORMAT_INVALID);
          z_proxy_return(self, FTP_REQ_REJECT);
        }

      /* do proxy authentication (inband) if necessary */
      if (!ftp_do_inband_auth(self))
        {
          SET_ANSWER(MSG_CONNECTION_ABORTED);
          z_proxy_log(self, FTP_ERROR, 3, "Authentication failed; proxy_username='%s'", self->proxy_username->str);
          z_proxy_return(self, FTP_REQ_ABORT);
        }

      ftp_proto_state_set(self, FTP_STATE_PRECONNECT_LOGIN_P);
      z_proxy_return(self, FTP_NOOP);

    case FTP_STATE_LOGIN:
    case FTP_STATE_LOGIN_P:
    case FTP_STATE_LOGIN_A:
    case FTP_STATE_LOGINAUTH:
      SET_ANSWER(MSG_USER_FIRST);
      z_proxy_return(self, FTP_REQ_REJECT);

    case FTP_STATE_LOGIN_U:

      if (!self->transparent_mode)
        {
          /* The proxy is in non-transparent mode, but we received a second PASS
           * request from the client: we have to be careful here, since the argument
           * might contain inband authentication password. If that's the case,
           * we parse the argument, re-do the inband authentication and only pass
           * the password to the server. */

          if (ftp_policy_parse_authinfo(self, "PASS", self->request_param))
            {
              /* re-do inband authentication */
              if (!ftp_do_inband_auth(self))
                {
                  SET_ANSWER(MSG_CONNECTION_ABORTED);
                  z_proxy_log(self, FTP_ERROR, 3, "Authentication failed; proxy_username='%s'", self->proxy_username->str);
                  z_proxy_return(self, FTP_REQ_ABORT);
                }

              /* send only the username part to the server */
              g_string_assign(self->request_param, self->password->str);
            }
        }

      clen = strlen(self->request_param->str);
      if (clen > self->max_password_length)
        {
          SET_ANSWER(MSG_PASSWORD_TOO_LONG);
          /*LOG
            This message indicates that the password is too long and Zorp rejects the request. Check the
            'max_password_length' attribute.
           */
          z_proxy_log(self, FTP_POLICY, 3, "Password too long; length='%d', max_password_length='%d'",
              clen, self->max_password_length);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      g_string_assign(self->password, self->request_param->str);
      ftp_proto_state_set(self, FTP_STATE_LOGIN_P);
      break;
      
    case FTP_STATE_CONVERSATION:
      z_proxy_return(self, FTP_REQ_ACCEPT);
      
    case FTP_STATE_DATA:
      SET_ANSWER(MSG_USER_FIRST);
      z_proxy_return(self, FTP_REQ_REJECT);

    default:
      /*LOG
        This message indicates an internal error, please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 1, "Internal error, proxy in unknown state; cmd='PASS', state='%s'",
                  ftp_proto_state_name(self->ftp_state));
      z_proxy_return(self, FTP_REQ_ABORT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_answer_PASS(FtpProxy *self)
{
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_LOGIN_P:
      switch (self->answer_cmd->str[0])
        {
        case '2':
          ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
          break;

        case '3':
          switch(self->answer_code)
            {
            case 332:
              ftp_proto_state_set(self, FTP_STATE_LOGIN_A);
              break;
            }
          break;
        }
      break;

    case FTP_STATE_CONVERSATION:
      /* do nothing, but accept response */
      break;

    default:
      z_proxy_log(self, FTP_ERROR, 1, "Internal error, proxy in unknown state; cmd='PASS', rsp='%u', state='%s'",
                  self->answer_code, ftp_proto_state_name(self->ftp_state));
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_proxy_return(self, FTP_RSP_ACCEPT);
}

guint
ftp_command_parse_ACCT(FtpProxy *self)
{
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_LOGIN:
    case FTP_STATE_LOGIN_U:
    case FTP_STATE_LOGIN_P:
    case FTP_STATE_LOGINAUTH:
      SET_ANSWER(MSG_USER_FIRST);
      z_proxy_return(self, FTP_REQ_REJECT);

    case FTP_STATE_LOGIN_A:
    case FTP_STATE_CONVERSATION:
    case FTP_STATE_DATA:
      break;
      
    default:
      /*LOG
        This message indicates an internal error, please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 1, "Internal error, proxy in unknown state; cmd='ACCT', state='%s'",
                  ftp_proto_state_name(self->ftp_state));
      z_proxy_return(self, FTP_REQ_ABORT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_answer_ACCT(FtpProxy *self)
{
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_LOGIN_A:
      switch (self->answer_cmd->str[0])
        {
        case '2':
          ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
          break;
        }
      break;

    default:
      /*LOG
        This message indicates an internal error, please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 1, "Internal error, proxy in unknown state; cmd='ACCT', rsp='%u', state='%s'",
                  self->answer_code, ftp_proto_state_name(self->ftp_state));
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_proxy_return(self, FTP_RSP_ACCEPT);
}


guint
ftp_command_parse_path(FtpProxy *self)
{
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
      break;

    case FTP_STATE_DATA:
      if (self->command_desc->need_data)
        {
          ftp_state_both(self);
          self->state = FTP_BOTH_SIDE;
        }
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_answer_path(FtpProxy *self)
{
  z_proxy_enter(self);
  if (!self->command_desc->need_data)
    z_proxy_return(self, FTP_RSP_ACCEPT);

  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
    case FTP_STATE_DATA:
      switch (self->answer_cmd->str[0])
        {
        case '1':
          self->oldstate = FTP_SERVER_TO_CLIENT;
          self->data_state |= FTP_DATA_SERVER_SAID;
          if (!self->command_desc || self->command_desc->need_data != 2) /* data: cli -> svr */
            {
              self->preamble = ftp_answer_setup(self, self->answer_cmd->str, self->answer_param->str);
              self->drop_answer = TRUE;
            }
          else
            {
              self->preamble = NULL;
            }
          break;
          
        case '2':
          if (self->data_state != 0)
            self->oldstate = FTP_CLIENT_TO_SERVER;

          ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
          if ((self->data_state & FTP_DATA_SERVER_SAID) == 0)   /* if we've received no 150 */
            ftp_data_reset(self);                       /* close any active data connection that might be left over; data_state is also reset */
          break;
          
        case '4':
        case '5':
          if (self->data_state != 0)
            self->oldstate = FTP_CLIENT_TO_SERVER;

          ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
          ftp_data_reset(self);
          break;
          
        default:
          /*LOG
            This message indicates that the data transfer command's answer sent by the server
            is invalid and Zorp resets the data transfer.
           */
          z_proxy_log(self, FTP_VIOLATION, 1, "Unexpected response to data transfer command; req='%s', answer='%d'", self->request_cmd->str, self->answer_code);
          self->oldstate = FTP_CLIENT_TO_SERVER;
          ftp_data_reset(self);
          break;
        }
      break;

    default:
      /*LOG
        This message indicates an internal error, please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 1, "Internal error, proxy in unknown state; cmd='%s', rsp='%u', state='%s'",
                  self->request_cmd->str, self->answer_code, ftp_proto_state_name(self->ftp_state));
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_proxy_return(self, FTP_RSP_ACCEPT);
}

guint
ftp_command_parse_QUIT(FtpProxy *self)
{
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_PRECONNECT:
    case FTP_STATE_PRECONNECT_FEAT:
    case FTP_STATE_PRECONNECT_AUTH:
    case FTP_STATE_PRECONNECT_PBSZ:
    case FTP_STATE_PRECONNECT_PROT:
    case FTP_STATE_PRECONNECT_LOGIN_U:
    case FTP_STATE_PRECONNECT_LOGIN_P:
      if (self->request_param->len > 0)
        {
          /*LOG
            This message indicates that the parameter of the request is invalid and Zorp rejects the
            request. This request must not have any parameter at all.
           */
          z_proxy_log(self, FTP_VIOLATION, 3, "Invalid parameter for command; req='%s', req_param='%s'", self->request_cmd->str, self->request_param->str);
          SET_ANSWER(MSG_INVALID_PARAMETER);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      SET_ANSWER(MSG_GOODBYE);
      ftp_proto_state_set(self, FTP_STATE_PRECONNECT_QUIT);
      z_proxy_return(self, FTP_REQ_ABORT);

    case FTP_STATE_LOGIN:
    case FTP_STATE_LOGIN_U:
    case FTP_STATE_LOGIN_P:
    case FTP_STATE_LOGIN_A:
    case FTP_STATE_LOGINAUTH:
    case FTP_STATE_CONVERSATION:
    case FTP_STATE_DATA:
      if (self->request_param->len > 0)
        {
          /*LOG
            This message indicates that the parameter of the request is invalid and Zorp rejects the
            request. This request must not have any parameter at all.
           */
          z_proxy_log(self, FTP_VIOLATION, 3, "Invalid parameter for command; req='%s', req_param='%s'", self->request_cmd->str, self->request_param->str);
          SET_ANSWER(MSG_INVALID_PARAMETER);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      ftp_proto_state_set(self, FTP_STATE_QUIT);
      break;

    default:
      /*LOG
        This message indicates an internal error, please contact the BalaBit QA team.
       */
      z_proxy_log(self, FTP_ERROR, 1, "Internal error, proxy in unknown state; cmd='QUIT', state='%s'",
                  ftp_proto_state_name(self->ftp_state));
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_answer_QUIT(FtpProxy *self)
{
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_QUIT:
      self->state = FTP_QUIT;
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_parse_TYPE(FtpProxy *self)
{
  gchar mytype;

  z_proxy_enter(self);
  if(self->ftp_state == FTP_STATE_CONVERSATION ||
     self->ftp_state == FTP_STATE_DATA)
    {

      if (self->request_param->len == 0)
        {
          SET_ANSWER(MSG_MISSING_PARAMETER);
          /*LOG
            This message indicates that the required parameter for the TYPE
            command is missing and Zorp rejects the request.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Missing parameter for the TYPE command;");
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      
      mytype = self->request_param->str[0];
      switch(mytype)
        {
        case 'a':
        case 'A':
        case 'i':
        case 'I':
          g_string_truncate(self->request_param, 0);
          g_string_append_c(self->request_param, toupper(mytype));
          g_string_up(self->request_param);
          break;
          
        case 'l':
        case 'L':
        case 'e':
        case 'E':
          /*LOG
            This message indicates that the requested transfer type specification is normally valid
            but currently unsupported by the proxy and Zorp rejects the request.
           */
          z_proxy_log(self, FTP_ERROR, 3, "Valid, but unsupported transfer type specification; type='%c'", mytype);
          SET_ANSWER(MSG_COMMAND_NOT_IMPLEMENTED_P);
          z_proxy_return(self, FTP_REQ_REJECT);

        default:
          SET_ANSWER(MSG_COMMAND_NOT_RECOGNIZED);
          /*LOG
            This message indicates that the requested transfer type specification is invalid and
            Zorp rejects the request.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Unknown transfer type specification; type='%c'", mytype);
          z_proxy_return(self, FTP_REQ_REJECT); 
        }
    }
  else
    {
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_parse_ABOR(FtpProxy *self)
{
  char buf[3];
  gsize len;

  z_proxy_enter(self);
  buf[0]=0xff;
  buf[1]=0xf4;
  buf[2]=0xff;
  if (self->ftp_state == FTP_STATE_CONVERSATION || self->ftp_state == FTP_STATE_DATA)
    {
      z_stream_write_pri(self->super.endpoints[EP_SERVER], buf, 3, &len, NULL);
      buf[0]=0xf2;
      z_stream_write(self->super.endpoints[EP_SERVER], buf, 1, &len, NULL);
      
      self->state = FTP_SERVER_TO_CLIENT;
      ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
      z_proxy_return(self, FTP_REQ_ACCEPT);
    }
  else if (self->ftp_state == FTP_STATE_RENAME)
    {
      ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
    }
  SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
  z_proxy_return(self, FTP_REQ_REJECT);
}

guint
ftp_command_answer_ABOR(FtpProxy *self)
{
  z_proxy_enter(self);
  if (self->ftp_state == FTP_STATE_CONVERSATION ||
     self->ftp_state == FTP_STATE_DATA)
    {
      if (self->answer_cmd->str[0] == '2')
        {
          ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
          self->oldstate = FTP_CLIENT_TO_SERVER;
        }
      else if (self->answer_cmd->str[0] == '4')
        {
          self->oldstate = FTP_SERVER_TO_CLIENT;
          self->data_state = 0;
        }
    }
  z_proxy_return(self, FTP_RSP_ACCEPT);
}

guint
ftp_command_parse_noarg(FtpProxy *self)
{
  z_proxy_enter(self);
  switch (self->ftp_state)
  {
  case FTP_STATE_CONVERSATION:
    g_string_assign(self->request_param, "");
    break;

  default:
    SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
    z_proxy_return(self, FTP_RSP_REJECT);
  }
  z_proxy_return(self, FTP_RSP_ACCEPT);
}

guint
ftp_command_parse_HELP(FtpProxy *self G_GNUC_UNUSED)
{
  return FTP_RSP_ACCEPT;
}

guint
ftp_command_parse_MODE(FtpProxy *self)
{
  char mymode;

  z_proxy_enter(self);
  if (self->ftp_state == FTP_STATE_CONVERSATION ||
      self->ftp_state == FTP_STATE_DATA)
    {
      if (self->request_param->len == 0)
        {
          SET_ANSWER(MSG_MISSING_PARAMETER);
          /*LOG
            This message indicates that the required parameter for the MODE
            command is missing and Zorp rejects the request.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Missing parameter to the MODE command;");
          z_proxy_return(self, FTP_REQ_REJECT);
        }

      mymode = self->request_param->str[0];
      switch(mymode)
        {
        case 's':
        case 'S':
        case 'b':
        case 'B':
        case 'c':
        case 'C':
          g_string_truncate(self->request_param, 0);
          g_string_append_c(self->request_param, toupper(mymode));
          break;
          
        default:
          /*LOG
            This message indicates that the MODE command parameter is invalid and
            Zorp rejects the request.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Invalid parameter to the MODE command; mode='%c'", mymode);
          SET_ANSWER(MSG_COMMAND_NOT_RECOGNIZED);
          z_proxy_return(self, FTP_REQ_REJECT); 
        }
    }
  else
    {
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_parse_string(FtpProxy *self)
{
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
    case FTP_STATE_DATA:
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_parse_STRU(FtpProxy *self)
{
  char mystru;
  
  z_proxy_enter(self);
  if (self->ftp_state == FTP_STATE_CONVERSATION ||
      self->ftp_state == FTP_STATE_DATA)
    {
      if (self->request_param->len == 0)
        {
          SET_ANSWER(MSG_MISSING_PARAMETER);
          /*LOG
            This message indicates that the required parameter for the STRU
            command is missing and Zorp rejects the request.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Missing parameter to the STRU command;");
          z_proxy_return(self, FTP_REQ_REJECT);
        }
        
      mystru = self->request_param->str[0];
      switch(mystru)
        {
        case 'f':
        case 'F':
          g_string_truncate(self->request_param, 0);
          g_string_append_c(self->request_param, toupper(mystru));
          break;
          
        default:
          SET_ANSWER(MSG_COMMAND_NOT_RECOGNIZED);
          /*LOG
            This message indicates that the STRU command parameter is invalid and
            Zorp rejects the request.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Invalid parameter to the STRU command; stru='%c'", mystru);
          z_proxy_return(self, FTP_REQ_REJECT); 
        }
    }
  else
    {
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_data_server_start_PORT(FtpProxy *self)
{
  guint port;
  gchar tmpaddr[16];

  z_proxy_enter(self);
  if (!ftp_data_prepare(self, EP_SERVER, 'L'))
    {
      SET_ANSWER(MSG_ERROR_PARSING_PORT);
      self->data_state = 0;
      /*LOG
        This message indicates that Zorp was unable to start listening for
        the data connection on the server side and Zorp rejects the request.
       */
      z_proxy_log(self, FTP_ERROR, 2, "Error preparing server-side data connection (PORT);");
      z_proxy_return(self, FTP_REQ_REJECT);
    }

  if (self->masq_address[EP_SERVER]->len)
    g_strlcpy(tmpaddr, self->masq_address[EP_SERVER]->str, sizeof(tmpaddr));
  else
    z_inet_ntoa(tmpaddr, sizeof(tmpaddr), ((struct sockaddr_in *) &self->data_local[EP_SERVER]->sa)->sin_addr);

  g_strdelimit(tmpaddr, ".", ',');
  /* FIXME: This check must be not in here. maybe in z_dispatch_register? */
  port = ntohs(((struct sockaddr_in *) &self->data_local[EP_SERVER]->sa)->sin_port);
  if (port == 0)
    {
      SET_ANSWER(MSG_ERROR_PARSING_PORT);
      /*LOG
        This message indicates that Zorp was unable to start listening for
        the data connection on the server side and Zorp rejects the request.
       */
      z_proxy_log(self, FTP_ERROR, 2, "There was an error binding a server-side listener;");
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  
  g_string_sprintf(self->request_param, "%s,%d,%d", tmpaddr, (port & 0xff00) >> 8, port & 0x00ff);
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_data_server_start_PASV(FtpProxy *self)
{
  guchar nums[6];
  gchar ip[17];
  guint16 port;

  z_proxy_enter(self);
  if (!ftp_parse_search_nums(self->answer_param->str, self->answer_param->len, nums))
    {
      SET_ANSWER(MSG_ERROR_PARAMETER_PASV);
      /*LOG
        This message indicates that the response to the PASV command is invalid and Zorp
        rejects the response.
       */
      z_proxy_log(self, FTP_VIOLATION, 2, "Error parsing PASV response; param='%s'", self->answer_param->str);
      z_proxy_return(self, FTP_RSP_REJECT);
    }

  g_snprintf(ip, sizeof(ip), "%d.%d.%d.%d", nums[0], nums[1], nums[2], nums[3]);
  port = nums[4] * 256 + nums[5];
  self->data_remote[EP_SERVER] = z_sockaddr_inet_new(ip, port);
  if (!ftp_data_prepare(self, EP_SERVER, 'C'))
    {
      SET_ANSWER(MSG_ERROR_PARSING_PASV);
      self->data_state = 0;
      /*LOG
        This message indicates that the proxy was unable to connect to the
        server on the port specified in its PASV response and Zorp rejects the
        response.
       */
      z_proxy_log(self, FTP_ERROR, 2, "Error preparing data connection to the server (PASV);");
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_proxy_return(self, FTP_RSP_ACCEPT);
}

guint
ftp_data_server_start_EPRT(FtpProxy *self)
{
  guint port;
  gchar tmpaddr[16];

  z_proxy_enter(self);
  if (!ftp_data_prepare(self, EP_SERVER, 'L'))
    {
      SET_ANSWER(MSG_ERROR_PARSING_PORT);
      self->data_state = 0;
      /*LOG
        This message indicates that Zorp was unable to start listening for
        the data connection on the server side and Zorp rejects the request.
       */
      z_proxy_log(self, FTP_ERROR, 2, "Error preparing server-side data connection listener (EPRT);");
      z_proxy_return(self, FTP_REQ_REJECT);
    }

  if (self->masq_address[EP_SERVER]->len)
    g_strlcpy(tmpaddr, self->masq_address[EP_SERVER]->str, sizeof(tmpaddr));
  else
    z_inet_ntoa(tmpaddr, sizeof(tmpaddr), ((struct sockaddr_in *) &self->data_local[EP_SERVER]->sa)->sin_addr);

  port = ntohs(((struct sockaddr_in *) &self->data_local[EP_SERVER]->sa)->sin_port);
  if (port == 0)
    {
      SET_ANSWER(MSG_ERROR_PARSING_PORT);
      /*LOG
        This message indicates that Zorp was unable to start listening for
        the data connection on the server side and Zorp rejects the request.
       */
      z_proxy_log(self, FTP_ERROR, 2, "Cannot bind to the given address (EPRT);");
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  g_string_printf(self->request_param, "|1|%s|%d|", tmpaddr, port);
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_data_server_start_EPSV(FtpProxy *self)
{
  gchar **split;
  guint port;
  gchar *err;
  gchar tmpline[FTP_LINE_MAX_LEN];
  gchar *start, *end;
  gchar delim[2];
  ZPolicyObj *sockaddr;
  ZSockAddr *tmpaddr;
  gchar tmpip[16];
  guint res = FTP_RSP_ACCEPT;

  z_proxy_enter(self);
  if (self->answer_param->len <= 0)
    {
      /*LOG
        This message indicates that the required parameter for the EPSV
        command is missing and Zorp rejects the response.
       */
      z_proxy_log(self, FTP_VIOLATION, 2, "Missing parameter (EPSV);");
      z_proxy_return(self, FTP_RSP_REJECT);
    }

  g_strlcpy(tmpline, self->answer_param->str, sizeof(tmpline));
  start = strchr(tmpline, '(');
  if (!start)
    {
      /*LOG
        This message indicates that the parameter of the EPSV response does not begin with
        a bracket and Zorp rejcets the response.
       */
      z_proxy_log(self, FTP_VIOLATION, 2, "Bad parameter (EPSV), not beginning with bracket; rsp_param='%s'", self->answer_param->str);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  *start = 0;
  end = strchr(start + 1, ')');
  if (!end)
    {
      /*LOG
        This message indicates that the parameter of the EPSV response does not have a closing
        bracket and Zorp rejects the response.
       */
      z_proxy_log(self, FTP_VIOLATION, 2, "Bad parameter (EPSV), not closing with bracket; rsp_param='%s'", self->answer_param->str);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  *end = 0;
  delim[0] = start[1];
  delim[1] = 0;
  split = g_strsplit(start + 1, delim, 6);
  if (split == NULL ||
      split[0] == NULL ||
      split[1] == NULL ||
      split[2] == NULL ||
      split[3] == NULL ||
      split[4] == NULL ||
      split[5] != NULL)
    {
      SET_ANSWER(MSG_ERROR_PARAMETER_EPSV);
      /*LOG
        This message indicates that the EPSV command response is invalid and
        Zorp rejects the response.
       */
      z_proxy_log(self, FTP_VIOLATION, 2, "Error parsing EPSV response; param='%s'", self->answer_param->str);
      res = FTP_RSP_REJECT;
      goto exit;
    }
  
  if (strlen(split[1]) == 0 || strcmp(split[1],"1") == 0)
    {
      port = strtol(split[3], &err, 10);
      if (port == 0 || *err != 0)
        {
          SET_ANSWER(MSG_ERROR_PARAMETER_EPSV);
          g_strfreev(split);
          /*LOG
            This message indicates that the port number of the EPSV command response
            is invalid and Zorp rejects the response.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Bad parameter (EPSV), invalid port; rsp_param='%s'", self->answer_param->str);
          res = FTP_RSP_REJECT;
          goto exit;
        }

      if (strlen(split[2]) > 0)
        {
          self->data_remote[EP_SERVER] = z_sockaddr_inet_new(split[2], port);
        }
      else
        {
          /* FIXME: use z_proxy_get_addresses */
          z_policy_lock(self->super.thread);
          sockaddr = z_session_getattr(self->super.handler, "server_address");
          if (!sockaddr || !z_policy_sockaddr_check(sockaddr))
            {
              z_policy_unlock(self->super.thread);
              /*LOG
                This message indicates that Proxy cannot detect the server address.
                This an internal error.
               */
              z_proxy_log(self, FTP_VIOLATION, 2, "Internal error, cannot detect server address;");
              res = FTP_RSP_REJECT;
              goto exit;
            }
          tmpaddr = z_policy_sockaddr_get_sa(sockaddr);
          z_inet_ntoa(tmpip, sizeof(tmpip), ((struct sockaddr_in *) &tmpaddr->sa)->sin_addr);
          z_sockaddr_unref(tmpaddr);
          self->data_remote[EP_SERVER] = z_sockaddr_inet_new(tmpip, port);
          z_policy_unlock(self->super.thread);
        }
    }
  else
    {
      SET_ANSWER(MSG_ERROR_PARAMETER_EPSV);
      g_strfreev(split);
      /*LOG
        This message indicates that the protocol specified by the EPSV command response
        is not supported by the proxy and Zorp rejects the response.
       */
      z_proxy_log(self, FTP_VIOLATION, 1, "Unknown protocol type (EPSV); protocol='%s', rsp_param='%s'", split[1], self->answer_param->str);
      res = FTP_RSP_REJECT;
      goto exit;
    }

  if (!ftp_data_prepare(self, EP_SERVER, 'C'))
    {
      SET_ANSWER(MSG_ERROR_PARSING_PASV);
      self->data_state = 0;
      /*LOG
        This message indicates that the proxy was unable to connect to the
        server on the port specified in its EPSV response and Zorp rejects the
        response.
       */
      z_proxy_log(self, FTP_ERROR, 2, "Error preparing data connection to the server (EPSV);");
      res = FTP_RSP_REJECT;
    }

exit:
  if (split)
    g_strfreev(split);
  z_proxy_return(self, res);
}

/**
 * Parse PORT FTP command.
 *
 * @param[in] self FtpProxy instance
 *
 * @returns FTP_REQ_ACCEPT if the connection is to be accepted, FTP_REQ_REJECT if it should be rejected
 **/
guint
ftp_command_parse_PORT(FtpProxy *self)
{
  guchar nums[6];
  gchar ip[17];
  guint16 port;
  guint res = FTP_REQ_ACCEPT;

  z_proxy_enter(self);
  if (self->ftp_state == FTP_STATE_DATA)
    {
      ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
      ftp_data_reset(self);
    }

  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
      if (!ftp_parse_nums(self->request_param->str, self->request_param->len, nums))
        {
          SET_ANSWER(MSG_ERROR_PARAMETER_PORT);
          /*LOG
            This message indicates that the parameter of the PORT command is invalid and Zorp
            rejects the request.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Invalid parameters to the PORT command; param='%s'", self->request_param->str);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      g_snprintf(ip, sizeof(ip), "%d.%d.%d.%d", nums[0], nums[1], nums[2], nums[3]);
      port = nums[4] * 256 + nums[5];
      self->data_remote[EP_CLIENT] = z_sockaddr_inet_new(ip, port);

      switch (self->data_mode)
        {
        case FTP_DATA_PASSIVE:
           g_string_assign(self->request_cmd, "PASV");
           g_string_assign(self->request_param, "");
           break;
           
        case FTP_DATA_ACTIVE:
        case FTP_DATA_KEEP:
          res = ftp_data_server_start_PORT(self);
          break;
          
        default:
          /*LOG
            This message indicates that the 'data_mode' attribute of the policy
            is invalid and Zorp rejects the request. Check the 'data_mode' attribute.
           */
          z_proxy_log(self, FTP_POLICY, 1, "Connection mode not supported; data_mode='%d'", self->data_mode);
          SET_ANSWER(MSG_ERROR_PARSING_PORT);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_proxy_return(self, res);
}

guint 
ftp_command_answer_PORT(FtpProxy *self)
{
  guint res = FTP_RSP_ACCEPT;

  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
      switch (self->data_mode)
        {
        case FTP_DATA_PASSIVE:
          switch (self->answer_cmd->str[0])
            {
            case '2':
              res = ftp_data_server_start_PASV(self);
              if (res == FTP_RSP_ACCEPT)
                {
                  if (!ftp_data_prepare(self, EP_CLIENT, 'C'))
                    {
                      self->data_state = 0;
                      SET_ANSWER(MSG_ERROR_PARSING_PORT);
                      /*LOG
                        This message indicates that the proxy was unable to connect to the
                        client on the port specified in its PORT response and Zorp rejects the
                        response.
                       */
                      z_proxy_log(self, FTP_ERROR, 2, "Error preparing client-side data connection (PORT->PASV);");
                      z_proxy_return(self, FTP_RSP_REJECT);
                    }
                  SET_ANSWER(MSG_PORT_SUCCESFULL);
                  res = FTP_RSP_ACCEPT;
                }
              ftp_proto_state_set(self, FTP_STATE_DATA);
              break;

            case '4':
            case '5':
              ftp_data_reset(self);
              z_proxy_return(self, FTP_RSP_ACCEPT);

            default:
              SET_ANSWER(MSG_ERROR_PARSING_PORT);
              /*LOG
                This message indicates that the response of the PASV command
                is invalid and Zorp rejects the response.
               */
              z_proxy_log(self, FTP_VIOLATION, 2, "Error parsing the server answer to the PASV command (PORT->PASV); answer='%s'", self->answer_cmd->str);
              ftp_data_reset(self);
              z_proxy_return(self, FTP_RSP_REJECT);
            }
          break;

        case FTP_DATA_ACTIVE:
        case FTP_DATA_KEEP:
          switch (self->answer_cmd->str[0])
            {
            case '2':
              if (!ftp_data_prepare(self, EP_CLIENT, 'C'))
                {
                  self->data_state = 0;
                  SET_ANSWER(MSG_ERROR_PARSING_PORT);
                  /*LOG
                    This message indicates that the proxy was unable to connect to the
                    client on the port specified in its PORT response and Zorp rejects the
                    response.
                   */
                  z_proxy_log(self, FTP_ERROR, 2, "Error preparing client-side data connection (PORT);");
                  z_proxy_return(self, FTP_RSP_REJECT);
                }
              ftp_proto_state_set(self, FTP_STATE_DATA);
              break;

            case '4':
            case '5':
              ftp_data_reset(self);
              z_proxy_return(self, FTP_RSP_ACCEPT);

            default:
              SET_ANSWER(MSG_ERROR_PARSING_PORT);
              /*LOG
                This message indicates that the response of the PORT command is invalid
                and Zorp rejects the response.
               */
              z_proxy_log(self, FTP_VIOLATION, 2, "Error parsing the server answer to the PORT command; answer='%s'", self->answer_cmd->str);
              ftp_data_reset(self);
              z_proxy_return(self, FTP_RSP_ACCEPT);
            }
          break;

        default:
          break;
        }
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_proxy_return(self, res);
}

guint
ftp_command_parse_PASV(FtpProxy *self)
{
  guint res = FTP_REQ_ACCEPT;

  z_proxy_enter(self);
  if (self->ftp_state == FTP_STATE_DATA)
    {
      ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
      ftp_data_reset(self);
    }

  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
      g_string_truncate(self->request_param, 0);
      self->data_state = 0;
      switch (self->data_mode)
        {
        case FTP_DATA_KEEP:
        case FTP_DATA_PASSIVE:
          break;
          
        case FTP_DATA_ACTIVE:
          g_string_assign(self->request_cmd, "PORT");
          g_string_truncate(self->request_param, 0);
          res = ftp_data_server_start_PORT(self);
          break;
          
        default:
          /*LOG
            This message indicates that the 'data_mode' attribute of the policy
            is invalid and Zorp rejects the request. Check the 'data_mode' attribute.
           */
          z_proxy_log(self, FTP_POLICY, 1, "Connection mode not supported; data_mode='%d'", self->data_mode);
          SET_ANSWER(MSG_ERROR_PARSING_PORT);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_answer_PASV(FtpProxy *self)
{
  gchar *start, *end;
  guint port;
  gchar tmpline[FTP_LINE_MAX_LEN];
  gchar tmpaddr[16];
  guint ret = FTP_RSP_ACCEPT;

  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
    case FTP_STATE_DATA:
      switch (self->data_mode)
        {
        case FTP_DATA_PASSIVE:
        case FTP_DATA_KEEP:
          switch (self->answer_cmd->str[0])
            {
            case '2':
              ret = ftp_data_server_start_PASV(self);
              if (ret == FTP_RSP_ACCEPT)
                {
                  if (!ftp_data_prepare(self, EP_CLIENT, 'L'))
                    {
                      ftp_data_reset(self);
                      SET_ANSWER(MSG_ERROR_PARSING_PASV);
                      /*LOG
                        This message indicates that Zorp was unable to start listening for
                        the data connection on the client side and Zorp rejects the request.
                       */
                      z_proxy_log(self, FTP_ERROR, 2, "Error preparing client-side data connection listener (PASV); error='bind error'");
                      z_proxy_return(self, FTP_RSP_REJECT);
                    }
                  
                  if (self->masq_address[EP_CLIENT]->len)
                    g_strlcpy(tmpaddr, self->masq_address[EP_CLIENT]->str, sizeof(tmpaddr));
                  else
                    z_inet_ntoa(tmpaddr, sizeof(tmpaddr), ((struct sockaddr_in *) &self->data_local[EP_CLIENT]->sa)->sin_addr);
                  g_strdelimit(tmpaddr, ".", ',');

                  port = ntohs(((struct sockaddr_in *) &self->data_local[EP_CLIENT]->sa)->sin_port);
                  if (port == 0)
                    {
                      ftp_data_reset(self);
                      SET_ANSWER(MSG_ERROR_PARSING_PASV);
                      /*LOG
                        This message indicates that Zorp was unable to start listening for
                        the data connection on the client side and Zorp rejects the request.
                       */
                      z_proxy_log(self, FTP_ERROR, 2, "Error preparing client-side data connection listener (PASV); error='port is invalid'");
                      z_proxy_return(self, FTP_RSP_REJECT);
                    }

                  g_strlcpy(tmpline, self->answer_param->str, sizeof(tmpline));
                  g_string_truncate(self->answer_param, 0);
                  start = strchr(tmpline, '(');
                  end = NULL;
                  if (start)
                    {
                      *start = 0;
                      end = strchr(start, ')');
                      g_string_assign(self->answer_param, tmpline);
                    }
                  g_string_append_printf(self->answer_param, "(%s,%d,%d)%s", tmpaddr, (port & 0xff00) >> 8, port & 0x00ff, end ? end + 1 : "");
                }
              ftp_proto_state_set(self, FTP_STATE_DATA);
              break;
              
            default:
              self->data_state = 0;
              z_proxy_return(self, FTP_RSP_ACCEPT);
            }
          break;

        case FTP_DATA_ACTIVE:
          switch (self->answer_cmd->str[0])
            {
            case '2':
              if (!ftp_data_prepare(self, EP_CLIENT, 'L'))
                {
                  self->data_state = 0;
                  SET_ANSWER(MSG_ERROR_PARSING_PASV);
                  /*LOG
                    This message indicates that Zorp was unable to start listening for
                    the data connection on the client side and Zorp rejects the request.
                   */
                  z_proxy_log(self, FTP_ERROR, 2, "Error preparing client-side data connection listener (PASV->PORT);");
                  z_proxy_return(self, FTP_RSP_REJECT);
                }

              g_string_assign(self->answer_cmd, "227");
              if (self->masq_address[EP_CLIENT]->len)
                g_strlcpy(tmpaddr, self->masq_address[EP_CLIENT]->str, sizeof(tmpaddr));
              else
                z_inet_ntoa(tmpaddr, sizeof(tmpaddr), ((struct sockaddr_in *) &self->data_local[EP_CLIENT]->sa)->sin_addr);
              
              g_strdelimit(tmpaddr, ".", ',');
              port = ntohs(((struct sockaddr_in *) &self->data_local[EP_CLIENT]->sa)->sin_port);
              if (port==0)
                {
                  SET_ANSWER(MSG_ERROR_PARSING_PASV);
                  self->data_state = 0;
                  /*LOG
                    This message indicates that Zorp was unable to start listening for
                    the data connection on the client side and Zorp rejects the request.
                   */
                  z_proxy_log(self, FTP_ERROR, 2, "Error preparing client-side data connection listener (PASV->PORT);");
                  z_proxy_return(self, FTP_RSP_REJECT);
                }
              g_string_sprintf(self->answer_param, "Entering Passive mode (%s,%d,%d).", tmpaddr, (port & 0xff00) >> 8, port & 0x00ff);
              ftp_proto_state_set(self, FTP_STATE_DATA);
              break;

            default:
              SET_ANSWER(MSG_ERROR_PARSING_PASV);
              self->data_state = 0;
              /*LOG
                This message indicates that the response of the PORT command is invalid
                and Zorp rejects the response.
               */
              z_proxy_log(self, FTP_VIOLATION, 2, "Error parsing the server answer to the PORT command (PASV->PORT); answer='%s'", self->answer_cmd->str);
              z_proxy_return(self, FTP_RSP_REJECT);
            }
          break;

        default:
          break;
        }
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_proxy_return(self, ret);
}

guint
ftp_command_parse_EPRT(FtpProxy *self)
{
  guint16 port;
  guint res = FTP_REQ_ACCEPT;
  gchar **split;
  gchar delim[2];
  gchar *err;

  z_proxy_enter(self);
  if (self->ftp_state == FTP_STATE_DATA)
    {
      ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
      ftp_data_reset(self);
    }

  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
      if (self->request_param->len <= 0)
        {
          /*LOG
            This message indicates that the required parameter for the EPRT
            command is missing and Zorp rejects the request.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Missing parameter (EPRT);");
          z_proxy_return(self, FTP_RSP_REJECT);
        }

      delim[0] = self->request_param->str[0];
      delim[1] = 0;
      split = g_strsplit(self->request_param->str, delim, 6);
      if (split[0] == NULL ||
          split[1] == NULL ||
          split[2] == NULL ||
          split[3] == NULL ||
          split[4] == NULL ||
          split[5] != NULL)
        {
          SET_ANSWER(MSG_ERROR_PARAMETER_EPRT);
          g_strfreev(split);
          /*LOG
            This message indicates that the parameter of the EPRT command is invalid
            and Zorp rejects the request.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Bad parameter (EPRT); req_param='%s'", self->request_param->str);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
  
      if (strcmp(split[1],"1") == 0)
        {
          port = strtol(split[3], &err, 10);
          if (port == 0 || *err != 0)
            {
              SET_ANSWER(MSG_ERROR_PARAMETER_EPRT);
              g_strfreev(split);
              /*LOG
                This message indicates that the port number of the EPRT command
                is invalid and Zorp rejects the request.
               */
              z_proxy_log(self, FTP_VIOLATION, 2, "Bad port parameter (EPRT); req_param='%s'", self->request_param->str);
              z_proxy_return(self, FTP_REQ_REJECT);
            }
        }
      else
        {
          SET_ANSWER(MSG_ERROR_PARAMETER_EPRT);
          g_strfreev(split);
          /*LOG
            This message indicates that the protocol specified by the EPRT command
            is not supported by the proxy and Zorp rejects the response.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Unknown protocol method (EPRT); protocol='%s', req_param='%s'", split[1], self->request_param->str);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      
      self->data_remote[EP_CLIENT] = z_sockaddr_inet_new(split[2], port);
      g_strfreev(split);
      if (!self->data_remote[EP_CLIENT])
        {
          SET_ANSWER(MSG_ERROR_PARAMETER_EPRT);
          /*LOG
            This message indicates that the host address of the EPRT command
            is invalid and Zorp rejects the request.
           */
          z_proxy_log(self, FTP_VIOLATION, 2, "Bad host address (EPRT); ip='%s', req_param='%s'", split[2], self->request_param->str);
          z_proxy_return(self, FTP_REQ_REJECT);
        }

      switch (self->data_mode)
        {
        case FTP_DATA_PASSIVE:
           g_string_assign(self->request_cmd, "EPSV");
           g_string_assign(self->request_param, "");
           break;
           
        case FTP_DATA_ACTIVE:
        case FTP_DATA_KEEP:
          res = ftp_data_server_start_EPRT(self);
          break;
          
        default:
          /*LOG
            This message indicates that the 'data_mode' attribute of the policy
            is invalid and Zorp rejects the request. Check the 'data_mode' attribute.
           */
          z_proxy_log(self, FTP_POLICY, 1, "Connection mode not supported; data_mode='%d'", self->data_mode);
          SET_ANSWER(MSG_ERROR_PARSING_PORT);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_proxy_return(self, res);
}

guint 
ftp_command_answer_EPRT(FtpProxy *self)
{
  guint res = FTP_RSP_ACCEPT;

  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
      switch (self->data_mode)
        {
        case FTP_DATA_PASSIVE:
          switch (self->answer_cmd->str[0])
            {
            case '2':
              res = ftp_data_server_start_EPSV(self);
              if (res == FTP_RSP_ACCEPT)
                {
                  if (!ftp_data_prepare(self, EP_CLIENT, 'C'))
                    {
                      self->data_state = 0;
                      SET_ANSWER(MSG_ERROR_PARSING_PORT);
                      /*LOG
                        This message indicates that the proxy was unable to connect to the
                        client specified in the EPRT response and Zorp rejects the
                        response.
                       */
                      z_proxy_log(self, FTP_ERROR, 2, "Error preparing client connect (EPRT);");
                      z_proxy_return(self, FTP_RSP_REJECT);
                    }
                  SET_ANSWER(MSG_PORT_SUCCESFULL);
                  res = FTP_RSP_ACCEPT;
                }
              ftp_proto_state_set(self, FTP_STATE_DATA);
              break;

            default:
              SET_ANSWER(MSG_ERROR_PARSING_PORT);
              self->data_state = 0;
              /*LOG
                This message indicates that the response of the EPRT is invalid
                and Zorp rejects the response.
               */
              z_proxy_log(self, FTP_VIOLATION, 2, "Bad server answer (EPRT); rsp='%s'", self->answer_cmd->str);
              z_proxy_return(self, FTP_RSP_REJECT);
            }
          break;

        case FTP_DATA_ACTIVE:
        case FTP_DATA_KEEP:
          switch (self->answer_cmd->str[0])
            {
            case '2':
              if (!ftp_data_prepare(self, EP_CLIENT, 'C'))
                {
                  self->data_state = 0;
                  SET_ANSWER(MSG_ERROR_PARSING_PORT);
                  /*LOG
                    This message indicates that the proxy was unable to connect to the
                    client specified in the EPRT response and Zorp rejects the
                    response.
                   */
                  z_proxy_log(self, FTP_ERROR, 2, "Error preparing client connect (EPRT);");
                  z_proxy_return(self, FTP_RSP_REJECT);
                }
              ftp_proto_state_set(self, FTP_STATE_DATA);
              break;

            default:
              self->data_state = 0;
              z_proxy_return(self, FTP_RSP_ACCEPT);
            }
          break;

        default:
          break;
        }
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_proxy_return(self, res);
}

guint
ftp_command_parse_EPSV(FtpProxy *self)
{
  guint res = FTP_REQ_ACCEPT;

  z_proxy_enter(self);
  if (self->ftp_state == FTP_STATE_DATA)
    {
      ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
      ftp_data_reset(self);
    }

  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
      g_string_assign(self->request_param, "");
      self->data_state = 0;
      switch (self->data_mode)
        {
        case FTP_DATA_KEEP:
        case FTP_DATA_PASSIVE:
          break;
          
        case FTP_DATA_ACTIVE:
          g_string_assign(self->request_cmd, "EPRT");
          g_string_assign(self->request_param, "");
          res = ftp_data_server_start_EPRT(self);
          break;
          
        default:
          /*LOG
            This message indicates that the 'data_mode' attribute of the policy
            is invalid and Zorp rejects the request. Check the 'data_mode' attribute.
           */
          z_proxy_log(self, FTP_POLICY, 1, "Connection mode not supported; data_mode='%d'", self->data_mode);
          SET_ANSWER(MSG_ERROR_PARSING_PORT);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_answer_EPSV(FtpProxy *self)
{
  gchar *start, *end;
  guint port;
  gchar tmpline[FTP_LINE_MAX_LEN];
  guint ret = FTP_RSP_ACCEPT;

  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
      switch (self->data_mode)
        {
        case FTP_DATA_PASSIVE:
        case FTP_DATA_KEEP:
          switch (self->answer_cmd->str[0])
            {
            case '2':
              ret = ftp_data_server_start_EPSV(self);
              if (ret == FTP_RSP_ACCEPT)
                {
                  if (!ftp_data_prepare(self, EP_CLIENT, 'L'))
                    {
                      self->data_state = 0;
                      SET_ANSWER(MSG_ERROR_PARSING_PASV);
                      /*LOG
                        This message indicates that Zorp was unable to start listening for
                        the data connection on the client side and Zorp rejects the response.
                       */
                      z_proxy_log(self, FTP_ERROR, 2, "Error preparing client listen (EPSV);");
                      z_proxy_return(self, FTP_RSP_REJECT);
                    }

                  port = ntohs(((struct sockaddr_in *) &self->data_local[EP_CLIENT]->sa)->sin_port);
                  if (port == 0)
                    {
                      SET_ANSWER(MSG_ERROR_PARSING_PASV);
                      self->data_state = 0;
                      /*LOG
                        This message indicates that Zorp was unable to start listening for
                        the data connection on the client side and Zorp rejects the response.
                       */
                      z_proxy_log(self, FTP_ERROR, 2, "Error preparing client listen (EPSV);");
                      z_proxy_return(self, FTP_RSP_REJECT);
                    }

                  g_strlcpy(tmpline, self->answer_param->str, sizeof(tmpline));
                  start = strchr(tmpline, '(');
                  end = NULL;
                  if (start)
                    {
                      *start = 0;
                      end = strchr(start + 1, ')');
                      g_string_assign(self->answer_param, tmpline);
                    }
                  g_string_append_printf(self->answer_param, "(|||%d|)", port);
                  if (end)
                    g_string_append(self->answer_param, end + 1);
                }
              ftp_proto_state_set(self, FTP_STATE_DATA);
              break;
              
            default:
              self->data_state = 0;
              z_proxy_return(self, FTP_RSP_ACCEPT);
            }
          break;

        case FTP_DATA_ACTIVE:
          switch (self->answer_cmd->str[0])
            {
            case '2':
              if (!ftp_data_prepare(self, EP_CLIENT, 'L'))
                {
                  self->data_state = 0;
                  SET_ANSWER(MSG_ERROR_PARSING_PASV);
                  /*LOG
                    This message indicates that Zorp was unable to start listening for
                    the data connection on the client side and Zorp rejects the response.
                   */
                  z_proxy_log(self, FTP_ERROR, 2, "Error preparing client listen (EPSV);");
                  z_proxy_return(self, FTP_RSP_REJECT);
                }
              g_string_assign(self->answer_cmd, "229");
              port = ntohs(((struct sockaddr_in *) &self->data_local[EP_CLIENT]->sa)->sin_port);
              if(port==0)
                {
                  SET_ANSWER(MSG_ERROR_PARSING_PASV);
                  self->data_state = 0;
                  /*LOG
                    This message indicates that Zorp was unable to start listening for
                    the data connection on the client side and Zorp rejects the response.
                   */
                  z_proxy_log(self, FTP_ERROR, 2, "Error preparing client listen (EPSV);");
                  z_proxy_return(self, FTP_RSP_REJECT);
                }

              g_string_printf(self->answer_param, "Entering Extended Passive Mode (|||%d|)", port);
              ftp_proto_state_set(self, FTP_STATE_DATA);
              break;

            default:
              SET_ANSWER(MSG_ERROR_PARSING_PASV);
              self->data_state = 0;
              /*LOG
                This message indicates that the response of the EPSV command is invalid
                and Zorp rejects the response.
               */
              z_proxy_log(self, FTP_VIOLATION, 2, "Bad server answer (EPSV); rsp='%s'", self->answer_cmd->str);
              z_proxy_return(self, FTP_RSP_REJECT);
            }
          break;

        default:
          break;
        }
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_proxy_return(self, ret);
}

guint
ftp_command_answer_RNFR(FtpProxy *self)
{
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
      switch(self->answer_code)
        {
          case 350:
            ftp_proto_state_set(self, FTP_STATE_RENAME);
          break;
        }
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_RSP_REJECT);
    }
  z_proxy_return(self, FTP_RSP_ACCEPT);
}

guint
ftp_command_parse_RNTO(FtpProxy *self)
{
  guint res = FTP_REQ_ACCEPT;
  
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_RENAME:
      ftp_proto_state_set(self, FTP_STATE_CONVERSATION);
      res = ftp_command_parse_path(self);
      break;
      
    default:
      SET_ANSWER(MSG_RNFR_RNTO);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  z_proxy_return(self, res);
}

guint
ftp_command_parse_ALLO(FtpProxy *self)
{
  glong num1;
  glong num2;
  gchar *str;
  gchar *endptr;
  
  z_proxy_enter(self);
  switch (self->ftp_state)
    {
    case FTP_STATE_CONVERSATION:
    case FTP_STATE_DATA:
      if (self->request_param->len == 0)
        break;

      str = self->request_param->str;
      num1 = strtol(str, &endptr, 10);
      if (num1 < 0 || ((num1 == LONG_MAX || num1 == LONG_MIN) && errno == ERANGE))
        {
          z_proxy_log(self, FTP_VIOLATION, 3, "Size is out of accepted range; req='%s' size='%ld'", "ALLO", num1);
          z_proxy_return(self, FTP_REQ_REJECT);
        }
      
      if (*endptr == 0)
        z_proxy_return(self, FTP_REQ_ACCEPT);
      
      if (strlen(endptr) >= 4 && endptr[0] == ' ' && endptr[1] == 'R' && endptr[2] == ' ' && endptr[3] != ' ')
        {
          str = endptr + 3;
          num2 = strtol(str, &endptr, 10);
          if (num2 < 0 || ((num2 == LONG_MAX || num2 == LONG_MIN) && errno == ERANGE))
            {
              z_proxy_log(self, FTP_VIOLATION, 3, "Record number is out of accepted range; req='%s' size='%ld'", "ALLO", num2);
              z_proxy_return(self, FTP_REQ_REJECT);
            }
          if (*endptr == 0)
            z_proxy_return(self, FTP_REQ_ACCEPT);
        }
      break;

    default:
      SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
      z_proxy_return(self, FTP_REQ_REJECT);
    }
  /*LOG
    This message indicates that the parameter of the ALLO command is invalid
    and Zorp rejects the request.
   */
  z_proxy_log(self, FTP_VIOLATION, 2, "Error parsing command (ALLO); param='%s'", self->request_param->str);
  z_proxy_return(self, FTP_REQ_REJECT);
}

guint
ftp_command_parse_REIN(FtpProxy *self)
{
  z_proxy_enter(self);

  if (self->auth_tls_ok[EP_CLIENT])
    {
      /* we're using TLS and thus do not support REIN */
      z_proxy_log(self, FTP_INFO, 4, "REIN command is not allowed in FTPS mode;");
      SET_ANSWER(MSG_COMMAND_NOT_IMPLEMENTED);
      z_proxy_return(self, FTP_REQ_REJECT);
    }

  z_proxy_return(self, FTP_RSP_ACCEPT);
}

guint
ftp_command_answer_REIN(FtpProxy *self)
{
  switch (self->answer_cmd->str[0])
    {
    case '1':
      return FTP_NOOP;
    case '2':
      /* FIXME: ughh... I can't see how this code is relevant here ... */
      /* REFIX: This code set the state before login. */
      ftp_proto_state_set(self, FTP_STATE_LOGIN);
      g_string_assign(self->username, "");
      g_string_assign(self->password, "");
      break;
    }
  return FTP_RSP_ACCEPT;
}

guint
ftp_command_parse_REST(FtpProxy *self)
{
  guint ret;
  
  ret = ftp_command_parse_string(self);
  
  if (ret == FTP_REQ_ACCEPT)
    if (self->request_param->len == 0)
      ret = FTP_REQ_REJECT;
  
  return ret;
}

static GHashTable *
ftp_process_feature_list(FtpProxy *self, GList *incoming)
{
  GHashTable *filtered;
  GList *i;

  z_proxy_enter(self);

  filtered = g_hash_table_new(g_str_hash, g_str_equal);

  i = incoming;
  while (i)
    {
      gchar *item = (gchar *) i->data;
      gint verdict;

      verdict = ftp_policy_feature_hash_search(self, item);

      if (verdict == FTP_FEATURE_ACCEPT)
        g_hash_table_insert(filtered, item, NULL);

      i = g_list_next(i);
    }

  /* we have the list of accepted features in 'filtered', now insert all new values
     according to the policy
   */
  ftp_policy_feature_hash_handle_insert(self, filtered);

  /* we also have some hard-coded rules depending on FTPS settings:
   *  - client: != ACCEPT_STARTTLS / server *: we have to remove 'AUTH TLS', 'PROT' and 'PBSZ'
   *  - client: ACCEPT_STARTTLS / server != FORWARD_STARTTLS: we have to add 'AUTH TLS',
   *    'PBSZ' and 'PROT'
   */
  if (self->super.ssl_opts.security[EP_CLIENT] != PROXY_SSL_SEC_ACCEPT_STARTTLS)
    {
      g_hash_table_remove(filtered, "AUTH TLS");
      g_hash_table_remove(filtered, "PROT");
      g_hash_table_remove(filtered, "PBSZ");
    }
  else if ((self->super.ssl_opts.security[EP_CLIENT] == PROXY_SSL_SEC_ACCEPT_STARTTLS)
           && ((self->super.ssl_opts.security[EP_SERVER] != PROXY_SSL_SEC_FORWARD_STARTTLS)
               || (self->transparent_mode == FALSE)))
    {
      g_hash_table_insert(filtered, "AUTH TLS", NULL);
      g_hash_table_insert(filtered, "PROT", NULL);
      g_hash_table_insert(filtered, "PBSZ", NULL);
    }

  z_proxy_return(self, filtered);
}

static void
ftp_feature_add_cb(gpointer _key, gpointer _value G_GNUC_UNUSED, gpointer user_data)
{
  gchar *key = (gchar *) _key;
  GString *str = (GString *) user_data;

  g_string_append(str, key);
  g_string_append(str, "\n");
}

guint
ftp_command_parse_FEAT(FtpProxy *self)
{
  GHashTable *features = NULL;

  z_proxy_enter(self);

  switch (self->ftp_state)
  {
  case FTP_STATE_LOGIN:
  case FTP_STATE_LOGIN_U:
  case FTP_STATE_LOGIN_P:
  case FTP_STATE_CONVERSATION:
    g_string_assign(self->request_param, "");
    break;

  case FTP_STATE_PRECONNECT:
    /* we're in non-transparent mode, generate a proxy answer */
    features = ftp_process_feature_list(self, NULL);

    self->answer_code = 211;
    g_string_assign(self->answer_cmd, "211");
    g_string_assign(self->answer_param, "Features:\n");
    g_hash_table_foreach(features, ftp_feature_add_cb, self->answer_param);
    g_string_append(self->answer_param, "End");

    g_hash_table_destroy(features);

    ftp_proto_state_set(self, FTP_STATE_PRECONNECT_FEAT);

    z_proxy_return(self, FTP_PROXY_ANS);
    break;

  default:
    SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
    z_proxy_return(self, FTP_REQ_REJECT);
  }

  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_answer_FEAT(FtpProxy *self)
{
  gchar **lines;
  GList *features = NULL;
  GHashTable *filtered = NULL;

  z_proxy_enter(self);

  if (self->answer_code != 211)
    {
      /* If it was an error, and FTPS is enabled on the client side but disabled on the
       * server, we have to generate a fake list of features containing AUTH TLS, etc.
       * Thus, we need to change the answer code to 221. */
      if ((self->super.ssl_opts.security[EP_CLIENT] == PROXY_SSL_SEC_ACCEPT_STARTTLS)
          && (self->super.ssl_opts.security[EP_SERVER] != PROXY_SSL_SEC_FORWARD_STARTTLS))
        {
          self->answer_code = 211;
          g_string_assign(self->answer_cmd, "211");
        }
      else
        {
          /* otherwise, we simply accept the server's answer */
          z_proxy_return(self, FTP_RSP_ACCEPT);
        }
    }

  lines = g_strsplit(self->answer_param->str, "\n", 255);

  if (lines != NULL && lines[0] != NULL)
    {
      gint i = 1;
      gchar *line;

      while ((line = lines[i++]) != NULL)
        {
          if (line[0] != ' ')
            continue;

          /* skip space */
          line++;

          z_proxy_log(self, FTP_RESPONSE, 6, "Feature parsed; feature='%s'", line);
          features = g_list_append(features, line);
        }
    }

  /* do policy-driven filter/insert/remove */
  filtered = ftp_process_feature_list(self, features);
  g_list_free(features);

  /* finally, replace the old answer_param with what we have */
  g_string_assign(self->answer_param, "Features:\n");
  g_hash_table_foreach(filtered, ftp_feature_add_cb, self->answer_param);
  g_string_append(self->answer_param, "End");

  g_hash_table_destroy(filtered);
  if (lines != NULL)
    g_strfreev(lines);

  z_proxy_return(self, FTP_RSP_ACCEPT);
}

guint
ftp_command_parse_AUTH(FtpProxy *self)
{
  gboolean non_transparent = FALSE;

  z_proxy_enter(self);

  switch (self->ftp_state)
  {
  case FTP_STATE_PRECONNECT:
  case FTP_STATE_PRECONNECT_FEAT:
    non_transparent = TRUE;
    /* continue */
  case FTP_STATE_LOGIN:

    /* FIXME: only the "TLS" method is supported at the moment */
    if (g_ascii_strcasecmp(self->request_param->str, "TLS"))
      {
        z_proxy_log(self, FTP_ERROR, 3, "Unsupported authentication method; method='%s'",
                    self->request_param->str);
        SET_ANSWER(MSG_COMMAND_NOT_IMPLEMENTED);
        z_proxy_return(self, FTP_REQ_REJECT);
      }

    /* we don't allow AUTH TLS more than once */
    if (self->auth_tls_ok[EP_CLIENT])
      {
        z_proxy_log(self, FTP_VIOLATION, 3, "AUTH TLS command is allowed only in plain-text mode;");
        SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
        z_proxy_return(self, FTP_REQ_REJECT);
      }

    /* based on the client/server SSL settings, we do the following:
     *  - client ACCEPT_STARTTLS / server FORWARD_STARTTLS: we forward
     *    the request as is
     *  - client !ACCEPT_STARTTLS / server *: we reject the request
     *  - client ACCEPT_STARTTLS / server !FORWARD_STARTTLS: return success
     *    to the client and don't forward the request
     */
    if (self->super.ssl_opts.security[EP_CLIENT] == PROXY_SSL_SEC_ACCEPT_STARTTLS)
      {
        if (!non_transparent
            && (self->super.ssl_opts.security[EP_SERVER] == PROXY_SSL_SEC_FORWARD_STARTTLS))
          /* nothing to do, we do handshake only if the server agrees to do so,
           * but that is handled in the _answer_AUTH function
           */
          break;
        else
          {
            /* we're either in non-transparent mode or must not forward AUTH TLS */
            gboolean res;

            /* return success to the client right away */
            z_proxy_log(self, FTP_INFO, 3, "Zorp is configured for non-transparent operation or client-only FTPS, accepting request;");

            SET_ANSWER(MSG_AUTH_TLS_SUCCESSFUL);
            ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);

            res = z_proxy_ssl_request_handshake(&self->super, EP_CLIENT, non_transparent);

            if (!res)
              {
                z_proxy_log(self, FTP_ERROR, 2, "Client-side SSL handshake failed, terminating session;");
                self->auth_tls_ok[EP_CLIENT] = FALSE;
                self->state = FTP_QUIT;
              }
            else
              self->auth_tls_ok[EP_CLIENT] = TRUE;

            if (self->ftp_state != FTP_STATE_LOGIN)
              {
                /* non-transparent mode */
                ftp_proto_state_set(self, FTP_STATE_PRECONNECT_AUTH);
              }
            else
              {
                /* FIXME: this is normally done in ftp_process_request(), but we need to
                 * do the SSL handshake *after* returning the proxy answer to the client
                 */
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
              }

            z_proxy_return(self, FTP_NOOP);
          }
      }
    else
      {
        /* reject the request */
        SET_ANSWER(MSG_COMMAND_NOT_IMPLEMENTED);
        z_proxy_return(self, FTP_REQ_REJECT);
      }

    break;

  default:
    SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
    z_proxy_return(self, FTP_REQ_REJECT);
  }

  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_answer_AUTH(FtpProxy *self)
{
  gboolean res;

  z_proxy_enter(self);

  /* we can get here only in the following case, all others should have been handled in
   * ftp_command_parse_AUTH():
   *  - client ACCEPT_STARTTLS / server FORWARD_STARTTLS: do handshake on both
   *    sides if the server accepted the request
   */
  g_assert((self->super.ssl_opts.security[EP_CLIENT] == PROXY_SSL_SEC_ACCEPT_STARTTLS)
           && (self->super.ssl_opts.security[EP_SERVER] == PROXY_SSL_SEC_FORWARD_STARTTLS));

  switch (self->answer_code)
    {
    case 234:
      ftp_answer_write_with_setup(self, self->answer_cmd->str, self->answer_param->str);

      z_proxy_log(self, FTP_INFO, 3, "Server accepted TLS authentication, starting handshake;");

      res = z_proxy_ssl_request_handshake(&self->super, EP_SERVER, FALSE);
      if (res)
        res = z_proxy_ssl_request_handshake(&self->super, EP_CLIENT, FALSE);

      if (!res)
        {
          z_proxy_log(self, FTP_ERROR, 2, "SSL handshake failed, terminating session;");
          self->state = FTP_QUIT;
        }
      else
        {
          self->auth_tls_ok[EP_CLIENT] = self->auth_tls_ok[EP_SERVER] = TRUE;
        }

      z_proxy_return(self, FTP_NOOP);
      break;

    default:
      break;
    }

  z_proxy_return(self, FTP_RSP_ACCEPT);
}

guint
ftp_command_parse_PBSZ(FtpProxy *self)
{
  z_proxy_enter(self);

  switch (self->ftp_state)
  {
  case FTP_STATE_CONVERSATION:
  case FTP_STATE_PRECONNECT_AUTH:
    if (strcmp(self->request_param->str, "0") != 0)
      {
        z_proxy_log(self, FTP_VIOLATION, 3, "PBSZ parameter must be zero; param='%s'",
                    self->request_param->str);
        SET_ANSWER(MSG_PBSZ_PARAMETER_INVALID);
        z_proxy_return(self, FTP_REQ_REJECT);
      }

    /* must have been preceded by successful AUTH TLS */
    if (!self->auth_tls_ok[EP_CLIENT])
      {
        z_proxy_log(self, FTP_VIOLATION, 3, "PBSZ must be preceded by a successful AUTH TLS command;");
        SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
        z_proxy_return(self, FTP_REQ_REJECT);
      }

    if (self->ftp_state == FTP_STATE_PRECONNECT_AUTH)
      {
        /* non-transparent mode */
        self->client_sent_pbsz = TRUE;
        ftp_proto_state_set(self, FTP_STATE_PRECONNECT_PBSZ);
        SET_ANSWER(MSG_PBSZ_SUCCESSFUL);
        z_proxy_return(self, FTP_PROXY_ANS);
      }
    else
      {
        /*
         * based on the client/server SSL settings, we do the following:
         * - client ACCEPT_STARTTLS / server !FORWARD_STARTTLS: return success to the client
         *   and don't forward the request
         * - in all other cases we forward the request to the server
         */
        if ((self->super.ssl_opts.security[EP_CLIENT] == PROXY_SSL_SEC_ACCEPT_STARTTLS)
            && (self->super.ssl_opts.security[EP_SERVER] != PROXY_SSL_SEC_FORWARD_STARTTLS))
          {
            SET_ANSWER(MSG_PBSZ_SUCCESSFUL);
            z_proxy_return(self, FTP_PROXY_ANS);
          }
      }
    break;

  default:
    SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
    z_proxy_return(self, FTP_RSP_REJECT);
  }

  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_parse_PROT(FtpProxy *self)
{
  gboolean prot_level_private = FALSE;

  z_proxy_enter(self);

  switch (self->ftp_state)
  {
  case FTP_STATE_CONVERSATION:
  case FTP_STATE_PRECONNECT_PBSZ:
    if (g_ascii_strcasecmp(self->request_param->str, "P")
        && g_ascii_strcasecmp(self->request_param->str, "C"))
      {
        z_proxy_log(self, FTP_VIOLATION, 3, "PROT parameter must be either 'P' or 'C'; param='%s'",
                    self->request_param->str);
        SET_ANSWER(MSG_PROT_PARAMETER_INVALID);
        z_proxy_return(self, FTP_REQ_REJECT);
      }

    /* must have been preceded by successful AUTH TLS */
    if (!self->auth_tls_ok[EP_CLIENT])
      {
        z_proxy_log(self, FTP_VIOLATION, 3, "PROT must be preceded by a successful AUTH TLS command;");
        SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
        z_proxy_return(self, FTP_REQ_REJECT);
      }

    if (g_ascii_strcasecmp(self->request_param->str, "P") == 0)
      prot_level_private = TRUE;

    if (self->ftp_state == FTP_STATE_PRECONNECT_PBSZ)
      {
        self->data_protection_enabled[EP_CLIENT] = prot_level_private;
        ftp_proto_state_set(self, FTP_STATE_PRECONNECT_PROT);

        SET_ANSWER(MSG_PROT_SUCCESSFUL);
        z_proxy_return(self, FTP_PROXY_ANS);
      }
    else
      /*
       * based on the client/server SSL settings, we do the following:
       * - client ACCEPT_STARTTLS / server !FORWARD_STARTTLS: return success to the client
       *   and don't forward the request
       * - in all other cases we forward the request to the server
       */
      if ((self->super.ssl_opts.security[EP_CLIENT] == PROXY_SSL_SEC_ACCEPT_STARTTLS)
          && (self->super.ssl_opts.security[EP_SERVER] != PROXY_SSL_SEC_FORWARD_STARTTLS))
        {
          self->data_protection_enabled[EP_CLIENT] = prot_level_private;

          SET_ANSWER(MSG_PROT_SUCCESSFUL);
          z_proxy_return(self, FTP_PROXY_ANS);
        }
      else
        {
          /* we temporary set data_protection_enabled according to the parameter,
           * in case the server doesn't accept the request we'll clear this */
          if (self->super.ssl_opts.security[EP_CLIENT] == PROXY_SSL_SEC_ACCEPT_STARTTLS)
            self->data_protection_enabled[EP_CLIENT] = prot_level_private;

          if (self->super.ssl_opts.security[EP_SERVER] == PROXY_SSL_SEC_FORWARD_STARTTLS)
            self->data_protection_enabled[EP_SERVER] = prot_level_private;
        }
    break;

  default:
    SET_ANSWER(MSG_COMMAND_NOT_ALLOWED_HERE);
    z_proxy_return(self, FTP_RSP_REJECT);
  }

  z_proxy_return(self, FTP_REQ_ACCEPT);
}

guint
ftp_command_answer_PROT(FtpProxy *self)
{
  z_proxy_enter(self);

  switch (self->answer_code)
    {
    case 200:
      z_proxy_log(self, FTP_INFO, 3, "Enabling SSL protection for data channels;");
      break;

    default:
      /* in all other cases we disable data channel protection */
      self->data_protection_enabled[EP_CLIENT] = self->data_protection_enabled[EP_SERVER] = FALSE;
      break;
    }

  z_proxy_return(self, FTP_RSP_ACCEPT);
}

guint
ftp_command_parse_CCC(FtpProxy *self)
{
  z_proxy_enter(self);

  z_proxy_log(self, FTP_INFO, 4, "CCC request is not implemented, rejecting;");
  SET_ANSWER(MSG_COMMAND_NOT_IMPLEMENTED);

  z_proxy_return(self, FTP_REQ_REJECT);
}
