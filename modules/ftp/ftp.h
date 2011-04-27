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
 * $Id: ftp.h,v 1.75 2004/07/22 09:04:39 bazsi Exp $
 *
 ***************************************************************************/

#ifndef ZORP_MODULES_FTP_H_INCLUDED
#define ZORP_MODULES_FTP_H_INCLUDED

#include <zorp/proxy.h>
#include <zorp/proxystack.h>
#include <zorp/streamline.h>
#include <zorp/sockaddr.h>
#include <zorp/poll.h>
#include <zorp/dimhash.h>
#include <zorp/attach.h>
#include <zorp/dispatch.h>
#include <zorp/connect.h>
#include <zorp/misc.h>
#include <zorp/log.h>
#include <zorp/proxy/transfer2.h>
#include <zorp/authprovider.h>

#include "ftphash.h"
#include "ftpolicy.h"
#include "ftpmsg.h"

#define FTP_LINE_MAX_LEN  2048

#define FTP_DEBUG     "ftp.debug"
#define FTP_ERROR     "ftp.error"
#define FTP_REQUEST   "ftp.request"
#define FTP_RESPONSE  "ftp.response"
#define FTP_POLICY    "ftp.policy"
#define FTP_VIOLATION "ftp.violation"
#define FTP_SESSION   "ftp.session"
#define FTP_INFO      "ftp.info"

/* telnet processor states */
#define FTP_TELNET            (0)
#define FTP_TELNET_IAC        (1)
#define FTP_TELNET_IAC_DW     (2)
#define FTP_TELNET_IAC_FUNC   (3)

/* parser function return values */
#define FTP_REQ_ACCEPT  1   /* Allow command                               */
#define FTP_REQ_REJECT  3   /* Does'n allow, connection will remain        */
#define FTP_REQ_ABORT   4   /* Doesn't allow, connection will dropped      */
#define FTP_REQ_POLICY  6   /* Put the command up to policy                */

#define FTP_NOOP      101   /* Do nothing, but not alert.                  */
#define FTP_PROXY_ANS 102   /* In non-transparent mode, proxy is answering */

#define FTP_RSP_ACCEPT 1   /* Allow answer                                */
#define FTP_RSP_REJECT 3   /* Does'n allow, connection will remain        */
#define FTP_RSP_ABORT  4   /* Doesn't allow, connection will dropped      */
#define FTP_RSP_POLICY 6   /* Put the answer up to policy                 */

#define FTP_STK_NONE           1
#define FTP_STK_DATA           2

enum ftp_feature_enum {
  FTP_FEATURE_ACCEPT = 1,
  FTP_FEATURE_DROP   = 2,
  FTP_FEATURE_INSERT = 3,
};

//
// FTP statemachine states
//

enum ftp_state_enum {
  FTP_STATE_CONNECT = 0,
  FTP_STATE_LOGIN,
  FTP_STATE_LOGIN_U,
  FTP_STATE_LOGIN_P,
  FTP_STATE_LOGIN_A,
  FTP_STATE_PRECONNECT,
  FTP_STATE_PRECONNECT_FEAT,
  FTP_STATE_PRECONNECT_AUTH,
  FTP_STATE_PRECONNECT_PBSZ,
  FTP_STATE_PRECONNECT_PROT,
  FTP_STATE_PRECONNECT_LOGIN_U,
  FTP_STATE_PRECONNECT_LOGIN_P,
  FTP_STATE_PRECONNECT_QUIT,
  FTP_STATE_LOGINAUTH,
  FTP_STATE_CONVERSATION,
  FTP_STATE_RENAME,
  FTP_STATE_DATA,
  FTP_STATE_QUIT,
  FTP_STATE_MAX
};

static gchar *ftp_state_names[] = {
  "CONNECT",
  "LOGIN",
  "LOGIN_U",
  "LOGIN_P",
  "LOGIN_A",
  "PRECONNECT",
  "PRECONNECT_FEAT",
  "PRECONNECT_AUTH",
  "PRECONNECT_PBSZ",
  "PRECONNECT_PROT",
  "PRECONNECT_LOGIN_U",
  "PRECONNECT_LOGIN_P",
  "PRECONNECT_QUIT",
  "LOGINAUTH",
  "CONVERSATION",
  "RENAME",
  "DATA",
  "QUIT",
};

#define FTP_INIT_TRANSPARENT        0
#define FTP_INIT_NONTRANSPARENT     1
#define FTP_SERVER_TO_CLIENT        2
#define FTP_CLIENT_TO_SERVER        3
#define FTP_BOTH_SIDE               4
#define FTP_NT_CLIENT_TO_PROXY      5
#define FTP_NT_SERVER_TO_PROXY      6
#define FTP_QUIT                    7

#define FTP_DATA_COMMAND_START      (0x001)
#define FTP_DATA_SERVER_START       (0x002)
#define FTP_DATA_SERVER_READY       (0x004)
#define FTP_DATA_SERVER_SAID        (0x008)
#define FTP_DATA_CLIENT_START       (0x010)
#define FTP_DATA_CLIENT_READY       (0x020)
#define FTP_DATA_CONVERSATION       (0x040)
#define FTP_DATA_CANCEL             (0x080)
#define FTP_DATA_DESTROY            (0x100)

#define FTP_SERVER_FIRST_READY      (FTP_DATA_COMMAND_START | FTP_DATA_SERVER_START | FTP_DATA_SERVER_READY | FTP_DATA_SERVER_SAID)
#define FTP_SERVER_CONNECT_READY    (FTP_SERVER_FIRST_READY | FTP_DATA_CLIENT_START | FTP_DATA_CLIENT_READY)

#define FTP_DATA_KEEP               0  /* keep connection mode    */
#define FTP_DATA_PASSIVE            1  /* convert to passive mode */
#define FTP_DATA_ACTIVE             2  /* convert to active mode  */

#define FTP_ACTIVE_MINUSONE         0  /* In active mode connect from command chanel minus one */
#define FTP_ACTIVE_TWENTY           1  /* In active mode connect from port 20 */
#define FTP_ACTIVE_RANDOM           3  /* In active mode connect from random port */

/*
   Command groups
 */

typedef struct _FtpProxy
{
  ZProxy super;
  
  int state;		/* I/O state in the proxy */
  int oldstate;         /* Where to go out from both side listening */
  enum ftp_state_enum ftp_state; /* our state in the FTP protocol */
  unsigned long data_state;	/* data connection state */
  ZPoll *poll;

  /* local permitted command & answer tables */
  GHashTable *policy_command_hash;
  ZDimHashTable *policy_answer_hash;
  
  /* feature policy hash */
  GHashTable *policy_features;

  /* command and answer buffer */
  gchar *line;          /* unparsed command */
  gsize line_length;    /* length of line */
  guint max_line_length;

  /* command part */
  GString *request_cmd;
  GString *request_param;
  FtpInternalCommand *command_desc;

  /* answer parts */
  guint answer_code;
  guint answer_handle;
  GString *answer_cmd;
  GString *answer_param;
  gboolean answer_cont;
  
  /* protocol state variables */
  GString *username;
  guint max_username_length;
  GString *password;
  guint max_password_length;

  GString *hostname;      /* the name of the host to connect to in non-transparent mode */
  guint hostport;
  guint max_hostname_length;

  GString *proxy_username;      /**< username provided inband for authentication */
  GString *proxy_password;      /**< password provided inband for authentication */
  guint proxy_auth_needed;      /**< set (1) by parseInbandAuth; cleared (0) by C code after acting on it */

  ZAuthProvider *auth;          /**< inband authentication provider */
  gboolean auth_done;           /**< set to TRUE to indicate that the user has authenticated (inband) already */

  GString *masq_address[EP_MAX];

  guint active_connection_mode;
  
  ZSockAddr *data_local_buf[EP_MAX];

  ZSockAddr *data_remote[EP_MAX];
  ZSockAddr *data_local[EP_MAX];

  guint server_port;
  
  ZDispatchEntry *data_listen[EP_MAX];
  ZAttach *data_connect[EP_MAX];
  
  ZStream *data_stream[EP_MAX];
  
  ZStackedProxy *stacked_proxy;
  
  guint data_port_min;
  guint data_port_max;

  gboolean auth_tls_ok[EP_MAX];
  gboolean data_protection_enabled[EP_MAX];
  gboolean client_sent_pbsz;

  /* config variables accessible from Python */
  gboolean transparent_mode;
  gint data_mode;
  gboolean permit_empty_command;
  gboolean permit_unknown_command;

  gboolean response_strip_msg;
  
  GString *valid_chars_username;
  ZCharSet username_charset;

  /* Timeout in both client and server side */
  guint timeout;

  GString *target_port_range;

  guint max_continuous_line;
  
  /* Data connection protect */
  GMutex *lock;

  gboolean ftp_data_hangup;

  ZTransfer2 *transfer;

  gsize buffer_size;

  gboolean drop_answer;
  
  gchar *preamble;

} FtpProxy;  

extern ZClass FtpProxy__class;

#define MSG_USERNAME_FORMAT_INVALID     0
#define MSG_HOSTNAME_TOO_LONG           1
#define MSG_USER_ALREADY_LOGGED_IN      2
#define MSG_CONNECTION_ABORTED          3
#define MSG_NON_TRANSPARENT_GREETING    4
#define MSG_LINE_TOO_LONG               5
#define MSG_LINE_TERM_CRLF              6
#define MSG_USERNAME_TOO_LONG           7
#define MSG_USER_FIRST                  8
#define MSG_PASSWORD_TOO_LONG           9
#define MSG_USER_OKAY                  10
#define MSG_COMMAND_NOT_ALLOWED_HERE   11
#define MSG_INVALID_PARAMETER          12
#define MSG_GOODBYE                    13
#define MSG_MISSING_PARAMETER          14
#define MSG_COMMAND_NOT_IMPLEMENTED_P  15
#define MSG_COMMAND_NOT_RECOGNIZED     16
#define MSG_ANSWER_ERROR               17
#define MSG_ERROR_PARSING_PORT         18
#define MSG_ERROR_PARAMETER_PASV       19
#define MSG_ERROR_PARSING_PASV         20
#define MSG_ERROR_PARAMETER_PORT       21
#define MSG_PORT_SUCCESFULL            22
#define MSG_RNFR_RNTO                  23
#define MSG_ERROR_PARSING_COMMAND      24
#define MSG_TIMED_OUT                  25
#define MSG_ERROR_PARAMETER_EPSV       26
#define MSG_ERROR_PARAMETER_EPRT       27
#define MSG_DATA_TRANSFER_FAILED       28
#define MSG_NON_TRANSPARENT_GREETING_WITH_INBAND_AUTH   29
#define MSG_PASSWORD_FORMAT_INVALID    30
#define MSG_AUTH_TLS_SUCCESSFUL        31
#define MSG_PBSZ_SUCCESSFUL            32
#define MSG_PBSZ_PARAMETER_INVALID     33
#define MSG_PROT_PARAMETER_INVALID     34
#define MSG_PROT_SUCCESSFUL            35
#define MSG_COMMAND_NOT_IMPLEMENTED    36
#define MSG_NT_SERVER_HANDSHAKE_FAILED 37
#define MSG_NT_SERVER_CERT_INVALID_SUBJECT 38
#define MSG_NT_SERVER_AUTH_REJECT      39
#define MSG_NT_SERVER_PBSZ_REJECT      40
#define MSG_NT_SERVER_PROT_REJECT      41
#define MSG_USER_INBAND_INFO_INVALID   42

extern Ftp_message ftp_know_messages[];

gboolean ftp_data_prepare(FtpProxy *self, gint side, gchar mode);
void ftp_data_start(FtpProxy *self);
void ftp_data_reset(FtpProxy *self);

void ftp_state_both(FtpProxy *self);

gboolean ftp_data_transfer(FtpProxy *self, ZStream *from_stream, ZStream *to_stream);

gchar *ftp_answer_setup(FtpProxy *self, gchar *answer_c, gchar *answer_p);
gboolean ftp_answer_write(FtpProxy *self, gchar *msg);
gboolean ftp_answer_write_with_setup(FtpProxy *self, gchar *answer_c, gchar *answer_p);

void ftp_state_set(FtpProxy *self, guint order);

static inline gchar *
ftp_proto_state_name(const enum ftp_state_enum state)
{
  return ftp_state_names[state];
}

static inline void
ftp_proto_state_set(FtpProxy *self, const enum ftp_state_enum new_state)
{
  g_assert(new_state < FTP_STATE_MAX);

  if (self->ftp_state != new_state)
    {
      z_proxy_log(self, FTP_DEBUG, 6, "Transitioning protocol state machine; old_state='%s', new_state='%s'",
                  ftp_proto_state_name(self->ftp_state), ftp_proto_state_name(new_state));
      self->ftp_state = new_state;
    }
}

#define SET_ANSWER(answer) {\
	g_string_assign(self->answer_cmd, ftp_know_messages[answer].code);\
	g_string_assign(self->answer_param, ftp_know_messages[answer].long_desc); }

#endif
