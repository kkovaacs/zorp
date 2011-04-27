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
 * $Id: telnet.h,v 1.16 2004/07/28 14:36:07 sasa Exp $
 *
 * Author: Hidden
 * Auditor:
 * Last audited version:
 * Notes:
 ***************************************************************************/

#ifndef ZORP_MODULES_TELNET_H_INCLUDED
#define ZORP_MODULES_TELNET_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/proxy.h>
#include <zorp/poll.h>
#include <zorp/dimhash.h>

/* Telnet command codes */

/* RFC 854 */
#define TELNET_IAC          255
#define TELNET_CMD_SE       240
#define TELNET_CMD_NOP      241
#define TELNET_CMD_DATAMARK 242
#define TELNET_CMD_BRK      243
#define TELNET_CMD_IP       244
#define TELNET_CMD_AO       245
#define TELNET_CMD_AYT      246
#define TELNET_CMD_EC       247
#define TELNET_CMD_EL       248
#define TELNET_CMD_GA       249
#define TELNET_CMD_SB       250
#define TELNET_CMD_WILL     251
#define TELNET_CMD_WONT     252
#define TELNET_CMD_DO       253
#define TELNET_CMD_DONT     254
#define TELNET_CMD_IAC      255

/* Telnet option codes */

/* RFC 856 - TELNET binary transmission */
#define TELNET_OPTION_BINARY                0

/* RFC 857 - TELNET echo */
#define TELNET_OPTION_ECHO                  1

/* RFC 858 - TELNET suppress go ahead */
#define TELNET_OPTION_SUPPRESS_GO_AHEAD     3

/* RFC 859 - TELNET status */
#define TELNET_OPTION_STATUS                5
#define TELNET_SB_STATUS_SB_IS                  0
#define TELNET_SB_STATUS_SB_SEND                1

/* RFC 860 - TELNET timing mark */
#define TELNET_OPTION_TIMING_MARK           6

/* RFC 726 - TELNET remote controlling transmission and echoing */
#define TELNET_OPTION_RCTE                  7
  /* suboptions:
   * IAC SB RCTE <cmd> [BC1 BC2] [TC1 TC2] IAC SE
   *   contains [BC1 BC2] if (cmd & 8)
   *   contains [TC1 TC2] if (cmd & 16)
   */

/* RFC 652 - TELNET negotiate about output CR disposition */
#define TELNET_OPTION_NAOCRD                10
#define TELNET_SB_NAOCRD_DR                     0
#define TELNET_SB_NAOCRD_DS                     1

/* RFC 653 - TELNET negotiate about output horizontal tabstops (HT) */
#define TELNET_OPTION_NAOHTS                11
#define TELNET_SB_NAOHTS_DR                     0
#define TELNET_SB_NAOHTS_DS                     1

/* RFC 654 - TELNET negotiate about output HT disposition */
#define TELNET_OPTION_NAOHTD                12
#define TELNET_SB_NAOHTD_DR                     0
#define TELNET_SB_NAOHTD_DS                     1

/* RFC 655 - TELNET negotiate about output FF disposition */
#define TELNET_OPTION_NAOFFD                13
#define TELNET_SB_NAOFFD_DR                     0
#define TELNET_SB_NAOFFD_DS                     1

/* RFC 656 - TELNET negotiate about vertical tabstops (VT) */
#define TELNET_OPTION_NAOVTS                14
#define TELNET_SB_NAOVTS_DR                     0
#define TELNET_SB_NAOVTS_DS                     1

/* RFC 657 - TELNET negotiate about VT disposition */
#define TELNET_OPTION_NAOVTD                15
#define TELNET_SB_NAOVTD_DR                     0
#define TELNET_SB_NAOVTD_DS                     1

/* RFC 658 - TELNET negotiate about LF disposition */
#define TELNET_OPTION_NAOLFD                16
#define TELNET_SB_NAOLFD_DR                     0
#define TELNET_SB_NAOLFD_DS                     1

/* RFC 698 - TELNET extended ASCII */
#define TELNET_OPTION_EXTEND_ASCII          17
  /* suboptions:
   * IAC SB EXTASC high_byte low_byte IAC SE
   */

/* RFC 727 - TELNET logout */
#define TELNET_OPTION_LOGOUT                18

/* RFC 735 - TELNET byte macro */
#define TELNET_OPTION_BM                    19
#define TELNET_SB_BM_DEFINE                     1
#define TELNET_SB_BM_ACCEPT                     2
#define TELNET_SB_BM_REFUSE                     3
#define TELNET_SB_BM_LITERAL                    4
#define TELNET_SB_BM_CANCEL                     5
  /* suboptions:
   * IAC SB BM <DEFINE> <macro byte> <count> <replacement string> IAC SE
   *   <DEFINE> is 1
   *   <macro byte> may not be IAC (255)
   *   <couny> is a 8-bit number, indicating the length of <replacement string>
   * IAC SB BM <ACCEPT> <macro byte> IAC SE
   *   <ACCEPT> is 2
   * IAC SB BM <REFUSE> <macro byte> <REASON> IAC SE
   *   <REFUSE> is 3
   *   <REASON> may be:
   *     <BAD-CHOICE> is 1
   *     <TOO-LONG> is 2
   *     <WRONG-LENGTH> is 3
   *     <OTHER-REASON> is 0
   * IAC SB BM <LITERAL> <macro byte> IAC SE
   *   <LITERAL> is 4
   * IAC SB BM <PLEASE CANCEL> <macro byte> <REASON> IAC SE
   *   <PLEASE CANCEL> is ?
   */

/* RFC 1043 - TELNET data entry terminal */
#define TELNET_OPTION_DET                   20
#define TELNET_SB_DET_DEFINE                    1
#define TELNET_SB_DET_ERASE                     2
#define TELNET_SB_DET_TRANSMIT                  3
#define TELNET_SB_DET_FORMAT                    4
#define TELNET_SB_DET_MOVE_CURSOR               5
#define TELNET_SB_DET_SKIP_TO_LINE              6
#define TELNET_SB_DET_SKIP_TO_CHAR              7
#define TELNET_SB_DET_UP                        8
#define TELNET_SB_DET_DOWN                      9
#define TELNET_SB_DET_LEFT                      10
#define TELNET_SB_DET_RIGHT                     11
#define TELNET_SB_DET_HOME                      12
#define TELNET_SB_DET_LINE_INSERT               13
#define TELNET_SB_DET_LINE_DELETE               14
#define TELNET_SB_DET_CHAR_INSERT               15
#define TELNET_SB_DET_CHAR_DELETE               16
#define TELNET_SB_DET_READ_CURSOR               17
#define TELNET_SB_DET_CURSOR_POSITION           18
#define TELNET_SB_DET_REVERSE_TAB               19
#define TELNET_SB_DET_TRANSMIT_SCREEN           20
#define TELNET_SB_DET_TRANSMIT_UNPROTECTED      21
#define TELNET_SB_DET_TRANSMIT_LINE             22
#define TELNET_SB_DET_TRANSMIT_FIELD            23
#define TELNET_SB_DET_TRANSMIT_REST_SCREEN      24
#define TELNET_SB_DET_TRANSMIT_REST_LINE        25
#define TELNET_SB_DET_TRANSMIT_REST_FIELD       26
#define TELNET_SB_DET_TRANSMIT_MODIFIED         27
#define TELNET_SB_DET_DATA_TRANSMIT             28
#define TELNET_SB_DET_ERASE_SCREEN              29
#define TELNET_SB_DET_ERASE_LINE                30
#define TELNET_SB_DET_ERASE_FIELD               31
#define TELNET_SB_DET_ERASE_REST_SCREEN         32
#define TELNET_SB_DET_ERASE_REST_LINE           33
#define TELNET_SB_DET_ERASE_REST_FIELD          34
#define TELNET_SB_DET_ERASE_UNPROTECTED         35
#define TELNET_SB_DET_FORMAT_DATA               36
#define TELNET_SB_DET_REPEAT                    37
#define TELNET_SB_DET_SUPPRESS_PROTECTION       38
#define TELNET_SB_DET_FIELD_SEPARATOR           39
#define TELNET_SB_DET_FN                        40
#define TELNET_SB_DET_ERROR                     41

/* RFC 736 - TELNET SUPDUP support */
#define TELNET_OPTION_SUPDUP                21

/* RFC 749 - TELNET SUPDUP output */
#define TELNET_OPTION_SUPDUP_OUTPUT         22
/* suboptions:
 * IAC SB SUPDUP-OUTPUT 1 <terminal parameters> IAC SE
 *
 * IAC SB SUPDUP-OUTPUT 2 n TD1 TD2 .. TDn SCx SCy IAC SE
 *   n is the number of TD bytes
 */

/* RFC 779 - TELNET SEND-LOCATION */
#define TELNET_OPTION_SEND_LOCATION         23

/* RFC 1091 - TELNET terminal-type */
#define TELNET_OPTION_TERMINAL_TYPE         24
#define TELNET_SB_TERMINAL_TYPE_IS              0
#define TELNET_SB_TERMINAL_TYPE_SEND            1

/* RFC 885 - TELNET end of record */
#define TELNET_OPTION_EOR                   25

/* RFC 927 - TELNET TACACS user identification */
#define TELNET_OPTION_TUID                  26

/* RFC 933 - TELNET output marking */
#define TELNET_OPTION_OUTMRK                27

/* RFC 946 - TELNET terminal location number */
#define TELNET_OPTION_TTYLOC                28

/* RFC 1041 - TELNET 3270 regime */
#define TELNET_OPTION_3270_REGIME           29
#define TELNET_SB_3270_REGIME_IS                0
#define TELNET_SB_3270_REGIME_ARE               1

/* RFC 1053 - TELNET X.3 PAD */
#define TELNET_OPTION_X3_PAD                30
#define TELNET_SB_X3_PAD_SET                    0
#define TELNET_SB_X3_PAD_RESPONSE_SET           1
#define TELNET_SB_X3_PAD_IS                     2
#define TELNET_SB_X3_PAD_RESPONSE_IS            3
#define TELNET_SB_X3_PAD_SEND                   4

/* RFC 1073 - TELNET windows size option */
#define TELNET_OPTION_NAWS                  31

/* RFC 1079 - TELNET terminal speed */
#define TELNET_OPTION_TERMINAL_SPEED        32
#define TELNET_SB_TERMINAL_SPEED_IS             0
#define TELNET_SB_TERMINAL_SPEED_SEND           1

/* RFC 1372 - TELNET remote flow control */
#define TELNET_OPTION_TOGGLE_FLOW_CONTROL   33

/* RFC 1184 - TELNET linemode */
#define TELNET_OPTION_LINEMODE              34
#define TELNET_SB_LINEMODE_MODE                 1
#define TELNET_SB_LINEMODE_FORWARDMASK          2
#define TELNET_SB_LINEMODE_SLC                  3

/* RFC 1096 - TELNET X display location */
#define TELNET_OPTION_X_DISPLAY_LOCATION    35
#define TELNET_SB_X_DISPLAY_LOCATION_IS         0
#define TELNET_SB_X_DISPLAY_LOCATION_SEND       1

/* RFC 1408 - TELNET enviroment variable access - old */
#define TELNET_OPTION_OLD_ENVIRONMENT       36
#define TELNET_SB_OLD_ENVIRONMENT_IS            0
#define TELNET_SB_OLD_ENVIRONMENT_SEND          1
#define TELNET_SB_OLD_ENVIRONMENT_INFO          2

/* RFC 2941 - TELNET authentication */
#define TELNET_OPTION_AUTHENTICATION        37
#define TELNET_SB_AUTHENTICATION_IS             0
#define TELNET_SB_AUTHENTICATION_SEND           1
#define TELNET_SB_AUTHENTICATION_REPLY          2
#define TELNET_SB_AUTHENTICATION_NAME           3

/* RFC 2946 - TELNET encryption */
#define TELNET_OPTION_ENCRYPT               38
#define TELNET_SB_ENCRYPT_IS                    0
#define TELNET_SB_ENCRYPT_SUPPORT               1
#define TELNET_SB_ENCRYPT_REPLY                 2
#define TELNET_SB_ENCRYPT_START                 3
#define TELNET_SB_ENCRYPT_END                   4
#define TELNET_SB_ENCRYPT_REQUEST_START         5
#define TELNET_SB_ENCRYPT_REQUEST_END           6
#define TELNET_SB_ENCRYPT_ENC_KEYID             7
#define TELNET_SB_ENCRYPT_DEC_KEYID             8

/* RFC 1572 - TELNET environment option */
#define TELNET_OPTION_ENVIRONMENT           39
#define TELNET_SB_ENVIRONMENT_IS                0
#define TELNET_SB_ENVIRONMENT_SEND              1
#define TELNET_SB_ENVIRONMENT_INFO              2
#define TELNET_OPTARG_ENVIRONMENT_VAR               0
#define TELNET_OPTARG_ENVIRONMENT_VALUE             1
#define TELNET_OPTARG_ENVIRONMENT_ESC               2
#define TELNET_OPTARG_ENVIRONMENT_USERVAR           3


/* RFC 1647 - TELNET TN3270E terminal functions */
#define TELNET_OPTION_TN3270E               40
#define TELNET_SB_TN3270E_ASSOCIATE             0
#define TELNET_SB_TN3270E_CONNECT               1
#define TELNET_SB_TN3270E_DEVICE_TYPE           2
#define TELNET_SB_TN3270E_FUNCTIONS             3
#define TELNET_SB_TN3270E_IS                    4
#define TELNET_SB_TN3270E_REASON                5
#define TELNET_SB_TN3270E_REJECT                6
#define TELNET_SB_TN3270E_REQUEST               7
#define TELNET_SB_TN3270E_SEND                  8

/* RFC 2066 - TELNET character set support */
#define TELNET_OPTION_CHARSET               42
#define TELNET_SB_CHARSET_REQUEST               1
#define TELNET_SB_CHARSET_ACCEPTED              2
#define TELNET_SB_CHARSET_REJECTED              3
#define TELNET_SB_CHARSET_TTABLE_IS             4
#define TELNET_SB_CHARSET_TTABLE_REJECTED       5
#define TELNET_SB_CHARSET_TTABLE_ACK            6
#define TELNET_SB_CHARSET_TTABLE_NAK            7

/* RFC 2217 - TELNET serial port settings */
#define TELNET_OPTION_COM_PORT              44
#define TELNET_SB_COM_PORT_CLI_SET_BAUDRATE         1
#define TELNET_SB_COM_PORT_CLI_SET_DATASIZE         2
#define TELNET_SB_COM_PORT_CLI_SET_PARITY           3
#define TELNET_SB_COM_PORT_CLI_SET_STOPSIZE         4
#define TELNET_SB_COM_PORT_CLI_SET_CONTROL          5
#define TELNET_SB_COM_PORT_CLI_NOTIFY_LINESTATE     6
#define TELNET_SB_COM_PORT_CLI_NOTIFY_MODEMSTATE    7
#define TELNET_SB_COM_PORT_CLI_FLOWCONTROL_SUSPEND  8
#define TELNET_SB_COM_PORT_CLI_FLOWCONTROL_RESUME   9
#define TELNET_SB_COM_PORT_CLI_SET_LINESTATE_MASK   10
#define TELNET_SB_COM_PORT_CLI_SET_MODEMSTATE_MASK  11
#define TELNET_SB_COM_PORT_CLI_PURGE_DATA           12
#define TELNET_SB_COM_PORT_SVR_SET_BAUDRATE         101
#define TELNET_SB_COM_PORT_SVR_SET_DATASIZE         102
#define TELNET_SB_COM_PORT_SVR_SET_PARITY           103
#define TELNET_SB_COM_PORT_SVR_SET_STOPSIZE         104
#define TELNET_SB_COM_PORT_SVR_SET_CONTROL          105
#define TELNET_SB_COM_PORT_SVR_NOTIFY_LINESTATE     106
#define TELNET_SB_COM_PORT_SVR_NOTIFY_MODEMSTATE    107
#define TELNET_SB_COM_PORT_SVR_FLOWCONTROL_SUSPEND  108
#define TELNET_SB_COM_PORT_SVR_FLOWCONTROL_RESUME   109
#define TELNET_SB_COM_PORT_SVR_SET_LINESTATE_MASK   110
#define TELNET_SB_COM_PORT_SVR_SET_MODEMSTATE_MASK  111
#define TELNET_SB_COM_PORT_SVR_PURGE_DATA           112

/* RFC 2840 - TELNET KERMIT protocol */
#define TELNET_OPTION_KERMIT                47
#define TELNET_SB_KERMIT_START_SERVER           0
#define TELNET_SB_KERMIT_STOP_SERVER            1
#define TELNET_SB_KERMIT_REQ_START_SERVER       2
#define TELNET_SB_KERMIT_REQ_STOP_SERVER        3
#define TELNET_SB_KERMIT_SOP                    4
#define TELNET_SB_KERMIT_RESP_START_SERVER      8
#define TELNET_SB_KERMIT_RESP_STOP_SERVER       9

/* RFC 861 - TELNET extended options list */
#define TELNET_OPTION_EXOPL                 255

/* new commands */
#define TELNET_OPTION_CMD_EOF               236
#define TELNET_OPTION_CMD_SUSP              237
#define TELNET_OPTION_CMD_ABORT             238

/* proxy states */
#define TELNET_DATA             1
#define TELNET_GOT_IAC          2
#define TELNET_GOT_OPNEG        3
#define TELNET_GOT_SB           4
#define TELNET_IN_SB            5
#define TELNET_GOT_SB_IAC       6
#define TELNET_QUIT             7

/* option state codes */
#define SENT_WILL               1   /* 1/0: client sent WILL/WONT */
#define GOT_DO                  2   /* 1/0: server sent DO/DONT */

/* option negotiation requests and responses */
#define WILL_OPTION             1
#define WONT_OPTION             2
#define DO_OPTION               3
#define DONT_OPTION             4

#define TELNET_BUFFER_SIZE      1024
#define TELNET_SUBOPTION_SIZE   (TELNET_BUFFER_SIZE - 4) /* IAC SB code + 1 byte */

#define TELNET_CHECK_OK         1
#define TELNET_CHECK_REJECT     3
#define TELNET_CHECK_ABORT      4
#define TELNET_CHECK_DROP       5

/* policy constants */
#define TELNET_OPTION_ACCEPT    1
#define TELNET_OPTION_REJECT    3
#define TELNET_OPTION_ABORT     4
#define TELNET_OPTION_DROP      5
#define TELNET_OPTION_POLICY    6

/* macro to determine other endpoint */
#define OTHER_EP(x)             ((EP_MAX - 1) - x)

/* macro to convert endpoint number to string */
#define WHICH_EP(x)             (((x) == EP_CLIENT) ? "client" : "server")

#define TELNET_AUDIT_FORMAT_VERSION        "0.0"

struct _TelnetProxy;

typedef guint (*TelnetOptionFunction)(struct _TelnetProxy *, guint);

typedef struct _TelnetOptions 
{
    guint                   option;
    TelnetOptionFunction    option_check;
} TelnetOptions;

typedef struct _ZIOBuffer
{
    guchar                  buf[TELNET_BUFFER_SIZE];
    gsize                   ofs, end;
} ZIOBuffer;

typedef struct _ZIOBufferDyn
{
    guchar                  *buf;
    guint                   ofs, end, size;
} ZIOBufferDyn;

#define TELNET_REQUEST      "telnet.request"
#define TELNET_RESPONSE     "telnet.response"
#define TELNET_DEBUG        "telnet.debug"
#define TELNET_VIOLATION    "telnet.violation"

#define TELNET_ERROR        "telnet.error"
#define TELNET_POLICY       "telnet.policy"
#define TELNET_VIOLATION    "telnet.violation"

typedef struct _TelnetProxy
{
    ZProxy super;
    /* Policy level variables */
  
    /* timeout in milliseconds */
    gint                    timeout;
  
    /* policy hash */
    ZDimHashTable           *telnet_policy;
  
    /* options <-> commands link hash keyed by the command */
    GHashTable              *negotiation;

    /* variables for the policy callbacks to be able to make changes */
    GString                 *policy_name, *policy_value;

    /* Private variables */
    gint                    state[EP_MAX];
    gint                    ep;

    /* input buffers */
    ZIOBuffer               read_buffers[EP_MAX];
  
    /* output buffers */
    ZIOBufferDyn            write_buffers[EP_MAX];

    /* buffer to store suboption negotiation stream */
    ZIOBuffer               suboptions[EP_MAX];
  
    /* option negotiation state */
    gchar                   options[256][EP_MAX];

    /* WILL_OPTION, WONT_OPTION, DO_OPTION or DONT_OPTION
     * shows what was requested in TELNET_GOT_OPNEG state
     *
     * NOTE: the code assumes that these are octet sized, please be sure to
     * audit the code if the type of these values is ever changed.
     */
    guchar                  command[EP_MAX];
    guchar                  opneg_option[EP_MAX];

    /* suboption check function lookup table */
    TelnetOptionFunction    telnet_options[256];
    

    ZPoll                   *poll;
} TelnetProxy;

gboolean telnet_collect_meta(TelnetProxy *self, const gchar *name, const gchar *value, gboolean commit) G_GNUC_WARN_UNUSED_RESULT;

extern ZClass TelnetProxy__class;
#endif
