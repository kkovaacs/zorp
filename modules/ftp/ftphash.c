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
 * $Id: ftphash.c,v 1.36 2004/07/19 16:56:01 sasa Exp $
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

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "ftp.h"
#include "ftphash.h"
#include "ftpcmd.h"

// APASV LPRT LPSV .... ???

//  FTP command hash: command, flag, c_function, a_function, need data conn.
static struct _FtpInternalCommand ftp_commands[] = {
/* rfc959 */
  {"ABOR", ftp_command_parse_ABOR,   ftp_command_answer_ABOR, 0},
  {"ACCT", ftp_command_parse_ACCT,   ftp_command_answer_ACCT, 0},
  {"ALLO", ftp_command_parse_ALLO,   NULL,                    0},
  {"APPE", ftp_command_parse_path,   ftp_command_answer_path, 2},
  {"CDUP", ftp_command_parse_noarg,  NULL,                    0},
  {"CWD",  ftp_command_parse_path,   NULL,                    0},
  {"DELE", ftp_command_parse_path,   NULL,                    0},
  {"HELP", ftp_command_parse_HELP,   NULL,                    0},
  {"LIST", ftp_command_parse_path,   ftp_command_answer_path, 1},
  {"MKD",  ftp_command_parse_path,   NULL,                    0},
  {"MODE", ftp_command_parse_MODE,   NULL,                    0},
  {"NLST", ftp_command_parse_path,   ftp_command_answer_path, 1},
  {"NOOP", ftp_command_parse_noarg,  NULL,                    0},
  {"PASS", ftp_command_parse_PASS,   ftp_command_answer_PASS, 0},
  {"PASV", ftp_command_parse_PASV,   ftp_command_answer_PASV, 0},
  {"PBSZ", ftp_command_parse_PBSZ,   NULL,                    0},
  {"PORT", ftp_command_parse_PORT,   ftp_command_answer_PORT, 0},
  {"PROT", ftp_command_parse_PROT,   ftp_command_answer_PROT, 0},
  {"PWD",  ftp_command_parse_noarg,  NULL,                    0},
  {"REST", ftp_command_parse_REST,   NULL,                    0},
  {"RETR", ftp_command_parse_path,   ftp_command_answer_path, 1},
  {"RMD",  ftp_command_parse_path,   NULL,                    0},
  {"RNFR", ftp_command_parse_path,   ftp_command_answer_RNFR, 0},
  {"RNTO", ftp_command_parse_RNTO,   NULL,                    0},
  {"QUIT", ftp_command_parse_QUIT,   ftp_command_answer_QUIT, 0},
  {"REIN", ftp_command_parse_REIN,   NULL,                    0},
  {"SITE", ftp_command_parse_string, NULL,                    0},
  {"SMNT", ftp_command_parse_path,   NULL,                    0},
  {"STAT", ftp_command_parse_path,   NULL,                    0},
  {"STOR", ftp_command_parse_path,   ftp_command_answer_path, 2},
  {"STOU", ftp_command_parse_path,   ftp_command_answer_path, 2},
  {"STRU", ftp_command_parse_STRU,   NULL,                    0},
  {"SYST", ftp_command_parse_noarg,  NULL,                    0},
  {"TYPE", ftp_command_parse_TYPE,   NULL,                    0},
  {"USER", ftp_command_parse_USER,   ftp_command_answer_USER, 0},
  
/* rfc775 */
  {"XCUP", ftp_command_parse_noarg,  NULL,                    0},
  {"XCWD", ftp_command_parse_path,   NULL,                    0},
  {"XMKD", ftp_command_parse_path,   NULL,                    0},
  {"XPWD", ftp_command_parse_noarg,  NULL,                    0},
  {"XRMD", ftp_command_parse_path,   NULL,                    0},

  /* rfc2389 */
  {"FEAT", ftp_command_parse_FEAT,   ftp_command_answer_FEAT, 0},
  {"AUTH", ftp_command_parse_AUTH,   ftp_command_answer_AUTH, 0},
  {"CCC",  ftp_command_parse_CCC,    NULL,                    0},

/* rfc2428 */
  {"EPRT", ftp_command_parse_EPRT,   ftp_command_answer_EPRT, 0},
  {"EPSV", ftp_command_parse_EPSV,   ftp_command_answer_EPSV, 0},

  /* rfc3659 */
  {"MLSD", ftp_command_parse_path,   ftp_command_answer_path, 1},
  {"MLST", ftp_command_parse_path,   NULL,                    0},

#if 0

  /* rfc2228 */
  {"ADAT", ftp_command_parse_sftp,   NULL,                    0},
  {"AUTH", ftp_command_parse_sftp,   NULL,                    0},
  {"CONF", ftp_command_parse_sftp,   NULL,                    0},
  {"ENC",  ftp_command_parse_sftp,   NULL,                    0},
  {"MIC",  ftp_command_parse_sftp,   NULL,                    0},
  {"PBSZ", ftp_command_parse_sftp,   NULL,                    0},
  {"PROT", ftp_command_parse_sftp,   NULL,                    0},
  
  /* rfc2389 */
  {"OPTS", ftp_command_parse_noarg,  NULL,                    0},
  
  /* rfc1579 */
  {"APSV", ftp_command_parse_PASV,   NULL,                    0},
  
  /* rfc1545 */
  {"LPRT", ftp_command_parse_string, NULL,                    0},
  {"LPSV", ftp_command_parse_string, NULL,                    0},
  
  /* ???? */
  {"MDTM", ftp_command_parse_string, NULL,                    0},
#endif
  {NULL,   NULL,                     NULL,                    0}
};
  
// Function:    ftp_command_hash_create
// In:          FtpProxy*               proxy pointer
// Out:         -                       
// Desc:        create and fill the hashtable
void
ftp_command_hash_create(void)
{
  int i;

  ftp_command_hash = g_hash_table_new(g_str_hash, g_str_equal);
  i = 0;

  while (ftp_commands[i].name != NULL)
    {
      g_hash_table_insert(ftp_command_hash, ftp_commands[i].name,
                          &ftp_commands[i]);
      i++;
    }
}

// Function:    ftp_command_hash_get
// In:          gchar                   command
// Out:         gpointer                value                       
// Desc:        look up the command in the ftp_command_hash
//              return: a pointer to the structure
FtpInternalCommand *
ftp_command_hash_get(gchar * name)
{
  FtpInternalCommand *wp = g_hash_table_lookup(ftp_command_hash, name);
  return wp;
}
