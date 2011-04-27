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
 * $Id: ftpcmd.h,v 1.15 2004/02/03 13:59:37 sasa Exp $
 *
 * Author:  Andras Kis-Szabo <kisza@sch.bme.hu>
 * Author:  Attila SZALAY <sasa@balabit.hu>
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/


#ifndef __FTP_PARSE_H
#define __FTP_PARSE_H

/* declare ftp command parser functions */

guint ftp_command_parse_noarg  (FtpProxy *self);
guint ftp_command_parse_path   (FtpProxy *self);
guint ftp_command_answer_path  (FtpProxy *self);
guint ftp_command_parse_string (FtpProxy *self);
guint ftp_command_parse_ABOR   (FtpProxy *self);
guint ftp_command_answer_ABOR  (FtpProxy *self);
guint ftp_command_parse_HELP   (FtpProxy *self);
guint ftp_command_parse_MODE   (FtpProxy *self);
guint ftp_command_parse_PASS   (FtpProxy *self);
guint ftp_command_answer_PASS  (FtpProxy *self);
guint ftp_command_parse_ACCT   (FtpProxy *self);
guint ftp_command_answer_ACCT  (FtpProxy *self);
guint ftp_command_parse_PASV   (FtpProxy *self);
guint ftp_command_answer_PASV  (FtpProxy *self);
guint ftp_command_parse_PORT   (FtpProxy *self);
guint ftp_command_answer_PORT  (FtpProxy *self);
guint ftp_command_parse_EPSV   (FtpProxy *self);
guint ftp_command_answer_EPSV  (FtpProxy *self);
guint ftp_command_parse_EPRT   (FtpProxy *self);
guint ftp_command_answer_EPRT  (FtpProxy *self);
guint ftp_command_parse_QUIT   (FtpProxy *self);
guint ftp_command_answer_QUIT  (FtpProxy *self);
guint ftp_command_parse_STRU   (FtpProxy *self);
guint ftp_command_parse_TYPE   (FtpProxy *self);
guint ftp_command_parse_USER   (FtpProxy *self);
guint ftp_command_answer_USER  (FtpProxy *self);
guint ftp_command_answer_RNFR  (FtpProxy *self);
guint ftp_command_parse_RNTO   (FtpProxy *self);
guint ftp_command_parse_ALLO   (FtpProxy *self);
guint ftp_command_parse_REIN   (FtpProxy *self);
guint ftp_command_answer_REIN  (FtpProxy *self);
guint ftp_command_parse_REST   (FtpProxy *self);
guint ftp_command_parse_FEAT   (FtpProxy *self);
guint ftp_command_answer_FEAT  (FtpProxy *self);
guint ftp_command_parse_AUTH   (FtpProxy *self);
guint ftp_command_answer_AUTH  (FtpProxy *self);
guint ftp_command_parse_PBSZ   (FtpProxy *self);
guint ftp_command_parse_PROT   (FtpProxy *self);
guint ftp_command_answer_PROT  (FtpProxy *self);
guint ftp_command_parse_CCC    (FtpProxy *self);

#endif
