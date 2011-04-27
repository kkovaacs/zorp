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
 * $Id: ftphash.h,v 1.14 2004/05/18 16:34:39 sasa Exp $
 *
 ***************************************************************************/


#ifndef ZORP_MODULES_FTP_FTPHASH_H
#define ZORP_MODULES_FTP_FTPHASH_H

struct _FtpInternalCommand;
struct _FtpProxy;

typedef guint (*FtpCmdFunction)(struct _FtpProxy *self);

typedef struct _FtpInternalCommand
{
  char *name;
//  guint state;
  FtpCmdFunction parse;
  FtpCmdFunction answer;
  int need_data;
} FtpInternalCommand;

extern GHashTable *ftp_command_hash;

void ftp_command_hash_create(void);
FtpInternalCommand *ftp_command_hash_get(gchar *name);

#endif
