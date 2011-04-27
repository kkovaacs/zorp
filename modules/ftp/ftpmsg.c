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
 * $Id: ftpmsg.c,v 1.7 2004/02/03 13:41:55 sasa Exp $
 *
 * Author:  Andras Kis-Szabo <kisza@sch.bme.hu>
 * Author:  Attila SZALAY <sasa@balabit.hu>
 * Auditor:
 * Last audited version:
 * Notes:
 *
 ***************************************************************************/

#include "ftp.h"

// Hard-coded answers
Ftp_message ftp_know_messages[] =
{
  {"501", "Username format invalid."},
  {"501", "Hostname too long."},
  {"530", "Already logged in."},
  {"421", "Service not available, remote server has closed connection."},
  {"220", "Welcome in Zorp FTP proxy authentication module!\nPlease authenticate yourself!\nAuthentication form:\n  USER <user>@<remote site>\n  PASS <password>\n"},
  {"500", "Command line too long."},
  {"500", "Line must be terminated with a CR LF pair."},
  {"501", "Username too long."},
  {"503", "Login with USER first."},
  {"501", "Password too long."},
  {"331", "Username and host okay, send your password."},
  {"500", "Command is not allowed at this time"},
  {"500", "Invalid parameters"},
  {"221", "Goodbye"},
  {"500", "Missing parameters"},
  {"504", "Command not implemented for that parameter"},
  {"500", "Command not recognized"},
  {"500", "Answer error"},
  {"500", "Error processing PORT command"},
  {"500", "Error parsing PASV parameters"},
  {"500", "Error processing PASV command"},
  {"500", "Error parsing PORT parameters"},
  {"200", "PORT command succesfull"},
  {"500", "RNFR must precedence RNTO"},
  {"500", "Error parsing command"},
  {"500", "Connection timed out"},
  {"500", "Error parsing EPSV parameters"},
  {"500", "Error parsing EPRT parameters"},
  {"550", "Data transfer failed"},
  {"220", "Welcome in Zorp FTP proxy authentication module!\nPlease authenticate yourself!\nAuthentication form:\n"
          "  USER <ftp user>@<proxy user>@<remote site>[:<port>]:<ftp password>@<proxy password>\n  PASS <anything>\n"
          "or\n  USER <ftp user>@<proxy user>@<remote site>[:<port>]\n  PASS <ftp password>@<proxy password>\n"},
  {"501", "Password format is invalid."},
  {"234", "AUTH TLS successful"},
  {"200", "PBSZ successful"},
  {"501", "Buffer size invalid"},
  {"504", "Invalid protection level"},
  {"200", "Protection level set"},
  {"502", "Command not implemented"},
  {"530", "Login failed: SSL handshake failed with the server"},
  {"530", "Login failed: the subject of the server's SSL certificate does not match the hostname"},
  {"530", "Login failed: the server rejected the AUTH request"},
  {"530", "Login failed: the server rejected the PBSZ request"},
  {"530", "Login failed: the server rejected the PROT request"},
  {"501", "Inband routing information invalid"},
};
