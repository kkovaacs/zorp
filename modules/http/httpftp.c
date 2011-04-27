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
 * $Id: http.c,v 1.175 2004/07/26 11:45:57 bazsi Exp $
 * 
 * Author: Balazs Scheidler <bazsi@balabit.hu>
 * Auditor: 
 * Last audited version: 
 * Notes:
 *   
 ***************************************************************************/
 
#include "http.h"

#include <zorp/log.h>
#include <zorp/attach.h>

  
/* NOTE: cross site scripting
 *
 * we may not add anything unescaped to the HTML output as otherwise cross
 * site scripting would become possible.  This includes the HTML page and
 * HTTP headers.
 */


enum 
{ 
  HTTP_FTP_FETCH_DIR = 0,
  HTTP_FTP_FETCH_FILE = 1
};

/**
 * http_ftp_fetch_response:
 * @self: HttpProxy instance
 * @status: returned FTP status code
 * @msg: returned FTP message
 * @msglen: size of the @msg buffer
 *
 * This function is called to fetch a response from the FTP server. Line
 * continuations are supported however only the first line will be returned
 * in @msg.
 **/
static gboolean
http_ftp_fetch_response(HttpProxy *self, gint *status, gchar *msg, gsize msglen)
{
  gchar *line;
  gsize length;
  gboolean continuation = TRUE, first = TRUE;
  gint mul, value, i;
  
  msg[0] = 0;
  while (continuation)
    {
      if (z_stream_line_get(self->super.endpoints[EP_SERVER], &line, &length, NULL) != G_IO_STATUS_NORMAL)
        return FALSE;
      if (length < 4)
        {
          /*LOG
            This message indicates that the response given by the FTP server
            was too short, not even the mandatory status code was included.
           */
          z_proxy_log(self, HTTP_VIOLATION, 2, "Invalid FTP response, line too short; line='%.*s'", (gint)length, line);
          return FALSE;
        }
      value = 0;
      mul = 100;
      for (i = 0; i < 3; i++)
        {
          if (!isdigit(line[i]))
            {
              /*LOG
                This message indicates that the FTP server gave an invalid
                response, the status code returned by the server was not
                numeric.
               */
              z_proxy_log(self, HTTP_VIOLATION, 2, "Invalid FTP response, response code not numeric; line='%.*s'", (gint)length, line);
              return FALSE;
            }
          value = value + mul * (line[i] - '0');
          mul = mul / 10;
        }
      if (first)
        {
          gint copy = MIN(msglen-1, length - 4 + 1);
          
          *status = value;
          memcpy(msg, &line[4], copy);
          msg[copy] = 0;
        }
      else if (*status != value)
        {
          /*LOG
            This message indicates that the FTP server gave an invalid response as the
            status code changed from the one which was present on the first line.
           */
          z_proxy_log(self, HTTP_VIOLATION, 2, "Invalid FTP response, continuation line contains different status code; ftp_status='%d', line='%.*s'", *status, (gint)length, line);
          return FALSE;
        }
      continuation = line[3] == '-';
      
    }
  return TRUE;
}

/**
 * http_ftp_send_command:
 * @self: HttpProxy instance
 * @cmd: FTP command to send
 * @param: parameter to @cmd
 *
 * Send a command to the FTP server.
 **/
static gboolean
http_ftp_send_command(HttpProxy *self, const gchar *cmd, const gchar *param)
{
  gchar request_msg[1024];
  gsize bw;
  
  if (param)
    g_snprintf(request_msg, sizeof(request_msg), "%s %s\r\n", cmd, param);
  else
    g_snprintf(request_msg, sizeof(request_msg), "%s\r\n", cmd);
  if (z_stream_write(self->super.endpoints[EP_SERVER], request_msg, strlen(request_msg), &bw, NULL) != G_IO_STATUS_NORMAL)
    return FALSE;
  return TRUE;
}

/**
 * http_ftp_communicate:
 * @self: HttpProxy instance
 * @cmd: FTP command to send
 * @param: parameter to @cmd
 * @status: FTP status is returned here
 * @response_msg: FTP response is returned here
 * @response_msglen: size of @response_msg
 *
 * Send a command and wait for a response from the FTP server.
 **/
static gboolean
http_ftp_communicate(HttpProxy *self, const gchar *cmd, const gchar *param, gint *status, gchar *response_msg, gsize response_msglen)
{
  if (!http_ftp_send_command(self, cmd, param))
    return FALSE;
  if (!http_ftp_fetch_response(self, status, response_msg, response_msglen))
    return FALSE;
  return TRUE;
}

/**
 * http_ftp_login:
 * @self: HttpProxy instance
 * @user: username to log in with
 * @passwd: password for @user
 *
 * Log in to the FTP server using credentials in @user and @passwd.
 **/
static gboolean
http_ftp_login(HttpProxy *self, const gchar *user, const gchar *passwd)
{
  gchar response_msg[1024];
  gint status;
  
  if (!http_ftp_communicate(self, "USER", user, &status, response_msg, sizeof(response_msg)))
    return FALSE;
  if (status == 230)
    {
      /* no password required */
      return TRUE;
    }
  else if (status != 331)
    {
      /* no password required */
      g_string_sprintf(self->error_info, "Unhandled status code returned to login request (%d, %s)", status, response_msg);
      /*LOG
        This message indicates that the FTP server returned an unknown
        status code in response to our login request.
       */
      z_proxy_log(self, HTTP_ERROR, 4, "FTP server returned an unhandled status code for the login request; ftp_status='%d'", status);
      return FALSE;
    }
  if (!http_ftp_communicate(self, "PASS", passwd, &status, response_msg, sizeof(response_msg)))
    return FALSE;
  if (status == 230)
    {
      /* logged in */
      return TRUE;
    }
  else
    {
      g_string_sprintf(self->error_info, "Error logging in (%d, %s)", status, response_msg);
      /*LOG
        This message indicates that the FTP refused our authentication
        attempt.
       */
      z_proxy_log(self, HTTP_ERROR, 4, "Error logging in; user='%s', ftp_status='%d', ftp_response='%s'", user, status, response_msg);
      return FALSE;
    }
}

/**
 * http_ftp_setcwd:
 * @self: HttpProxy instance
 * @cwd: directory to change into
 *
 * Set the current working directory on the FTP server to @cwd.
 **/
static gboolean
http_ftp_setcwd(HttpProxy *self, const gchar *cwd)
{
  gchar response_msg[1024];
  gint status;
  
  if (!http_ftp_communicate(self, "CWD", cwd, &status, response_msg, sizeof(response_msg)))
    return FALSE;

  if (status != 250)
    {
      return FALSE;
    }
  return TRUE;
}

/**
 * http_ftp_set_type:
 * @self: HttpProxy instance
 * @type: transfer type
 *
 * Set the transfer type to ascii (A) or binary (I).
 **/
static gboolean
http_ftp_set_type(HttpProxy *self, const gchar *type)
{
  gchar response_msg[1024];
  gint status;
  
  if (!http_ftp_communicate(self, "TYPE", type, &status, response_msg, sizeof(response_msg)))
    return FALSE;

  if (status != 200)
    {
      return FALSE;
    }
  return TRUE;
}

/**
 * http_ftp_initiate_passive_data:
 * @self: HttpProxy instance
 *
 * This function is called to initiate a passive data connection to the FTP
 * server. If it returns FALSE an active connection might still be
 * attempted. (however it is currently unimplemented). 
 *
 * It currently creates the ZAttach object only does not start the actual
 * connection, it is done somewhat later in the http_ftp_complete_data()
 * function.
 **/
static gboolean
http_ftp_initiate_passive_data(HttpProxy *self)
{
  gchar response_msg[1024];
  gint status;
  gchar *start, *end;
  gint i;
  gint ftp_pasv_endpoint[6];
  gchar ip[16];
  ZSockAddr *peer;
  ZAttachParams params;
  
  if (!http_ftp_communicate(self, "PASV", NULL, &status, response_msg, sizeof(response_msg)))
    return FALSE;
  
  if (status != 227)
    return FALSE;
  start = strchr(response_msg, '(');
  if (!start)
    {
      /* hmm no '(' in PASV response */
      return FALSE;
    }
  start++;
  for (i = 0; i < 6; i++)
    {
      ftp_pasv_endpoint[i] = strtol(start, &end, 10);
      if ((i < 5 && *end != ',') ||
          (i == 5 && *end != ')'))
        {
          g_string_sprintf(self->error_info, "Response to PASV is invalid; response='%s'", response_msg);
          return FALSE;
        }
      start = end + 1;
    }
  g_snprintf(ip, sizeof(ip), "%d.%d.%d.%d", ftp_pasv_endpoint[0], ftp_pasv_endpoint[1], ftp_pasv_endpoint[2], ftp_pasv_endpoint[3]);
  peer = z_sockaddr_inet_new(ip, 256 * ftp_pasv_endpoint[4] + ftp_pasv_endpoint[5]);
  
  memset(&params, 0, sizeof(params));
  params.timeout = 30000;
  
  self->ftp_data_attach = z_attach_new(&self->super, ZD_PROTO_TCP, NULL, peer, &params, NULL, NULL, NULL);
  z_sockaddr_unref(peer);
  /* attach not started yet */  
  
  return TRUE;
}

/**
 * http_ftp_initiate_passive_data:
 * @self: HttpProxy instance
 *
 * This function is called to initiate an active data connection to the FTP
 * server. 
 *
 * This function is only a placeholder as active-mode data transfer is not
 * yet implemented.
 **/
static gboolean
http_ftp_initiate_active_data(HttpProxy *self G_GNUC_UNUSED)
{
  return FALSE;
}

/**
 * http_ftp_cleanup_data:
 * @self: HttpProxy instance
 *
 * This function is called to clean up the FTP data state, e.g. dispose
 * self->ftp_data_attach.
 **/
static inline void
http_ftp_cleanup_data(HttpProxy *self)
{
  z_attach_free(self->ftp_data_attach);
  self->ftp_data_attach = NULL;
}

/**
 * http_ftp_complete_data:
 * @self: HttpProxy
 * @data_stream: the resulting data stream
 *
 * This function is called to complete the data connection setup and should
 * return with the negotiated data channel in @data_stream. It currently
 * supports passive mode only.
 **/
static gboolean
http_ftp_complete_data(HttpProxy *self, ZStream **data_stream)
{
  ZConnection *conn;
  gboolean success;
  
  /* FIXME: supports PASV only */
  success = z_attach_start_block(self->ftp_data_attach, &conn);
  http_ftp_cleanup_data(self);
  
  if (!success)
    {
      *data_stream = NULL;
      return FALSE;
    }
  else
    {
      *data_stream = z_stream_ref(conn->stream);
      z_connection_destroy(conn, FALSE);
      return TRUE;
    }
}


/**
 * http_ftp_format_response: 
 * @self: HttpProxy instance
 * @stacked: whether headers towards the stacked proxy need to be formatted
 * @response: resulting HTTP response
 *
 * This function is passed as a function pointer to HttpTransfer whenever it
 * needs to format the preamble to be sent prior to the first data byte.
 **/
static gboolean
http_ftp_format_response(HttpProxy *self, gboolean stacked, GString *response)
{
  if (self->proto_version[EP_CLIENT] >= 0x0100)
    {
      http_flat_headers(&self->headers[EP_SERVER]);
      g_string_sprintf(response, "Content-Type: application/octet-stream\r\n"
                                 "%s\r\n", self->headers[EP_SERVER].flat->str);
      if (!stacked)
        {
          g_string_prepend(response, "HTTP/1.0 200 OK\r\n");
        }
    }
  else
    g_string_truncate(response, 0);
  return TRUE;
}

#define SKIP_SPACES \
  do					\
    {					\
      while (left && *src == ' ')	\
        {				\
          src++;			\
          left--;			\
        }				\
    }					\
  while (0)

#define HTTP_FTP_MAX_FILES 16384
#define HTTP_FTP_FILE_WIDTH 32

/**
 * http_ftp_htmlize_listing:
 * @self: HttpProxy instance
 * @data_stream: stream to fetch LIST output from
 * @http_response: GString to store HTML output into
 *
 * This function reads the incoming LIST output from the FTP server and
 * reformats it in HTML so that browsers can simply display it.  NOTE:
 * maximum HTTP_FTP_MAX_FILES of lines are processed as the HTTP response
 * and body is formatted in memory.
 *
 * Returns: TRUE for success, FALSE otherwise
 **/
static gboolean
http_ftp_htmlize_listing(HttpProxy *self, ZStream *data_stream, GString *http_response)
{
  ZStream *list;
  gchar *line;
  gsize length;
  gchar perm[16];
  gchar owner[32], group[32], size[16], date[13], *filename;
  gsize fill;
  gint file_count = 0, filelen, i;
  gchar spaces[HTTP_FTP_FILE_WIDTH + 3 + 1];
  
  z_stream_set_timeout(data_stream, self->timeout);
  memset(spaces, ' ', sizeof(spaces));
  spaces[HTTP_FTP_FILE_WIDTH] = 0;
  
  for (i = sizeof(spaces) - 1; i > 0; i -= 3)
    spaces[i] = '.';
  
  /* request_url is canonicalized, thus it might only contain US-ASCII
   * characters, anything else will be escaped */
  
  g_string_sprintfa(http_response, 
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n"
        "<!-- HTML listing generated by Zorp %s -->\n"
        "<HTML><HEAD><TITLE>FTP directory %s</TITLE>\n"
        "<STYLE type=\"text/css\"><!--BODY{background-color:#ffffff;font-family:verdana,sans-serif}--></STYLE>\n"
        "</HEAD><BODY>\n"
        "<H2>FTP directory <A HREF=\"%s\">%s</A></H2>\n"
        "<PRE>\n", VERSION, self->request_url->str, self->request_url->str, self->request_url->str);
        
  g_string_sprintfa(http_response, 
        "<A HREF=\"../\">Parent directory</A>\n");
  list = z_stream_line_new(data_stream, 4096, ZRL_EOL_NL | ZRL_TRUNCATE);
  while (file_count < HTTP_FTP_MAX_FILES && z_stream_line_get(list, &line, &length, NULL) == G_IO_STATUS_NORMAL)
    {
      gchar *src = line;
      gint left = length;
      
      fill = 0;
      while (left && *src && *src != ' ' && fill < sizeof(perm) - 1)
        {
          perm[fill] = *src;
          src++;
          left--;
          fill++;
        }
      perm[fill] = 0;
      
      /* link count */
      SKIP_SPACES;
      while (left && *src && *src != ' ')
        {
          src++;
          left--;
        }
      /* owner */
      SKIP_SPACES;
      fill = 0;
      while (left && *src && *src != ' ' && fill < sizeof(owner) - 1)
        {
          owner[fill] = *src;
          src++;
          left--;
          fill++;
        }
      owner[fill] = 0;

      /* group */
      SKIP_SPACES;
      fill = 0;
      while (left && *src && *src != ' ' && fill < sizeof(group) - 1)
        {
          group[fill] = *src;
          src++;
          left--;
          fill++;
        }
      group[fill] = 0;

      /* size */
      SKIP_SPACES;
      fill = 0;
      while (left && *src && *src != ' ' && fill < sizeof(size) - 1)
        {
          size[fill] = *src;
          src++;
          left--;
          fill++;
        }
      size[fill] = 0;
      
      /* date */
      SKIP_SPACES;
      fill = 0;
      while (left && *src && fill < sizeof(date) - 1)
        {
          date[fill] = *src;
          src++;
          left--;
          fill++;
        }
      date[fill] = 0;
      
      SKIP_SPACES;
      filelen = 0;
      
      filename = src;
      while (left && *src && *src != ' ' && *src != '\n' && *src != '\r')
        {
          src++;
          filelen++;
          left--;
        }
        
      if (filelen > 0)
        {
          if (perm[0] == 'd')
            {
              filename[filelen] = '/';
              filelen++;
            }
          
          /* FIXME: escape HTML output properly */
          g_string_sprintfa(http_response, 
                "<A HREF=\"%.*s\">%.*s</A>   %.*s  %s  %12s bytes\n", 
                      filelen, filename, 
                      MIN(filelen, HTTP_FTP_FILE_WIDTH), filename, 
                      MAX(HTTP_FTP_FILE_WIDTH - filelen, 0), spaces + filelen % 3,
                      date, size);
        }      
      file_count++;
    }
  if (file_count >= HTTP_FTP_MAX_FILES)
    {
      g_string_sprintfa(http_response, "Too many files, listing truncated (limit is %d)\n", HTTP_FTP_MAX_FILES);
    }
  g_string_sprintfa(http_response, "</PRE></BODY></HTML>");
  
  z_stream_unref(list);
  return TRUE;
}

#undef  SKIP_SPACES

/**
 * http_handle_ftp_request:
 * @self: HttpProxy instance
 *
 * Handle an incoming non-transparent FTP request if permit_ftp_over_http is
 * enabled. Connects to the upstream server using the FTP protocol.
 **/
gboolean 
http_handle_ftp_request(HttpProxy *self)
{
  gint status;
  gchar response_msg[1024];
  const gchar *user, *passwd, *fetch_fname = NULL;
  gchar *slash;
  gint fetch = HTTP_FTP_FETCH_DIR; 
  ZStream *data_stream;
  gboolean res = TRUE;
  
  http_clear_headers(&self->headers[EP_SERVER]);
  self->connection_hdr = http_add_header(&self->headers[EP_SERVER], "Proxy-Connection", 16, "close", 5);
  self->connection_hdr->present = TRUE;
  
  if (!http_connect_server(self))
    {
      return FALSE;
    }
  
  if (!http_ftp_fetch_response(self, &status, response_msg, sizeof(response_msg)))
    {
      return FALSE;
    }
  if (status != 220)
    {
      /*LOG
        This message indicates that the FTP server greeted Zorp with a
        non-220 response code.
       */
      z_proxy_log(self, HTTP_ERROR, 3, "Error in FTP greeting, expecting 220; ftp_status='%d'", status);
    }

  if (self->request_url_parts.user->len)
    {
      user = self->request_url_parts.user->str;
      passwd = self->request_url_parts.passwd->str;
    }
  else
    {
      user = "anonymous";
      passwd = "ftp@";
    }
  if (!http_ftp_login(self, user, passwd))
    {     
      return FALSE;
    }
  
  /* check whether request_url_parts.file ends with '/'  => directory                      */
  /* try to cd into request_url_parts.file, if successful => directory                     */
  /* try to cd into path of request_url_parts.file, if successful => file, if not => error */
  /* if file => fetch file, if directory => fetch and format dirlist */
  
  if (self->request_url_parts.file->str[self->request_url_parts.file->len - 1] == '/')
    {
      fetch = HTTP_FTP_FETCH_DIR;
      slash = &self->request_url_parts.file->str[self->request_url_parts.file->len - 1];
      
      if (slash != self->request_url_parts.file->str)
        *slash = '\0';
        
      if (!http_ftp_setcwd(self, self->request_url_parts.file->str))
        {
          *slash = '/';
          g_string_sprintf(self->error_info, "Directory not found on server. (%s)", self->request_url_parts.file->str);
          /*LOG
            This message indicates that the directory specified in the URL
            was not accepted by the FTP server.
           */
          z_proxy_log(self, HTTP_ERROR, 4, "Error changing directory on server; dir='%s'", self->request_url_parts.file->str);
          return FALSE;
        }
      *slash = '/';
    }
  else
    {
      if (http_ftp_setcwd(self, self->request_url_parts.file->str))
        {
          const gchar *reason;
          GString *url = g_string_sized_new(0);
          
          g_string_append_c(self->request_url_parts.file, '/');
          if (!http_format_url(&self->request_url_parts, url, TRUE, FALSE, TRUE, &reason))
            {
              g_string_assign(url, "Error formatting URL");
            }
          self->error_code = HTTP_MSG_REDIRECT;
          self->error_status = 301;
          g_string_assign(self->error_info, url->str);
          g_string_sprintf(self->error_msg, "Redirect");
          
          /* NOTE: url is properly escaped, as it was canonicalized by
           * http_format_url above */
          
          g_string_sprintfa(self->error_headers, "Location: %s\r\n", url->str);
          g_string_free(url, TRUE);
          return FALSE;
        }
      else
        {
          slash = strrchr(self->request_url_parts.file->str, '/');
          if (!slash)
            {
              /* no backslash (or only first backslash present), we already tried to CD into this */
              g_string_sprintf(self->error_info, "Directory not found on server. (%s)", self->request_url_parts.file->str);
              /*LOG
                This message indicates that the directory specified in the URL
                was not accepted by the FTP server.
               */
              z_proxy_log(self, HTTP_ERROR, 4, "Error changing directory on server; dir='%s'", self->request_url_parts.file->str);
              return FALSE;
            }
          if (slash != self->request_url_parts.file->str)
            {
              *slash = '\0';
              if (!http_ftp_setcwd(self, self->request_url_parts.file->str))
                {
                  g_string_sprintf(self->error_info, "Directory not found on server. (%s)", self->request_url_parts.file->str);
                  /*LOG
                    This message indicates that the directory specified in the URL
                    was not accepted by the FTP server.
                   */
                  z_proxy_log(self, HTTP_ERROR, 4, "Error changing directory on server; dir='%s'", self->request_url_parts.file->str);
                  *slash = '/';
                  return FALSE;
                }
              *slash = '/';
            }
          fetch = HTTP_FTP_FETCH_FILE;
          fetch_fname = slash + 1;
        }
    }
  if (!http_ftp_set_type(self, (fetch == HTTP_FTP_FETCH_FILE) ? "I" : "A"))
    {
      z_proxy_log(self, HTTP_ERROR, 4, "Error setting FTP transfer type;");
      g_string_assign(self->error_info, "Error setting FTP transfer type.");
      return FALSE;
    }
  /* ok, everything ok, set up data channel */
  
  if (!http_ftp_initiate_passive_data(self) &&
      !http_ftp_initiate_active_data(self))
    {
      return FALSE;
    }
  
  g_string_sprintf(self->error_info, "Error downloading file %s", self->request_url->str);
  
  /* fetch file pointed to by fetch_fname */
  if (!http_ftp_send_command(self, fetch == HTTP_FTP_FETCH_FILE ? "RETR" : "LIST", fetch == HTTP_FTP_FETCH_FILE ? fetch_fname : NULL))
    {
      /*LOG
        This message indicates that an I/O error occurred while sending our
        RETR or LIST request.
       */
      z_proxy_log(self, HTTP_ERROR, 4, "Error sending RETR or LIST command to FTP server;");
      http_ftp_cleanup_data(self);
      return FALSE;
    }
  if (!http_ftp_complete_data(self, &data_stream))
    {
      /*LOG
        This message indicates that an I/O error occurred while trying to
        establish the data connection with the FTP server.
       */
      z_proxy_log(self, HTTP_ERROR, 4, "Error establishing data connection to FTP server;");
      return FALSE;
    }
  if (!http_ftp_fetch_response(self, &status, response_msg, sizeof(response_msg)) || (status != 150 && status != 125))
    {
      /* file was successfully downloaded, finished */
      z_stream_shutdown(data_stream, SHUT_RDWR, NULL);
      z_stream_close(data_stream, NULL);
      z_stream_unref(data_stream);
      g_string_sprintf(self->error_info, "FTP error: %d %s", status, response_msg);
      /*LOG
        This message indicates that the FTP server did not react with a
        150 response after the data connection was established.
       */
      z_proxy_log(self, HTTP_ERROR, 4, "Error reading data channel confirmation from FTP server; status='%d', response='%s'", status, response_msg);
      return FALSE;
    }
  
  if (fetch == HTTP_FTP_FETCH_FILE)
    {
      if (!http_data_transfer(self, HTTP_TRANSFER_NORMAL, EP_SERVER, data_stream, EP_CLIENT, self->super.endpoints[EP_CLIENT], TRUE, FALSE, http_ftp_format_response))
        {
          /* file was not successfully downloaded, finished */
          res = FALSE;
        }
    }
  else
    {
      GString *http_response = g_string_sized_new(128);
      
      g_string_sprintf(http_response, "HTTP/1.0 200 OK\r\n"
                                      "Content-Type: text/html\r\n"
                                      "Proxy-Connection: close\r\n\r\n");
      if (!http_ftp_htmlize_listing(self, data_stream, http_response))
        {
          res = FALSE;
        }
      else
        {
          if (!http_write(self, EP_CLIENT, http_response->str, http_response->len))
            res = FALSE;
        }
      g_string_free(http_response, TRUE);
    }

  /* file was successfully downloaded, finished */
  z_stream_shutdown(data_stream, SHUT_RDWR, NULL);
  z_stream_close(data_stream, NULL);
  z_stream_unref(data_stream);

  if (res)
    {
      status = 999;
      if (!http_ftp_fetch_response(self, &status, response_msg, sizeof(response_msg)) || status != 226)
        {
          /*LOG
            This message indicates that the FTP server did not return with
            an appropriate status code at the end of the data transfer.
           */
          z_proxy_log(self, HTTP_ERROR, 4, "Error reading 226 from FTP server; status='%d', response='%s'", status, response_msg);
          /* we already sent the page, thus we may not return FALSE here */
        }
    }
  return res;
}
