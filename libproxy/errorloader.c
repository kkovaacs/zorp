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
 * 
 * Author: SZALAY Attila <sasa@balabit.hu>
 * Auditor: 
 * Last audited version: 
 * Notes:
 *   
 ***************************************************************************/
            

#include <zorp/proxy/errorloader.h>
#include <zorp/log.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void
z_error_append_escaped(GString *content, const gchar *append, guint32 flags)
{
  const gchar *p;
  
  g_assert((flags & (Z_EF_ESCAPE_NONE + Z_EF_ESCAPE_HTML)) != 0);
  
  if (flags & Z_EF_ESCAPE_NONE)
    {
      g_string_append(content, append);
      return;
    }
    
  for (p = append; *p; p++)
    {
      if (flags & Z_EF_ESCAPE_HTML)
        {
          if (*p == '<')
            g_string_append(content, "&lt;");
          else if (*p == '>')
            g_string_append(content, "&gt;");
          else if (*p == '"')
            g_string_append(content, "&quot;");
          else if (*p == '&')
            g_string_append(content, "&amp;");
          else
            g_string_append_c(content, *p);
        }
    }
}

gchar *
z_error_loader_format_file(gchar *filepath, gchar *additional_info, guint32 flags, ZErrorLoaderVarInfo *infos, gpointer user_data)
{
  gint fd;
  GString *new_contents = NULL;
  gchar *ret = NULL;

  z_enter();
  fd = open(filepath, O_RDONLY);
  if (fd == -1)
    {
      /*LOG
        This message indicates that Zorp was unable to open the error file
        for the given reason. It is likely that the file does not exist, or
        has too restrictive permissions.
       */
      z_log(NULL, CORE_ERROR, 3, "I/O error opening error file; filename='%s', error='%s'", filepath, g_strerror(errno));
      goto exit;
    }
  else
    {
      gchar contents[4096], *src;
      gint count;

      new_contents = g_string_sized_new(4096);
      count = read(fd, contents, sizeof(contents) - 1);
      while (count > 0)
        {
          contents[count] = 0;
          src = contents;
          while (*src)   
            {
              if (*src == '@')
                {
                  if (strncmp(src, "@INFO@", 6) == 0)
                    {
                      src += 5;
                      z_error_append_escaped(new_contents, additional_info, flags);
                    }
                  else if (strncmp(src, "@VERSION@", 9) == 0)
                    {
                      src += 8;
                      z_error_append_escaped(new_contents, VERSION, flags);
                    }
                  else if (strncmp(src, "@DATE@", 6) == 0)
                    {
                      time_t t;
                      gchar timebuf[64];
                      struct tm tm;

                      src += 5;
                      t = time(NULL);
                      localtime_r(&t, &tm);
                      strftime(timebuf, sizeof(timebuf), "%a %b %e %H:%M:%S %Z %Y", &tm);
                      z_error_append_escaped(new_contents, timebuf, flags);
                    }
                  else if (strncmp(src, "@HOST@", 6) == 0)
                    {
                      gchar hostname[256];

                      src += 5;
                      if (gethostname(hostname, sizeof(hostname)) == 0)
                        z_error_append_escaped(new_contents, hostname, flags);
                    }
                  else
                    {
                      gint i = 0;
                      
                      if (infos)
                        {
                          gint left = strlen(src + 1);
                          
                          for (i = 0; infos[i].variable != NULL; i++)
                            {
                              gint var_length = strlen(infos[i].variable);
                              
                              if (left > var_length && strncmp(src + 1, infos[i].variable, strlen(infos[i].variable)) == 0 &&
                                         src[var_length + 1] == '@')
                                {
                                  gchar *info;
                                  
                                  info = infos[i].resolve(infos[i].variable, user_data);
                                  if (info)
                                    {
                                      z_trace(NULL, "Replace info stub; type='%s', data='%s'", infos[i].variable, info);
                                      z_error_append_escaped(new_contents, info, flags);
                                      g_free(info);
                                    }
                                  break;
                                }
                            }
                          if (infos[i].variable != NULL)
                            src += strlen(infos[i].variable) + 1;
                        }

                      if (infos == NULL || infos[i].variable == NULL)
                        {
                          z_cp();
                          g_string_append_c(new_contents, *src);
                        }
                    }
                }
              else
                {
                  g_string_append_c(new_contents, *src);
                }
              src++;
            }
          count = read(fd, contents, sizeof(contents) - 1);
        }
      close(fd);
      
      if (count < 0)
        {
          g_string_free(new_contents, TRUE);
          new_contents = NULL;
        }
    }
  
 exit:
  if (new_contents)
    ret = g_string_free(new_contents, FALSE);
  z_return(ret);
}
