#ifndef ZORP_PROXY_ERRORLOADER_H_INCLUDED
#define ZORP_PROXY_ERRORLOADER_H_INCLUDED

#include <zorp/zorp.h>

enum
{
  Z_EF_ESCAPE_NONE = 0x0001,
  Z_EF_ESCAPE_HTML = 0x0002,
};

typedef gchar *(*ZErrorLoaderResolveFunc)(gchar *variable, gpointer user_data);

typedef struct _ZErrorLoaderVarInfo
{
  gchar *variable;
  ZErrorLoaderResolveFunc resolve;
} ZErrorLoaderVarInfo;

gchar *
z_error_loader_format_file(gchar *filepath, gchar *additional_info, guint32 flags, ZErrorLoaderVarInfo *infos, gpointer user_data);

#endif
