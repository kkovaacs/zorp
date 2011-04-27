#ifndef ZORP_DOTTRANSFER_H_INCLUDED
#define ZORP_DOTTRANSFER_H_INCLUDED

#include <zorp/proxy/transfer2.h>

enum
{
  DOT_DW_PREAMBLE = 0,
  DOT_DW_DATA     = 1,
  DOT_DW_DATA_LF  = 2,
  DOT_DW_DATA_DOT = 3,
};

typedef struct _ZDotTransfer
{
  ZTransfer2 super;
  gboolean previous_line_split;
  GString *preamble;
  guint preamble_ofs;
  guint dst_write_state;
} ZDotTransfer;

extern ZClass ZDotTransfer__class;

ZDotTransfer *
z_dot_transfer_new(ZClass *class,
                   ZProxy *owner,
                   ZPoll *poll,
                   ZStream *client, ZStream *server,
                   gsize buffer_size,
                   glong timeout,
                   gulong flags,
                   GString *preamble);

#endif
