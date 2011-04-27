#ifndef ZORP_PROXY_TRANSFER2_H_INCLUDED
#define ZORP_PROXY_TRANSFER2_H_INCLUDED

#include <zorp/zorp.h>
#include <zorp/zobject.h>
#include <zorp/proxystack.h>
#include <zorp/poll.h>
#include <zorp/log.h>

typedef enum
{
  ZT2_RESULT_FINISHED = 0,    /* success */
  ZT2_RESULT_SUSPENDED = 1,   /* temporary suspend */
  ZT2_RESULT_FAILED = 2,      /* general error, continuation is possible */
  ZT2_RESULT_ABORTED = 3,     /* error, state is unknown, proxy should abort */
} ZTransfer2Result;

#define ZT2F_COMPLETE_COPY        0x0001
#define ZT2F_PROXY_STREAMS_POLLED 0x0002
#define ZT2F_SUSPEND_NOOP	  0x0004

/* transfer status constants */

#define ZT2S_FINISHED  0x0001
#define ZT2S_SUSPENDED 0x0002

#define ZT2S_FAILED    0x0004
#define ZT2S_TIMEDOUT  0x0008
#define ZT2S_ABORTED   0x0010

#define ZT2S_STARTED       0x0020
#define ZT2S_COPYING_TAIL  0x0040
#define ZT2S_EOF_SOURCE    0x0100
#define ZT2S_EOF_DEST      0x0200

#define ZT2S_SOFT_EOF_SOURCE 0x0400
#define ZT2S_SOFT_EOF_DEST   0x0800

/* if this flag is set, the proxy has something to say, so regardless of the buffer contents, poll the output side */
#define ZT2S_PROXY_OUT       0x1000

#define ZT2S_EOF_BITS (ZT2S_EOF_SOURCE | ZT2S_EOF_DEST | ZT2S_SOFT_EOF_SOURCE | ZT2S_SOFT_EOF_DEST)

#define ZT2E_STACKED     0x02

#define ZT2E_SOURCE      0
#define ZT2E_DEST        1
#define ZT2E_DOWN_SOURCE ZT2E_SOURCE | ZT2E_STACKED
#define ZT2E_DOWN_DEST   ZT2E_DEST | ZT2E_STACKED
#define ZT2E_MAX         3

typedef struct _ZTransfer2Buffer ZTransfer2Buffer;
typedef struct _ZTransfer2 ZTransfer2;

struct _ZTransfer2Buffer
{
  gchar *buf;
  gsize size;
  gsize ofs, end;
};

struct _ZTransfer2 
{
  ZObject super;
  ZProxy *owner;
  ZPoll *poll;
  ZTransfer2Buffer buffers[2];
  ZStream *endpoints[2];
  ZStreamContext transfer_contexts[2];
  ZStreamContext proxy_contexts[2];
  gsize buffer_size;
  glong timeout, progress_interval;
  guint32 flags;
  
  ZStackedProxy *stacked;
  GSource *timeout_source;
  GSource *progress_source;

  /* internal state */
  guint32 status;
  gint suspend_reason;
  
  /* info returned by the stacked proxy */
  const gchar *content_format;
  ZVerdict stack_decision;
  GString *stack_info;
  gint64 our_content_length_hint;
  gboolean our_content_length_hint_set;
  gint64 child_content_length_hint;
  gboolean child_content_length_hint_set;
  
  /* Note: This mutex save a race condition in
   * transfer startup. In the function z_transfer2_start
   * the stacking is called before z_transfer2_setup is called.
   * But after stacking an iface callback might be called and
   * it would be causing some problem.
   */
  GMutex *startup_lock;
};

typedef struct _ZTransfer2Funcs
{
  ZObjectFuncs super;
  GIOStatus (*src_read)(ZTransfer2 *self, ZStream *s, gchar *buf, gsize count, gsize *bytes_read, GError **error);
  GIOStatus (*dst_write)(ZTransfer2 *self, ZStream *s, const gchar *buf, gsize count, gsize *bytes_written, GError **error);
  GIOStatus (*src_shutdown)(ZTransfer2 *self, ZStream *s, GError **error);
  GIOStatus (*dst_shutdown)(ZTransfer2 *self, ZStream *s, GError **error);
  gboolean (*stack_proxy)(ZTransfer2 *self, ZStackedProxy **stacked);
  gboolean (*setup)(ZTransfer2 *self);
  ZTransfer2Result (*run)(ZTransfer2 *self);
  gboolean (*progress)(ZTransfer2 *self);
} ZTransfer2Funcs;

extern ZClass ZTransfer2__class;


gboolean z_transfer2_start(ZTransfer2 *self);
void z_transfer2_suspend(ZTransfer2 *self, gint suspend_reason);
gboolean z_transfer2_rollback(ZTransfer2 *self);
gboolean z_transfer2_cancel(ZTransfer2 *self);
void z_transfer2_enable_progress(ZTransfer2 *elf, glong progress_interval);
gboolean z_transfer2_simple_run(ZTransfer2 *self);


ZTransfer2 *
z_transfer2_new(ZClass *class, 
                ZProxy *owner, ZPoll *poll, 
                ZStream *source, ZStream *dest, 
                gsize buffer_size, 
                glong timeout, 
                guint32 flags);

void z_transfer2_free_method(ZObject *s);


static inline gint
z_transfer2_get_suspend_reason(ZTransfer2 *self)
{
  return self->suspend_reason;
}

static inline guint32
z_transfer2_get_status(ZTransfer2 *self, guint32 status_bit)
{
  return !!(self->status & status_bit);
}

static inline void
z_transfer2_set_stacked_proxy(ZTransfer2 *self, ZStackedProxy *stacked)
{
  g_assert(!z_transfer2_get_status(self, ZT2S_STARTED));

  if (self->stacked)
    z_stacked_proxy_destroy(self->stacked);
  self->stacked = stacked;
}

static inline void
z_transfer2_set_content_format(ZTransfer2 *self, const gchar *content_format)
{ 
  self->content_format = content_format;
}

static inline void
z_transfer2_set_proxy_out(ZTransfer2 *self, gboolean enable)
{
  if (enable)
    self->status |= ZT2S_PROXY_OUT;
  else
    self->status &= ~ZT2S_PROXY_OUT;
}

static inline const gchar *
z_transfer2_get_stack_info(ZTransfer2 *self)
{
  return self->stack_info->str;
}

static inline ZVerdict
z_transfer2_get_stack_decision(ZTransfer2 *self)
{
  return self->stack_decision;
}

/**
 * z_transfer2_get_stream:
 * @self: ZTransfer2 instance
 * @endpoint: endpoint index
 *
 * This function returns the stream associated to the endpoint specified
 * by @endpoint. @endpoint should be one of the ZT2E_* values.
 **/
static inline ZStream *
z_transfer2_get_stream(ZTransfer2 *self, gint endpoint)
{
  if (endpoint & ZT2E_STACKED)
    return self->stacked ? self->stacked->downstreams[endpoint & ~ZT2E_STACKED] : NULL;
  else
    return self->endpoints[endpoint];
}

/* helper functions for virtual methods */
static inline GIOStatus
z_transfer2_src_read(ZTransfer2 *self, ZStream *s, gchar *buf, gsize count, gsize *bytes_read, GError **err)
{
  return Z_FUNCS(self, ZTransfer2)->src_read(self, s, buf, count, bytes_read, err);
}

static inline GIOStatus
z_transfer2_dst_write(ZTransfer2 *self, ZStream *s, gchar *buf, gsize count, gsize *bytes_written, GError **err)
{
  return Z_FUNCS(self, ZTransfer2)->dst_write(self, s, buf, count, bytes_written, err);
}

static inline GIOStatus
z_transfer2_src_shutdown(ZTransfer2 *self, ZStream *s, GError **err)
{
  if (Z_FUNCS(self, ZTransfer2)->src_shutdown)
    return Z_FUNCS(self, ZTransfer2)->src_shutdown(self, s, err);
  else
    return G_IO_STATUS_NORMAL;
}

static inline GIOStatus
z_transfer2_dst_shutdown(ZTransfer2 *self, ZStream *s, GError **err)
{
  if (Z_FUNCS(self, ZTransfer2)->dst_shutdown)
    return Z_FUNCS(self, ZTransfer2)->dst_shutdown(self, s, err);
  else
    return G_IO_STATUS_NORMAL;
}
  
static inline gboolean
z_transfer2_stack_proxy(ZTransfer2 *self, ZStackedProxy **stacked)
{
  if (Z_FUNCS(self, ZTransfer2)->stack_proxy)
    return Z_FUNCS(self, ZTransfer2)->stack_proxy(self, stacked);
  else
    return TRUE;
}

static inline ZTransfer2Result
z_transfer2_run(ZTransfer2 *self)
{
  return Z_FUNCS(self, ZTransfer2)->run(self);
}

static inline gboolean
z_transfer2_setup(ZTransfer2 *self)
{
  if (Z_FUNCS(self, ZTransfer2)->setup)
    return Z_FUNCS(self, ZTransfer2)->setup(self);
  else
    return TRUE;
}

static inline gboolean
z_transfer2_progress(ZTransfer2 *self)
{
  if (Z_FUNCS(self, ZTransfer2)->progress)
    return Z_FUNCS(self, ZTransfer2)->progress(self);
  else
    return TRUE;
}

#endif
