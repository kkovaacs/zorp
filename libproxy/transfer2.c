#include <zorp/proxy/transfer2.h>
#include <zorp/log.h>
#include <zorp/source.h>

#define MAX_READ_AT_A_TIME 30

typedef struct _ZTransfer2PSIface
{
  ZProxyStackIface super;
  ZTransfer2 *transfer;
} ZTransfer2PSIface;

extern ZClass ZTransfer2PSIface__class;

static inline void
z_transfer2_update_status(ZTransfer2 *self, guint32 status_bit, gint enable)
{
  guint32 old_mask = self->status & ZT2S_EOF_BITS;
  if (enable)
    self->status |= status_bit;
  else
    self->status &= ~status_bit;
  
  /*LOG
    This message reports that the data-transfer to or from some endpoint is closed.
   */
  z_proxy_log(self->owner, CORE_DEBUG, 7, "Eofmask is updated; old_mask='%04x', eof_mask='%04x'", old_mask, self->status & ZT2S_EOF_BITS);
}

/**
 * z_transfer2_ps_iface_set_stacked_verdict:
 * @self: ZProxyStackIface instance
 * @verdict: verdict sent by the child proxy
 * @description: additional information about @decision
 *
 * This function is the virtual set_result method in the ZProxyStackIface
 * interface callable by child proxies. It simply stores the verdict sent
 * by the child proxy in self->stack_decision.
 *
 * NOTE: this function runs in the thread of the child proxy and there is no
 * synchronization between this and the main proxy thread except for the fact
 * that the child proxy should call this function before he sends anything
 * and HTTP will make use of this value when it first receives something,
 * thus there must be at least one context switch in between, and the HTTP
 * is possibly sleeping when this function is called.
 **/
static void
z_transfer2_ps_iface_set_stacked_verdict(ZProxyStackIface *s, ZVerdict verdict, const gchar *description)
{
  ZTransfer2PSIface *self = Z_CAST(s, ZTransfer2PSIface);

  g_string_assign(self->transfer->stack_info, description ? description : "");
  self->transfer->stack_decision = verdict;
}

/**
 * http_set_content_length:
 * @self: ZProxyStackIface instance
 * @content_length: the length of the content to be transferred
 *
 * This function is the virtual set_content_length method in the
 * ZProxyStackIface interface callable by child proxies. It simply stores
 * the future size of the transferred data blob. This information will then
 * be used by the transfer code to decide whether to include a
 * content-length header. Calling this function is not mandatory by the
 * child proxy, if it is not called chunked mode transfer-encoding will be
 * used.
 */
static void
z_transfer2_ps_iface_set_content_hint(ZProxyStackIface *s, gint64 content_length)
{
  ZTransfer2PSIface *self = Z_CAST(s, ZTransfer2PSIface);

  self->transfer->child_content_length_hint = content_length;
  self->transfer->child_content_length_hint_set = TRUE;
}

/**
 * http_get_content_hint:
 * @self: ZProxyStackIface instance
 * @content_length: the length of the content to be transferred
 *
 * This function is the virtual get_content_length method in the
 * ZProxyStackIface interface callable by child proxies.
 */
static gboolean
z_transfer2_ps_iface_get_content_hint(ZProxyStackIface *s, gint64 *content_length, const gchar **content_format)
{
  ZTransfer2PSIface *self = Z_CAST(s, ZTransfer2PSIface);

  /* Note: Save it with a mutex because it's only be set in z_transfer2_setup in
   * other thread than this called.
   */
  g_mutex_lock(self->transfer->startup_lock);
  *content_format = self->transfer->content_format;
  if (self->transfer->our_content_length_hint_set)
    *content_length = self->transfer->our_content_length_hint;
  else
    *content_length = -1;
  g_mutex_unlock(self->transfer->startup_lock);

  return TRUE;
}


static ZProxyIface *
z_transfer2_ps_iface_new(ZTransfer2 *transfer)
{
  ZTransfer2PSIface *self;
  
  self = Z_CAST(z_proxy_stack_iface_new(Z_CLASS(ZTransfer2PSIface), transfer->owner), ZTransfer2PSIface);
  self->transfer = transfer;
  return &self->super;
}

static void
z_transfer2_ps_iface_free(ZObject *s)
{
  z_proxy_stack_iface_free_method(s);
}

ZProxyStackIfaceFuncs z_transfer2_ps_iface_funcs =
{
  {
    Z_FUNCS_COUNT(ZProxyStackIface),
    .free_fn = z_transfer2_ps_iface_free,
  },
  .set_verdict = z_transfer2_ps_iface_set_stacked_verdict,
  .set_content_hint = z_transfer2_ps_iface_set_content_hint,
  .get_content_hint = z_transfer2_ps_iface_get_content_hint
};

ZClass ZTransfer2PSIface__class =
{
  Z_CLASS_HEADER,
  Z_CLASS(ZProxyStackIface),
  "ZTransfer2PSIface",
  sizeof(ZTransfer2PSIface),
  &z_transfer2_ps_iface_funcs.super,
};

/**
 * z_transfer2_buffer_empty:
 * @self: ZTransfer2Buffer instance
 *
 * This function returns TRUE when the buffer specified by @self contains no
 * data.
 **/
static inline gboolean
z_transfer2_buffer_empty(ZTransfer2Buffer *self)
{
  return self->ofs == self->end;
}

/**
 * z_transfer2_buffer_full:
 * @self: ZTransfer2Buffer instance
 *
 * This function returns TRUE when the buffer specified by @self is full
 **/
static inline gboolean
z_transfer2_buffer_full(ZTransfer2Buffer *self)
{
  return self->end == self->size;
}

/**
 * z_transfer2_buffer_init:
 * @self: ZTransfer2Buffer instance
 * @buffer_size: buffer size
 *
 * This function initializes a ZTransfer2Buffer structure and allocates the
 * memory area where the buffer is stored. 
 *
 * NOTE: the ZTransfer2Buffer structure itself is not allocated, it is
 * expected that it is a member of some container structure, thus it will be
 * allocated independently by the caller.
 **/
static inline void
z_transfer2_buffer_init(ZTransfer2Buffer *self, gsize buffer_size)
{
  self->buf = g_malloc(buffer_size);
  self->size = buffer_size;
}

/**
 * z_transfer2_buffer_destroy:
 * @self: ZTransfer2Buffer instance
 *
 * This function frees the memory area associated to the buffer of
 * the ZTransfer2Buffer structure specified by @self.
 *
 * NOTE: the ZTransfer2Buffer structure itself is not freed, it is
 * expected that it is a member of some container structure, thus it will be
 * freed independently by the caller.
 **/
static inline void
z_transfer2_buffer_destroy(ZTransfer2Buffer *self)
{
  g_free(self->buf);
}

/**
 * z_transfer2_timeout:
 * @user_data: ZTransfer2 instance passed as a generic pointer
 *
 * This function is a timeout-callback registered to terminate the 
 * transfer loop when a specified time elapses.
 **/
static gboolean
z_transfer2_timeout(gpointer user_data)
{
  ZTransfer2 *self = Z_CAST(user_data, ZTransfer2);
   
  z_proxy_enter(self->owner);
  /*LOG
    This message indicates the data transfer timed out.
   */
  z_proxy_log(self->owner, CORE_ERROR, 3, "Data transfer timed out; timeout='%ld'", self->timeout);
  z_transfer2_update_status(self, ZT2S_TIMEDOUT+ZT2S_FAILED+ZT2S_FINISHED, TRUE);
  z_proxy_leave(self->owner);
  return FALSE;
}

/**
 * z_transfer2_timed_progress:
 * @user_data: ZTransfer2 instance passed as a generic pointer
 *
 * This function is the timeout callback registered to be called when the
 * interval specified by the timeout_progress variable elapses.  This is
 * used for example to generate NOOPs in SMTP while transfer is downloading
 * data to the virus checking proxy.
 **/
static gboolean
z_transfer2_timed_progress(gpointer user_data)
{
  ZTransfer2 *self = Z_CAST(user_data, ZTransfer2);
   
  z_proxy_enter(self->owner);
  if (!z_transfer2_progress(self))
    {
      /*LOG
        This message indicates that the data-transfer is interrupted by a timed
	progress callback and Zorp is closing the date-transfer channels.
       */
      z_proxy_log(self->owner, CORE_ERROR, 3, "Data transfer interrupted by progress;");
      z_transfer2_update_status(self, ZT2S_FAILED+ZT2S_FINISHED, TRUE);
    }
  z_timeout_source_set_timeout(self->progress_source, self->progress_interval);

  z_proxy_leave(self->owner);
  return TRUE;
}

/**
 * z_transfer2_update_cond:
 * @self: ZTransfer2 instance
 *
 * This function is called after a chunk of data was transferred to update
 * the stream read/write conditions. It works based on the bits
 * stored in self->status.
 **/
static void
z_transfer2_update_cond(ZTransfer2 *self)
{
  gint i;

  z_proxy_enter(self->owner);
  for (i = 0; i <= ZT2E_MAX; i++)
    {
      if ((i & ZT2E_STACKED) == 0 || self->stacked)
        {
          z_stream_set_cond(z_transfer2_get_stream(self, i), G_IO_IN, FALSE);
          z_stream_set_cond(z_transfer2_get_stream(self, i), G_IO_OUT, FALSE);
        }
    }
  if (self->stacked)
    {
      if (!z_transfer2_get_status(self, ZT2S_EOF_SOURCE))
        {
          if (z_transfer2_buffer_empty(&self->buffers[0]) && !z_transfer2_get_status(self, ZT2S_PROXY_OUT))
            z_stream_set_cond(z_transfer2_get_stream(self, ZT2E_SOURCE), G_IO_IN, TRUE);
          else
            z_stream_set_cond(z_transfer2_get_stream(self, ZT2E_DOWN_SOURCE), G_IO_OUT, TRUE);
        }
      if (!z_transfer2_get_status(self, ZT2S_EOF_DEST))
        {
          if (z_transfer2_buffer_empty(&self->buffers[1]))
            z_stream_set_cond(z_transfer2_get_stream(self, ZT2E_DOWN_DEST), G_IO_IN, TRUE);
          else
            z_stream_set_cond(z_transfer2_get_stream(self, ZT2E_DEST), G_IO_OUT, TRUE);
        }
    }
  else
    {
      /* no stacking */
      if (!z_transfer2_get_status(self, ZT2S_EOF_SOURCE))
        {
          if ((z_transfer2_buffer_empty(&self->buffers[0]) || z_transfer2_get_status(self, ZT2S_EOF_DEST) != 0) && !z_transfer2_get_status(self, ZT2S_PROXY_OUT))
            z_stream_set_cond(z_transfer2_get_stream(self, ZT2E_SOURCE), G_IO_IN, TRUE);
          else
            z_stream_set_cond(z_transfer2_get_stream(self, ZT2E_DEST), G_IO_OUT, TRUE);
        }
    }
  z_proxy_leave(self->owner);
}

/**
 * z_transfer2_eof:
 * @self: ZTransfer2 instance
 *
 * This function is called when transfer encounters an EOF one of the
 * endpoints. It updates self->status end also terminates the poll loop
 * by setting ZT2S_FINISHED when the transfer supposedly finished.
 **/
static void
z_transfer2_eof(ZTransfer2 *self, gint endpoint)
{
  guint32 eof_status = endpoint == ZT2E_SOURCE ? ZT2S_EOF_SOURCE : ZT2S_EOF_DEST;
  
  z_proxy_enter(self->owner);
  if (!z_transfer2_get_status(self, eof_status))
    {
      if (self->stacked)
        {
          if (endpoint == ZT2E_SOURCE)
            {
              z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_SOURCE), FALSE);
              z_transfer2_src_shutdown(self, z_transfer2_get_stream(self, ZT2E_SOURCE), NULL);
              z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_SOURCE), TRUE);

              z_stream_shutdown(z_transfer2_get_stream(self, ZT2E_DOWN_SOURCE), SHUT_WR, NULL);
            }
          else
            {
              z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_DOWN_DEST), FALSE);
              z_stream_shutdown(z_transfer2_get_stream(self, ZT2E_DOWN_DEST), SHUT_RD, NULL);
              z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_DOWN_DEST), TRUE);
              z_transfer2_dst_shutdown(self, z_transfer2_get_stream(self, ZT2E_DEST), NULL);
            }
        }
      else
        {
          z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_SOURCE), FALSE);
          z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_DEST), FALSE);
          z_transfer2_src_shutdown(self, z_transfer2_get_stream(self, ZT2E_SOURCE), NULL);
          z_transfer2_dst_shutdown(self, z_transfer2_get_stream(self, ZT2E_DEST), NULL);
          z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_DEST), TRUE);
          z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_SOURCE), TRUE);

          eof_status = ZT2S_EOF_SOURCE+ZT2S_EOF_DEST;
        }
        
      z_transfer2_update_status(self, eof_status, TRUE);
    }
  if ((self->status & (ZT2S_EOF_SOURCE+ZT2S_EOF_DEST)) == (ZT2S_EOF_SOURCE+ZT2S_EOF_DEST))
    {
      z_transfer2_update_status(self, ZT2S_FINISHED, TRUE);
    }
  z_proxy_leave(self->owner);
}

/**
 * z_transfer2_read_source:
 * @self: ZTransfer2 instance
 * @endpoint: endpoint to fetch data from
 * @buf: store fetched information into this buffer
 * @error: error details are stored here
 *
 * This function is called to fetch data from the specified endpoint. When
 * it is a proxy-connected stream then the proxy provided callbacks are
 * used to fetch information, otherwise z_stream_read is called directly.
 **/
static GIOStatus
z_transfer2_read_source(ZTransfer2 *self, gint endpoint, ZTransfer2Buffer *buf, GError **error)
{
  ZStream *from = z_transfer2_get_stream(self, endpoint);
  GIOStatus res = G_IO_STATUS_NORMAL;
  GError *local_error = NULL;
  gsize read_len;
 
  z_proxy_enter(self->owner);
  if (endpoint & ZT2E_STACKED)
    {
      res = z_stream_read(from, &buf->buf[buf->end], buf->size - buf->end, &read_len, &local_error);
    }
  else if (endpoint == ZT2E_SOURCE)
    {
      res = z_transfer2_src_read(self, self->endpoints[endpoint], &buf->buf[buf->end], buf->size - buf->end, &read_len, &local_error);
    }

  if (res == G_IO_STATUS_NORMAL)
    {
      buf->end += read_len;
    }
  if (local_error)
    g_propagate_error(error, local_error);
  z_proxy_leave(self->owner);
  return res;
}

/**
 * z_transfer2_write_dest:
 * @self: ZTransfer2 instance
 * @endpoint: endpoint to send data to
 * @buf: send data from this buffer
 * @error: error details are stored here
 *
 * This function is called to send data to the specified endpoint. When
 * it is a proxy-connected stream then the proxy provided callbacks are
 * used to send information, otherwise z_stream_write is called directly.
 **/
static GIOStatus
z_transfer2_write_dest(ZTransfer2 *self, gint endpoint, ZTransfer2Buffer *buf, GError **error)
{
  ZStream *to = z_transfer2_get_stream(self, endpoint);
  GError *local_error = NULL;
  GIOStatus res = G_IO_STATUS_NORMAL;
  gsize bytes_written;
  
  z_proxy_enter(self->owner);
  if (!z_transfer2_buffer_empty(buf))
    {
      if (endpoint & ZT2E_STACKED)
        res = z_stream_write(to, &buf->buf[buf->ofs], buf->end - buf->ofs, &bytes_written, &local_error);
      else
        res = z_transfer2_dst_write(self, to, &buf->buf[buf->ofs], buf->end - buf->ofs, &bytes_written, &local_error);
      switch (res)
        {
        case G_IO_STATUS_NORMAL:
          buf->ofs += bytes_written;
          if (!z_transfer2_buffer_empty(buf))
            {
              res = G_IO_STATUS_AGAIN;
            }
        default:
          break;
        }
    }
  if (local_error)
    g_propagate_error(error, local_error);
  z_proxy_leave(self->owner);
  return res;
}

/**
 * z_transfer2_copy_data:
 * @self: ZTransfer2 instance
 * @ep_from: source endpoint
 * @ep_to: destination endpoint
 * @error: error details are stored here
 *
 * This function is the central copy-loop of ZTransfer2 and is called by I/O
 * callbacks assigned to various streams. It copies data while:
 * 1) data is available (e.g. G_IO_STATUS_NORMAL is returned)
 * 2) have not copied MAX_READ_AT_A_TIME chunks yet
 * 3) data can be flushed to destination (e.g. G_IO_STATUS_NORMAL is returned)
 *
 * when any of the conditions become FALSE, z_transfer2_copy_data returns,
 * but the operation can simply be restarted by calling it again.
 * Information stored in internal buffers are automatically reused in the
 * next invocation.
 *
 * This function also updates the timeout timer to indicate that some I/O
 * has happened, thus the timeout callback does not need to be called.
 **/
static GIOStatus
z_transfer2_copy_data(ZTransfer2 *self, gint ep_from, gint ep_to, GError **error)
{
  GError *local_error = NULL;
  ZTransfer2Buffer *buf = &self->buffers[ep_from & ~ZT2E_STACKED];
  gint pkt_count = 0;
  GIOStatus res = G_IO_STATUS_NORMAL;
  gboolean leave_while = FALSE;
  
  z_proxy_enter(self->owner);
  if (self->timeout_source)
    z_timeout_source_set_timeout(self->timeout_source, self->timeout);
  
  while (pkt_count < MAX_READ_AT_A_TIME && !leave_while)
    {
      if (!z_transfer2_get_status(self, ZT2S_COPYING_TAIL))
        {
          res = z_transfer2_write_dest(self, ep_to, buf, &local_error);
          if (res == G_IO_STATUS_NORMAL)
            {
              if (!z_transfer2_buffer_empty(buf))
                break;
            }
          else if (res == G_IO_STATUS_AGAIN)
            {
              break;
            }
          else
            {
              z_transfer2_update_status(self, ZT2S_FAILED, TRUE);
              if (self->flags & ZT2F_COMPLETE_COPY)
                {
                  z_transfer2_update_status(self, ZT2S_COPYING_TAIL, TRUE);
                }
              else
                {
                  z_transfer2_update_status(self, ZT2S_FINISHED, TRUE);
                }
              break;
            }
        }
      else
        {
          buf->ofs = buf->end = 0;
        }

      if (z_transfer2_buffer_empty(buf))
        {
          buf->ofs = buf->end = 0;
        }

      while (pkt_count < MAX_READ_AT_A_TIME && !z_transfer2_buffer_full(buf))
        {
          guint eof_status = ep_from == ZT2E_SOURCE ? ZT2S_SOFT_EOF_SOURCE : ZT2S_SOFT_EOF_DEST;
          
          if (!z_transfer2_get_status(self, eof_status))
            {
              res = z_transfer2_read_source(self, ep_from, buf, &local_error);
              if (res == G_IO_STATUS_NORMAL)
                {
                  ;
                }
              else if (res == G_IO_STATUS_AGAIN)
                {
                  leave_while = TRUE;
                  break;
                }
              else if (res == G_IO_STATUS_EOF)
                {
                  if (z_transfer2_buffer_empty(buf))
                    {
                      z_transfer2_eof(self, ep_from);
                      leave_while = TRUE;
                      break;
                    }
                  else
                    {
                      z_transfer2_update_status(self, eof_status, TRUE);
                      break;
                    }
                }
              else 
                {
                  z_transfer2_update_status(self, ZT2S_FINISHED + ZT2S_ABORTED, TRUE);
                  z_transfer2_eof(self, ep_from);
                  leave_while = TRUE;
                  break;
                }
              pkt_count++;
            }
          else
            {
              if (z_transfer2_buffer_empty(buf))
                {
                  z_transfer2_eof(self, ep_from);
                  leave_while = TRUE;
                }
              break;
            }
        }
    }
  
  z_transfer2_update_cond(self);
  if (local_error)
    g_propagate_error(error, local_error);
  
  z_proxy_leave(self->owner);
  return res;
}

/**
 * z_transfer2_copy_src_to_dst:
 * @s: ZStream instance
 * @cond: condition which triggered this callback
 * @user_data: ZTransfer2 instance passed as a generic pointer
 *
 * This function is registered as the "readable" callback of the client-side
 * stream when no stacking is used, thus data is directly copied to the
 * server-side.
 **/
static gboolean
z_transfer2_copy_src_to_dst(ZStream *s G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED)
{
  ZTransfer2 *self = Z_CAST(user_data, ZTransfer2);

  z_proxy_enter(self->owner);  
  z_transfer2_copy_data(self, ZT2E_SOURCE, ZT2E_DEST, NULL);
  z_proxy_leave(self->owner);
  return TRUE;
}

/**
 * z_transfer2_copy_src_to_down:
 * @s: ZStream instance
 * @cond: condition which triggered this callback
 * @user_data: ZTransfer2 instance passed as a generic pointer
 *
 * This function is registered as the "readable" callback of the client-side
 * stream when stacking is used, thus data must be copied to the stacked
 * proxy first.
 **/
static gboolean
z_transfer2_copy_src_to_down(ZStream *s G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED)
{
  ZTransfer2 *self = Z_CAST(user_data, ZTransfer2);

  z_proxy_enter(self->owner);
  z_transfer2_copy_data(self, ZT2E_SOURCE, ZT2E_DOWN_SOURCE, NULL);
  z_proxy_leave(self->owner);
  return TRUE;
}

/**
 * z_transfer2_copy_down_to_dst:
 * @s: ZStream instance
 * @cond: condition which triggered this callback
 * @user_data: ZTransfer2 instance passed as a generic pointer
 *
 * This function is registered as the "readable" callback of the server-side
 * stacked stream, and copies data to the server-side.
 **/
static gboolean
z_transfer2_copy_down_to_dst(ZStream *s G_GNUC_UNUSED, GIOCondition cond G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED)
{
  ZTransfer2 *self = Z_CAST(user_data, ZTransfer2);

  z_proxy_enter(self->owner);
  z_transfer2_copy_data(self, ZT2E_DOWN_DEST, ZT2E_DEST, NULL);
  z_proxy_leave(self->owner);
  return TRUE;
}

/**
 * z_transfer2_switch_to_transfer_context:
 * @self: ZTransfer2 instance
 *
 * This function switches all related streams to use the transfer context.
 **/
static void
z_transfer2_switch_to_transfer_context(ZTransfer2 *self)
{
  z_stream_save_context(z_transfer2_get_stream(self, ZT2E_SOURCE), &self->proxy_contexts[0]);
  z_stream_save_context(z_transfer2_get_stream(self, ZT2E_DEST), &self->proxy_contexts[1]);
  
  z_stream_restore_context(z_transfer2_get_stream(self, ZT2E_SOURCE), &self->transfer_contexts[0]);
  z_stream_restore_context(z_transfer2_get_stream(self, ZT2E_DEST), &self->transfer_contexts[1]);
}

/**
 * z_transfer2_switch_to_proxy_context:
 * @self: ZTransfer2 instance
 *
 * This function switches all related streams to use the proxy context.
 **/
static void
z_transfer2_switch_to_proxy_context(ZTransfer2 *self)
{
  z_stream_save_context(z_transfer2_get_stream(self, ZT2E_SOURCE), &self->transfer_contexts[0]);
  z_stream_save_context(z_transfer2_get_stream(self, ZT2E_DEST), &self->transfer_contexts[1]);
  
  z_stream_restore_context(z_transfer2_get_stream(self, ZT2E_SOURCE), &self->proxy_contexts[0]);
  z_stream_restore_context(z_transfer2_get_stream(self, ZT2E_DEST), &self->proxy_contexts[1]);
}

/**
 * z_transfer2_start:
 * @self: ZTransfer2 instance
 *
 * This function must be called after the construction of the ZTransfer2
 * object to actually register read/write callbacks and various timers.
 * Without calling this function z_transfer2_run will not do anything.
 * 
 **/
gboolean 
z_transfer2_start(ZTransfer2 *self)
{
  gboolean res;
  ZProxyIface *iface;
  
  z_proxy_enter(self->owner);
  
  iface = z_transfer2_ps_iface_new(self);
  z_proxy_add_iface(self->owner, iface);
  z_object_unref(&iface->super);
        
  g_mutex_lock(self->startup_lock);
  if (!z_transfer2_stack_proxy(self, &self->stacked))
    {
      g_mutex_unlock(self->startup_lock);
      z_proxy_log(self->owner, CORE_ERROR, 3, "Could not start stacked proxy, rejecting transfer;");
      z_proxy_leave(self->owner);
      return FALSE;
    }
 
  z_transfer2_switch_to_transfer_context(self);

  /* NOTE: shutdown goes back to blocking mode in which case timeout is significant */
  z_stream_set_timeout(z_transfer2_get_stream(self, ZT2E_SOURCE), self->timeout);
  z_stream_set_timeout(z_transfer2_get_stream(self, ZT2E_DEST), self->timeout);
  
  z_transfer2_buffer_init(&self->buffers[0], self->buffer_size);
  
  if ((self->flags & ZT2F_PROXY_STREAMS_POLLED) == 0)
    {
      z_poll_add_stream(self->poll, z_transfer2_get_stream(self, ZT2E_SOURCE));
      z_poll_add_stream(self->poll, z_transfer2_get_stream(self, ZT2E_DEST));
    }
  
  /* initialize stacked streams */
  if (self->stacked)
    {
      if ((self->stacked->flags & Z_SPF_HALF_DUPLEX) == 0)
        {
          /* shutdown the reverse direction */
          z_stream_shutdown(z_transfer2_get_stream(self, ZT2E_DOWN_SOURCE), SHUT_RD, NULL);
          z_stream_shutdown(z_transfer2_get_stream(self, ZT2E_DOWN_DEST), SHUT_WR, NULL);
        }

      z_transfer2_buffer_init(&self->buffers[1], self->buffer_size);
      z_poll_add_stream(self->poll, z_transfer2_get_stream(self, ZT2E_DOWN_SOURCE));
      z_poll_add_stream(self->poll, z_transfer2_get_stream(self, ZT2E_DOWN_DEST));

      z_stream_set_callback(z_transfer2_get_stream(self, ZT2E_SOURCE),
                            G_IO_IN,
                            z_transfer2_copy_src_to_down,
                            self,
                            NULL);
      z_stream_set_callback(z_transfer2_get_stream(self, ZT2E_DOWN_SOURCE),
                            G_IO_OUT,
                            z_transfer2_copy_src_to_down,
                            self,
                            NULL);
                                                                                                                             
      z_stream_set_cond(z_transfer2_get_stream(self, ZT2E_SOURCE), G_IO_IN, TRUE);

      z_stream_set_callback(z_transfer2_get_stream(self, ZT2E_DOWN_DEST),
                            G_IO_IN,
                            z_transfer2_copy_down_to_dst,
                            self,
                            NULL);
      z_stream_set_callback(z_transfer2_get_stream(self, ZT2E_DEST),
                            G_IO_OUT,
                            z_transfer2_copy_down_to_dst,
                            self,
                            NULL);
                                                                                                                             
      z_stream_set_cond(z_transfer2_get_stream(self, ZT2E_DEST | ZT2E_STACKED), G_IO_IN, TRUE);

      z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_DOWN_SOURCE), TRUE);
      z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_DOWN_DEST), TRUE);

    }
  else
    {
      z_stream_set_callback(z_transfer2_get_stream(self, ZT2E_SOURCE),
                            G_IO_IN,
                            z_transfer2_copy_src_to_dst,
                            self,
                            NULL);
      z_stream_set_callback(z_transfer2_get_stream(self, ZT2E_DEST),
                            G_IO_OUT,
                            z_transfer2_copy_src_to_dst,
                            self,
                            NULL);

      z_stream_set_cond(z_transfer2_get_stream(self, ZT2E_SOURCE), G_IO_IN, TRUE);
    }
  z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_SOURCE), TRUE);
  z_stream_set_nonblock(z_transfer2_get_stream(self, ZT2E_DEST), TRUE);
  
  res = z_transfer2_setup(self);

  z_transfer2_switch_to_proxy_context(self);
  g_mutex_unlock(self->startup_lock);

  if (self->timeout > 0)
    {
      GMainContext *context;
                                                                                
      self->timeout_source = z_timeout_source_new(self->timeout);
      g_source_set_callback(self->timeout_source, z_transfer2_timeout, self, NULL);
      context = z_poll_get_context(self->poll);
      g_source_attach(self->timeout_source, context);
    }
  if (self->progress_interval > 0)
    {
      GMainContext *context;
                                                                                
      self->progress_source = z_timeout_source_new(self->progress_interval);
      g_source_set_callback(self->progress_source, z_transfer2_timed_progress, self, NULL);
      context = z_poll_get_context(self->poll);
      g_source_attach(self->progress_source, context);
    }
    
  
  z_proxy_leave(self->owner);
  return res;
}

/**
 * z_transfer2_suspend:
 * @self: ZTransfer2 instance
 * @suspend_reason: information indicating why transfer was suspended
 *
 * This function can be used from proxy provided callbacks while transfer is
 * taking place. It temporarily suspends the data transfer and returns to
 * the caller. Transfer can be restarted by calling z_transfer2_run again.
 * 
 * The suspend feature is used for example to generate NOOP commands to the
 * SMTP server while transfer is processing data.
 **/
void 
z_transfer2_suspend(ZTransfer2 *self, gint suspend_reason)
{
  z_proxy_enter(self->owner);
  z_transfer2_update_status(self, ZT2S_SUSPENDED, TRUE);
  self->suspend_reason = suspend_reason;
  z_proxy_leave(self->owner);
}

/**
 * z_transfer2_rollback:
 * @self: ZTransfer2 instance
 *
 * This function can be called when transfer was suspended and the data 
 * stream is to be dropped. It basically consumes the incoming data stream
 * without actually writing it to the server side.
 *
 * This function can only be called when the transfer is suspended.
 **/
gboolean 
z_transfer2_rollback(ZTransfer2 *self)
{
  z_enter();
  if (z_transfer2_get_status(self, ZT2S_STARTED) && !z_transfer2_get_status(self, ZT2S_FINISHED))
    {
      /* roll back transfer state */
      z_transfer2_update_status(self, ZT2S_COPYING_TAIL, TRUE);
      while (z_transfer2_run(self) == ZT2_RESULT_SUSPENDED)
        ;
    }
  z_return(TRUE);
}

/**
 * z_transfer2_cancel:
 * @self: ZTransfer2 instance
 *
 * This function abort the transfer. This function can be called from anywhere but
 * it's only set the state of the transfer. You have to continue running the
 * transfer untill it's quit.
 **/
gboolean 
z_transfer2_cancel(ZTransfer2 *self)
{
  z_enter();
  if (!z_transfer2_get_status(self, ZT2S_FINISHED))
    z_transfer2_update_status(self, ZT2S_FINISHED + ZT2S_ABORTED, TRUE);
  z_return(TRUE);
}

/**
 * z_transfer2_run_method:
 * @self: ZTransfer2 instance
 *
 * This function actually performs data transfer.
 **/
static ZTransfer2Result
z_transfer2_run_method(ZTransfer2 *self)
{
  z_enter();
  z_transfer2_switch_to_transfer_context(self);
  z_transfer2_update_cond(self);  
  
  z_transfer2_update_status(self, ZT2S_STARTED, TRUE);
  z_transfer2_update_status(self, ZT2S_SUSPENDED, FALSE);
  while (((self->status & (ZT2S_FINISHED+ZT2S_SUSPENDED)) == 0) && z_poll_iter_timeout(self->poll, -1))
    {
      if (!z_proxy_loop_iteration(self->owner))
        {
          z_transfer2_update_status(self, ZT2S_ABORTED + ZT2S_FINISHED, TRUE);
          break;
        }
    }
  z_transfer2_switch_to_proxy_context(self);
  if (self->status & ZT2S_SUSPENDED)
    {
      z_leave();
      return ZT2_RESULT_SUSPENDED;
    }
  else if (self->status & ZT2S_FAILED)
    {
      z_leave();
      return ZT2_RESULT_FAILED;
    }
  else if (self->status & ZT2S_ABORTED)
    {
      z_leave();
      return ZT2_RESULT_ABORTED;
    }
  else
    {
      z_leave();
      return ZT2_RESULT_FINISHED;
    }
  z_leave();
}

/**
 * z_transfer2_enable_progress:
 * @self: ZTransfer2 instance
 * @progress_interval: interval in milliseconds to call the progress timeout callback
 *
 * This function must be called before z_transfer2_start() is called to
 * enable the progress callback.
 **/
void
z_transfer2_enable_progress(ZTransfer2 *self, glong progress_interval)
{
  self->progress_interval = progress_interval;
}

gboolean
z_transfer2_simple_run(ZTransfer2 *self)
{
  ZTransfer2Result tr;
  gboolean success;
  
  if (!z_transfer2_start(self))
    return FALSE;
  
  do
    {
      tr = z_transfer2_run(self);
    }
  while (tr == ZT2_RESULT_SUSPENDED);
  success = (tr != ZT2_RESULT_FAILED) && (tr != ZT2_RESULT_ABORTED);
  
  if (tr == ZT2_RESULT_FAILED)
    z_transfer2_rollback(self);
    
  return success;
}

/**
 * z_transfer2_new:
 * @class: class to instantiate 
 * @owner: owner proxy instance
 * @poll: ZPoll instance
 * @source: source stream
 * @dest: destination stream
 * @buffer_size: size of the transfer buffer
 * @timeout: after this amount of inactivity, the transfer is ended with failure
 * @flags: bit combination of the ZT2F_* constants
 *
 * This constructor creates a new ZTransfer2 instance with the specified parameters.
 **/
ZTransfer2 *
z_transfer2_new(ZClass *class, 
                ZProxy *owner, ZPoll *poll, 
                ZStream *source, ZStream *dest, 
                gsize buffer_size, 
                glong timeout, 
                guint32 flags)
{
  ZTransfer2 *self;
  
  z_proxy_enter(owner);
  
  self = Z_NEW_COMPAT(class, ZTransfer2);
  z_proxy_ref(owner);
  self->owner = owner;
  z_poll_ref(poll);
  self->poll = poll;
  self->endpoints[0] = z_stream_ref(source);
  self->endpoints[1] = z_stream_ref(dest);
  self->buffer_size = buffer_size;
  self->timeout = timeout;
  self->flags = flags;
  self->content_format = "file";
  
  self->startup_lock = g_mutex_new();
  
  self->stack_info = g_string_sized_new(32);
  self->stack_decision = Z_ACCEPT;
  
  z_proxy_leave(owner);
  return self;
}

/**
 * z_transfer2_free_method:
 * @s: ZTransfer2 instance passed as a ZObject
 *
 * This method is called when a ZTransfer2 instance is freed. It has to free
 * all dynamically allocated members in @s.
 **/
void
z_transfer2_free_method(ZObject *s)
{
  ZTransfer2 *self = Z_CAST(s, ZTransfer2);
  ZProxyIface *iface;
  guint i;

  z_enter();
  iface = z_proxy_find_iface(self->owner, Z_CLASS(ZTransfer2PSIface));
  if (iface)
    {
      z_proxy_del_iface(self->owner, iface);
      z_object_unref(&iface->super);
    }
  
  z_proxy_unref(self->owner);
  if ((self->flags & ZT2F_PROXY_STREAMS_POLLED) == 0)
    {
      z_poll_remove_stream(self->poll, z_transfer2_get_stream(self, ZT2E_SOURCE));
      z_poll_remove_stream(self->poll, z_transfer2_get_stream(self, ZT2E_DEST));
    }

  z_stream_unref(self->endpoints[0]);
  z_stream_unref(self->endpoints[1]);
  z_transfer2_buffer_destroy(&self->buffers[0]);
  if (self->stacked)
    {
      z_poll_remove_stream(self->poll, z_transfer2_get_stream(self, ZT2E_DOWN_SOURCE));
      z_poll_remove_stream(self->poll, z_transfer2_get_stream(self, ZT2E_DOWN_DEST));
      z_stacked_proxy_destroy(self->stacked);
      z_transfer2_buffer_destroy(&self->buffers[1]);
    }
  if (self->timeout_source)
    {
      g_source_destroy(self->timeout_source);
      g_source_unref(self->timeout_source);
      self->timeout_source = NULL;
    }
  if (self->progress_source)
    {
      g_source_destroy(self->progress_source);
      g_source_unref(self->progress_source);
      self->progress_source = NULL;
    }
  for (i = 0; i < EP_MAX; i++)
    {
      if (self->transfer_contexts[i].stream_extra)
        z_stream_context_destroy(&self->transfer_contexts[i]);
    }
  z_poll_unref(self->poll);
  g_string_free(self->stack_info, TRUE);
  
  if (self->startup_lock)
    g_mutex_free(self->startup_lock);
  
  z_object_free_method(s);
  z_return();
}

ZTransfer2Funcs z_transfer2_funcs = 
{
  {
    Z_FUNCS_COUNT(ZTransfer2),
    z_transfer2_free_method,
  },
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  .run = z_transfer2_run_method,
  .progress = NULL
};

ZClass ZTransfer2__class = 
{
  Z_CLASS_HEADER,
  &ZObject__class,
  "ZTransfer2",
  sizeof(ZTransfer2),
  &z_transfer2_funcs.super
};
