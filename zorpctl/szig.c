#include "szig.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define SZIG_MAX_CMD_LENGTH 256
#define SZIG_MAX_VALUE_LENGTH 16384

static int
z_szig_write_request(ZSzigContext *ctx, const char *request)
{
  if (write(ctx->fd, request, strlen(request)) < 0)
    return 0;
  return 1;
}

static int
z_szig_read_response(ZSzigContext *ctx, char *response, size_t response_len)
{
  int len;
  if ((len = read(ctx->fd, response, response_len - 1)) < 0)
    return 0;
  response[len] = 0;
  if (response[len - 1] == '\n')
    response[len-1] = 0;
  return 1;
}

int
z_szig_get_value(ZSzigContext *ctx, const char *key, char *result, size_t result_len)
{
  char buf[SZIG_MAX_CMD_LENGTH];
  
  snprintf(buf, sizeof(buf), "GETVALUE %s\n", key);
  if (!z_szig_write_request(ctx, buf))
    return 0;
  if (!z_szig_read_response(ctx, result, result_len))
    return 0;
  return 1;
}

int
z_szig_get_sibling(ZSzigContext *ctx, const char *key, char *result, size_t result_len)
{
  char buf[SZIG_MAX_CMD_LENGTH];
  
  snprintf(buf, sizeof(buf), "GETSBLNG %s\n", key);
  if (!z_szig_write_request(ctx, buf))
    return 0;
  if (!z_szig_read_response(ctx, result, result_len))
    return 0;
    
  return 1;
}

int
z_szig_get_child(ZSzigContext *ctx, const char *key, char *result, size_t result_len)
{
  char buf[SZIG_MAX_CMD_LENGTH];

  snprintf(buf, sizeof(buf), "GETCHILD %s\n", key);
  if (!z_szig_write_request(ctx, buf))
    return 0;
  if (!z_szig_read_response(ctx, result, result_len))
    return 0;
    
  return 1;
}

int
z_szig_logging(ZSzigContext *ctx, const char *subcmd, const char *param, char *result, size_t result_len)
{
  char buf[SZIG_MAX_CMD_LENGTH];
  char res_buf[128];
  
  snprintf(buf, sizeof(buf), "LOGGING %s %s\n", subcmd, param);
  if (!z_szig_write_request(ctx, buf))
    return 0;
  if (!z_szig_read_response(ctx, res_buf, sizeof(res_buf)))
    return 0;
    
  if (strncmp(res_buf, "FAIL ", 5) == 0)
    {
      return 0;
    }
  else if (strncmp(res_buf, "OK ", 3) == 0)
    {
      if (result)
        {
          strncpy(result, res_buf + 3, result_len);
          res_buf[result_len - 1] = 0;
        }
      return 1;
    }
  else
    {
      return 0;
    }
}

int
z_szig_deadlockcheck(ZSzigContext *ctx, const char *subcmd, char *result, size_t result_len)
{
  char buf[SZIG_MAX_CMD_LENGTH];
  char res_buf[128];

  snprintf(buf, sizeof(buf), "DEADLOCKCHECK %s\n", subcmd);
  if (!z_szig_write_request(ctx, buf))
    return 0;
  if (!z_szig_read_response(ctx, res_buf, sizeof(res_buf)))
    return 0;

  if (strncmp(res_buf, "FAIL ", 5) == 0)
    {
      return 0;
    }
  else if (strncmp(res_buf, "OK ", 3) == 0)
    {
      if (result)
        {
          strncpy(result, res_buf + 3, result_len);
          res_buf[result_len - 1] = 0;
        }
      return 1;
    }
  else
    {
      return 0;
    }
}

int
z_szig_reload(ZSzigContext *ctx, const char *subcmd, char *result, size_t result_len)
{
  char buf[SZIG_MAX_CMD_LENGTH];
  char res_buf[128];
  
  if (!subcmd)
    snprintf(buf, sizeof(buf), "RELOAD\n");
  else
    snprintf(buf, sizeof(buf), "RELOAD %s\n", subcmd);
    
  if (!z_szig_write_request(ctx, buf))
    return 0;
  if (!z_szig_read_response(ctx, res_buf, sizeof(res_buf)))
    return 0;
    
  if (strncmp(res_buf, "FAIL ", 5) == 0)
    {
      return 0;
    }
  else if (strncmp(res_buf, "OK ", 3) == 0)
    {
      if (result)
        {
          strncpy(result, res_buf + 3, result_len);
          res_buf[result_len - 1] = 0;
        }
      return 1;
    }
  else
    {
      return 0;
    }
}



int
z_szig_authorize(ZSzigContext *ctx, const char *instance, int accept, const char *description, char *result, size_t result_len)
{
  char buf[SZIG_MAX_CMD_LENGTH];
  char res_buf[128];
  
  if (!instance)
    return 0;
  else
    snprintf(buf, sizeof(buf), "AUTHORIZE %s %s %s\n", accept ? "ACCEPT" : "REJECT", instance, description);
    
  if (!z_szig_write_request(ctx, buf))
    return 0;
  if (!z_szig_read_response(ctx, res_buf, sizeof(res_buf)))
    return 0;
    
  if (strncmp(res_buf, "FAIL ", 5) == 0)
    {
      if (result)
        {
          strncpy(result, res_buf + 5, result_len);
          res_buf[result_len - 1] = 0;
        }
      return 0;
    }
  else if (strncmp(res_buf, "OK ", 3) == 0)
    {
      if (result)
        {
          strncpy(result, res_buf + 3, result_len);
          res_buf[result_len - 1] = 0;
        }
      return 1;
    }
  else
    {
      return 0;
    }
}

int
z_szig_coredump(ZSzigContext *ctx)
{
  char buf[SZIG_MAX_CMD_LENGTH];
  char res_buf[128];

  snprintf(buf, sizeof(buf), "COREDUMP\n");
  if (!z_szig_write_request(ctx, buf))
    return 0;
  if (!z_szig_read_response(ctx, res_buf, sizeof(res_buf)))
    return 0;

  if (strncmp(res_buf, "FAIL ", 5) == 0)
    {
      return 0;
    }
  else if (strncmp(res_buf, "OK ", 3) == 0)
    {
      return 1;
    }
  else
    {
      return 0;
    }
}

ZSzigContext *
z_szig_context_new(const char *instance_name)
{
  ZSzigContext *ctx;
  struct sockaddr_un unaddr;
  int fd;
  
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1)
    return NULL;  
  unaddr.sun_family = AF_UNIX;
  snprintf(unaddr.sun_path, sizeof(unaddr.sun_path), ZORP_PIDFILEDIR "zorpctl.%s", instance_name);
  if (connect(fd, (struct sockaddr *) &unaddr, sizeof(unaddr)) < 0)
    {
      close(fd);
      return NULL;
    }

  ctx = calloc(sizeof(ZSzigContext), 1);
  ctx->fd = fd;
  return ctx;
}

void 
z_szig_context_destroy(ZSzigContext *ctx)
{
  if (ctx)
    {
      close(ctx->fd);
      free(ctx);
    }
}

