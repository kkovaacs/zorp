#ifndef ZORPCTL_SZIG_H_INCLUDED
#define ZORPCTL_SZIG_H_INCLUDED

#include "zorpctl.h"

#include <sys/types.h>

typedef struct _ZSzigContext
{
  int fd;
} ZSzigContext;

int z_szig_get_value(ZSzigContext *ctx, const char *key, char *result, size_t result_len);
int z_szig_get_sibling(ZSzigContext *ctx, const char *key, char *result, size_t result_len);
int z_szig_get_child(ZSzigContext *ctx, const char *key, char *result, size_t result_len);
int z_szig_logging(ZSzigContext *ctx, const char *subcmd, const char *param, char *result, size_t result_len);
int z_szig_reload(ZSzigContext *ctx, const char *subcmd, char *result, size_t result_len);
int z_szig_stop_session(ZSzigContext *ctx, const char *instance, char *result, size_t result_len);
int z_szig_authorize(ZSzigContext *ctx, const char *instance, int accept, const char *description, char *result, size_t result_len);
int z_szig_coredump(ZSzigContext *ctx);
int z_szig_deadlockcheck(ZSzigContext *ctx, const char *subcmd, char *result, size_t result_len);

ZSzigContext *z_szig_context_new(const char *instance_name);
void z_szig_context_destroy(ZSzigContext *ctx);

#endif
