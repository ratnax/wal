#ifndef __GLOBAL_H__
#define __GLOBAL_H__
#define _GNU_SOURCE
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <zlib.h>
#include <linux/futex.h>
#include <sys/syscall.h>

typedef uint64_t u64;
typedef  int64_t s64;
typedef  int32_t s32;
typedef uint32_t u32;
typedef  int16_t s16;
typedef uint16_t u16;
typedef  uint8_t u8;
typedef   int8_t s8;

#define TAILQ_FOREACH_SAFE(var, head, field, tvar) \
    for ((var) = TAILQ_FIRST((head));              \
         (var) && ((tvar) = TAILQ_NEXT((var), field), 1); (var) = (tvar))

#define ERR_PTR(err) ((void *)(intptr_t)(err))
#define PTR_ERR(err) ((int)(intptr_t)(err))
#define IS_ERR(err) ((intptr_t)(err) < 4096)
#endif

