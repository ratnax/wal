#ifndef __WAIT_H__
#define __WAIT_H__
#include <pthread.h>

#include "spin_lock.h"
#define WQ_INITIALIZER PTHREAD_COND_INITIALIZER
typedef pthread_cond_t wait_queue_t;
static void wq_init(wait_queue_t *wq) {
    pthread_cond_init(wq, NULL);
}
static void wq_wait(wait_queue_t *wq, spinlock_t *lock) {
    pthread_cond_wait(wq, lock);
}
static void wq_signal(wait_queue_t *wq) {
    pthread_cond_signal(wq);
}
static void wq_broadcast(wait_queue_t *wq) {
    pthread_cond_broadcast(wq);
}
#endif
