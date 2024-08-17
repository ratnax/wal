#include "wait_queue.h"

#include <pthread.h>

struct wait_queue_elem {
    pthread_mutex_t lock;
    pthread_cond_t cond;
};
struct wait_queue {
    int size;
    struct wait_queue_elem *elem;
};

uint64_t __hash(u64 x) {
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
    x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
    x = x ^ (x >> 31);
    return x;
}
int wq_get(struct wait_queue *wq, void *key) {
    return __hash((u64)key) % wq->size;
}
int wq_get2(struct wait_queue *wq, u64 key1, u64 key2) {
    return __hash(__hash(key1) + __hash(key2)) % wq->size;
}
void wq_lock(struct wait_queue *wq, int id) {
    pthread_mutex_lock(&wq->elem[id].lock);
}
void wq_unlock(struct wait_queue *wq, int id) {
    pthread_mutex_unlock(&wq->elem[id].lock);
}
void wq_wait(struct wait_queue *wq, int id) {
    pthread_cond_wait(&wq->elem[id].cond, &wq->elem[id].lock);
}
void wq_signal(struct wait_queue *wq, int id) {
    pthread_cond_broadcast(&wq->elem[id].cond);
}
struct wait_queue *wq_alloc(int size) {
    struct wait_queue *wq;

    if (NULL == (wq = malloc(sizeof(struct wait_queue))))
        return NULL;

    wq->elem = malloc(sizeof(struct wait_queue_elem) * size);
    for (int i = 0; i < size; i++) {
        pthread_mutex_init(&wq->elem[i].lock, NULL);
        pthread_cond_init(&wq->elem[i].cond, NULL);
    }
    wq->size = size;
    return wq;
}
void wq_free(struct wait_queue *wq) {
    if (wq->elem) {
        for (int i = 0; i < wq->size; i++) {
            pthread_mutex_destroy(&wq->elem[i].lock);
            pthread_cond_destroy(&wq->elem[i].cond);
        }
        free(wq->elem);
    }
    free(wq);
}