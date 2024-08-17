#include "include/io_uring.h"

#include <liburing.h>

#define QUEUE_DEPTH 128
struct ioring {
    int ref;
    struct io_uring ring;
    ioring_endio_t cb;
    TAILQ_ENTRY(ioring) list;
};
typedef TAILQ_HEAD(, ioring) ioring_list_t;
static ioring_list_t ioring_free_list =
    TAILQ_HEAD_INITIALIZER(ioring_free_list);
static struct ioring *io_rings;
static int n_io_rings;
static pthread_mutex_t ioring_mutex = PTHREAD_MUTEX_INITIALIZER;
int io_uring_get(ioring_endio_t cb) {
    pthread_mutex_lock(&ioring_mutex);
    struct ioring *ring = TAILQ_FIRST(&ioring_free_list);
    if (!ring) {
        pthread_mutex_unlock(&ioring_mutex);
        return -EAGAIN;
    }
    TAILQ_REMOVE(&ioring_free_list, ring, list);
    ring->ref = 1;
    ring->cb = cb;
    pthread_mutex_unlock(&ioring_mutex);
    return io_rings - ring;
}
void io_uring_put(int i) {
    struct ioring *ring = &io_rings[i];
    pthread_mutex_lock(&ioring_mutex);
    if (--ring->ref) {
        pthread_mutex_unlock(&ioring_mutex);
        return;
    }
    TAILQ_INSERT_TAIL(&ioring_free_list, ring, list);
    pthread_mutex_unlock(&ioring_mutex);
}
int io_uring_is_pending(int i) {
    return io_uring_sq_ready(&io_rings[i].ring);
}
int io_uring_schedule_read(int i, int fd, void *buf, size_t len, off_t offset,
    void *data) {
    struct io_uring_sqe *sqe;

    sqe = io_uring_get_sqe(&io_rings[i].ring);
    if (!sqe) {
        return -EAGAIN;
    }
    io_uring_sqe_set_data(sqe, data);
    io_uring_prep_read(sqe, fd, buf, len, offset);
    return 0;
}
int io_uring_schedule_write(int i, int fd, void *buf, size_t len, off_t offset,
    void *data) {
    struct io_uring_sqe *sqe;

    assert(data);
    sqe = io_uring_get_sqe(&io_rings[i].ring);
    if (!sqe) {
        return -EAGAIN;
    }
    io_uring_prep_write(sqe, fd, buf, len, offset);
    io_uring_sqe_set_data(sqe, data);
    return 0;
}
int io_uring_flush_pending(int i) {
    int err = io_uring_submit(&io_rings[i].ring);
    if (err < 0) {
        return err;
    }
    return 0;
}
int io_uring_wait(int i) {
    struct io_uring_cqe *cqe;
    void *data;
    int res;
    int err;
    do {
        err = io_uring_wait_cqe(&io_rings[i].ring, &cqe);
    } while (err == -EAGAIN);
    if (err)
        return err;
    data = io_uring_cqe_get_data(cqe);
    res = cqe->res;
    assert(data);
    io_uring_cqe_seen(&io_rings[i].ring, cqe);
    io_rings[i].cb(data, res);
    return 0;
}
void __exit_io_uring(void) {
    int i;

    if (io_rings) {
        for (i = 0; i < n_io_rings; i++) {
            io_uring_queue_exit(&io_rings[i].ring);
        }
        free(io_rings);
    }
}
int __init_io_uring(int n) {
    int i;

    io_rings = calloc(n, sizeof(struct ioring));
    if (!io_rings) {
        return -ENOMEM;
    }
    for (i = 0; i < n; i++) {
        io_uring_queue_init(QUEUE_DEPTH, &io_rings[i].ring, 0);

        pthread_mutex_lock(&ioring_mutex);
        TAILQ_INSERT_TAIL(&ioring_free_list, &io_rings[i], list);
        pthread_mutex_unlock(&ioring_mutex);
    }
    n_io_rings = n;
    return 0;
}