#include <sys/types.h>

#include "op_queue.h"
#include "page_operation.h"
#include "page_queue.h"
#include "spin_lock.h"
#include "umem.h"
#include "wait.h"

typedef TAILQ_HEAD(operation_list, operation) operation_list_t;
struct operation {
    uint64_t seqno;
    void *buf;
    u16 len;
    u8 removed : 1;
    u8 flags : 7;
    u8 reserved;
    int flushes_pending;
    page_operation_list_t page_ops;
    TAILQ_ENTRY(operation) list;
    wait_queue_t *flush_cond;
    struct page_operation __page_ops[0];
};

static struct {
    spinlock_t lock;
    wait_queue_t cond;
    operation_list_t queue;
    struct operation *write_from;
    struct operation *flush_till;
    op_queue_error_cb_t error_cb;
    pthread_t thread;
    u64 seqno;
    struct page *page;
} OPQ;

static struct operation *__op_queue_can_be_truncated(void) {
    struct operation *op = TAILQ_FIRST(&OPQ.queue);
    if (op && op->removed && op->flushes_pending == 0) {
        return op;
    }
    return NULL;
}

void operation_endio(struct operation *op) {
    spin_lock(&OPQ.lock);
    do {
        assert(op->flushes_pending);
        op->flushes_pending--;
        if (op->flushes_pending)
            break;
        if (op->flush_cond)
            wq_signal(op->flush_cond);
        op = TAILQ_NEXT(op, list);
    } while (op);
    spin_unlock(&OPQ.lock);
}

/* split an unattached (to a page yet) operation so that a part can be fit on
 * the page at the head of page queue */
int page_operation_split(struct page_operation *pgop, u16 len) {
    struct page_operation *new_pgop =
        umem_calloc(1, sizeof(struct page_operation));
    if (!new_pgop) {
        return -ENOMEM;
    }
    new_pgop->buf = pgop->buf + len;
    new_pgop->len = pgop->len - len;
    new_pgop->op = pgop->op;
    new_pgop->malloced = 1;
    pgop->len = len;
    TAILQ_INSERT_TAIL(&pgop->op->page_ops, new_pgop, op_list);
    spin_lock(&OPQ.lock);
    pgop->op->flushes_pending++;
    spin_unlock(&OPQ.lock);
    return 0;
}

static int __wal_operation(struct operation *op) {
    struct page_operation *pgop;
    struct page *page = OPQ.page;
    int err = 0;

    pgop = TAILQ_FIRST(&OPQ.write_from->page_ops);
    while (pgop) {
        u16 avail;
        if (pgop->page) {
            /* already attached to a page */
            pgop = TAILQ_NEXT(pgop, op_list);
            continue;
        }
        /* get a page near head of the page queue */
        if (!page && IS_ERR(page = page_queue_next())) {
            OPQ.error_cb(PTR_ERR(page));
            break;
        }
        if ((avail = page_space_available(page)) < pgop->len) {
            /* current page is not sufficient, split the operation */
            if ((err = page_operation_split(pgop, avail))) {
                OPQ.error_cb(err);
                break;
            }
            /* log the first part of the op and schedule the full page
             * write IO */
            if ((err = page_write_final(page, pgop))) {
                OPQ.error_cb(err);
                break;
            }
            page = NULL;
        } else if (avail == pgop->len) {
            /* fits in the page, log and schedule for IO */
            if ((err = page_write_final(page, pgop))) {
                OPQ.error_cb(err);
                break;
            }
            page = NULL;
        } else {
            /* page would not be full after logging op. it would not get
             * scheduled for IO. */
            if ((err = page_write_partial(page, pgop))) {
                OPQ.error_cb(err);
                break;
            }
        }
        pgop = TAILQ_NEXT(pgop, op_list);
    }
    OPQ.page = page;
    if (pgop == NULL) {
        assert(err == 0);
        return 0;
    } else {
        /* could not write the current op completely. break here.
         * Operations on log have to be in sequence, we can not jump to
         * next opeartion. */
        return err;
    }
    return err;
}

static int __wal_operations(void) {
    struct page_operation *pgop;
    struct operation *op;
    int err;

    while (OPQ.write_from) {
        if ((err = __wal_operation(OPQ.write_from)))
            break;

        spin_lock(&OPQ.lock);
        OPQ.write_from = TAILQ_NEXT(OPQ.write_from, list);
        spin_unlock(&OPQ.lock);
    }

    spin_lock(&OPQ.lock);
    while (OPQ.flush_till && OPQ.write_from == NULL) {
        if (OPQ.page == NULL) {
            OPQ.flush_till = NULL;
            break;
        }
        pgop = page_head_pgop(OPQ.page);
        assert(pgop);
        if (pgop->op->seqno <= OPQ.flush_till->seqno) {
            spin_unlock(&OPQ.lock);
            if (!(err = page_flush(OPQ.page))) {
                OPQ.page = NULL;
                spin_lock(&OPQ.lock);
            } else {
                OPQ.error_cb(err);
                spin_lock(&OPQ.lock);
                break;
            }
        } else {
            assert(pgop->op->seqno < OPQ.seqno);
            OPQ.flush_till = NULL;
            break;
        }
    }
    /* OPQ.lock is still held */

    while ((op = TAILQ_FIRST(&OPQ.queue)) && op->removed &&
           op->flushes_pending == 0) {
        if (op == OPQ.flush_till) {
            OPQ.flush_till = NULL;
        }
        TAILQ_REMOVE(&OPQ.queue, op, list);
        spin_unlock(&OPQ.lock);
        while ((pgop = TAILQ_FIRST(&op->page_ops))) {
            TAILQ_REMOVE(&op->page_ops, pgop, op_list);
            pgop->removed = 1;
        }
        page_queue_truncate();
        spin_lock(&OPQ.lock);
    }
    spin_unlock(&OPQ.lock);
    return err;
}

static int __write_operations(void) {
    int err;
    while (OPQ.write_from) {
        spin_unlock(&OPQ.lock);

        if ((err = __wal_operation(OPQ.write_from)))
            return err;

        spin_lock(&OPQ.lock);
        OPQ.write_from = TAILQ_NEXT(OPQ.write_from, list);
    }
    return 0;
}

static int __flush_operations(void) {
    struct page_operation *pgop;
    int err = 0;

    while (OPQ.flush_till && OPQ.write_from == NULL) {
        if (OPQ.page == NULL) {
            OPQ.flush_till = NULL;
            break;
        }
        pgop = page_head_pgop(OPQ.page);
        assert(pgop);
        if (pgop->op->seqno <= OPQ.flush_till->seqno) {
            spin_unlock(&OPQ.lock);
            if (!(err = page_flush(OPQ.page))) {
                OPQ.page = NULL;
                spin_lock(&OPQ.lock);
            } else {
                OPQ.error_cb(err);
                break;
            }
        } else {
            assert(pgop->op->seqno < OPQ.seqno);
            OPQ.flush_till = NULL;
            break;
        }
    }
    return err;
}

static void __truncate_operations(void) {
    struct operation *op;
    struct page_operation *pgop;

    while ((op = __op_queue_can_be_truncated())) {
        if (op == OPQ.flush_till) {
            OPQ.flush_till = NULL;
        }
        TAILQ_REMOVE(&OPQ.queue, op, list);
        spin_unlock(&OPQ.lock);
        while ((pgop = TAILQ_FIRST(&op->page_ops))) {
            TAILQ_REMOVE(&op->page_ops, pgop, op_list);
            pgop->removed = 1;
        }
        page_queue_truncate();
        spin_lock(&OPQ.lock);
    }
}

static void *__wal_operations_bg(void *arg) {
    struct operation *truncate_op;
    int err;

    spin_lock(&OPQ.lock);
    while (1) {
        while (!OPQ.write_from && !OPQ.flush_till &&
               !__op_queue_can_be_truncated()) {
            wq_wait(&OPQ.cond, &OPQ.lock);
        }
        err = __write_operations();
        if (err) {
            spin_lock(&OPQ.lock);
        }
        err = __flush_operations();
        if (err) {
            spin_lock(&OPQ.lock);
        }
        __truncate_operations();
    }
}

struct operation *op_enqueue(void *op_buf, u16 len) {
    struct operation *op = NULL;
    struct operation *prev;
    int err;

    if ((op = umem_calloc(1, sizeof(struct operation) +
                                 sizeof(struct page_operation))) == NULL) {
        return NULL;
    }

    op->buf = op_buf;
    op->len = len;
    op->flushes_pending = 1;

    op->__page_ops[0].op = op;
    op->__page_ops[0].buf = op_buf;
    op->__page_ops[0].len = len;
    TAILQ_INIT(&op->page_ops);
    TAILQ_INSERT_TAIL(&op->page_ops, &op->__page_ops[0], op_list);
    spin_lock(&OPQ.lock);
    if ((prev = TAILQ_LAST(&OPQ.queue, operation_list)) &&
        prev->flushes_pending) {
        op->flushes_pending++;
    }
    op->seqno = OPQ.seqno++;
    TAILQ_INSERT_TAIL(&OPQ.queue, op, list);
    if (OPQ.write_from == NULL) {
        OPQ.write_from = op;
        wq_signal(&OPQ.cond);
    }
    spin_unlock(&OPQ.lock);
    return op;
}

int op_sync(struct operation *op) {
    wait_queue_t cond = WQ_INITIALIZER;

    if (op->flushes_pending == 0) {
        return 0;
    }
    spin_lock(&OPQ.lock);
    if (op->flushes_pending == 0) {
        spin_unlock(&OPQ.lock);
        return 0;
    }
    op->flush_cond = &cond;
    if (OPQ.flush_till == NULL || op->seqno > OPQ.flush_till->seqno) {
        OPQ.flush_till = op;
        wq_signal(&OPQ.cond);
    }
    while (op->flushes_pending) {
        wq_wait(&cond, &OPQ.lock);
    }
    spin_unlock(&OPQ.lock);
    return 0;
}

int op_dequeue(struct operation *op) {
    int err;

    if (op->flushes_pending) {
        err = op_sync(op);
        if (err) {
            return err;
        }
    }
    assert(op->flushes_pending == 0);

    spin_lock(&OPQ.lock);
    op->removed = 1;
    if (op == TAILQ_FIRST(&OPQ.queue) && op->flushes_pending == 0) {
        wq_signal(&OPQ.cond);
    }
    spin_unlock(&OPQ.lock);
    return 0;
}

void __exit_op_queue(void) {
    pthread_mutex_destroy(&OPQ.lock);
    pthread_cond_destroy(&OPQ.cond);
}

int __init_op_queue(op_queue_error_cb_t err_cb) {
    spin_lock_init(&OPQ.lock);
    wq_init(&OPQ.cond);
    OPQ.error_cb = err_cb;
    OPQ.seqno = 1;
    TAILQ_INIT(&OPQ.queue);
    if (pthread_create(&OPQ.thread, NULL, __wal_operations_bg, NULL)) {
        return -1;
    }
    return 0;
}
