#include <liburing.h>

#include "block_queue.h"
#include "include/io_uring.h"
#include "page_operation.h"
#include "spin_lock.h"
#include "umem.h"
#include "wait.h"

#define RECORD_MAGIC (*(u64 *)"DWALRECB")
static u64 wal_seqno = 0;

struct page {
    struct block *block;
    u64 pgno;
    void *buf;
    u16 write_offset;
    u16 commit_offset;
    u16 inio : 1;
    u16 flags : 7;
    TAILQ_ENTRY(page) list;
    page_operation_list_t ops;
    struct page_operation *head_pgop;
};

typedef TAILQ_HEAD(page_list, page) page_list_t;
struct page_queue {
    struct page *page;
    struct page *next_page;
    page_list_t page_list;
    spinlock_t lock;
    wait_queue_t cond;
    int io_uring_idx;
    pthread_t thread;
    u64 waste_io;
    u64 pages_written;
    u64 pages_committed;
    u64 ops_written;
    u64 pages_inio;
    u64 pages_inio_samples;
} PQ;

struct record_hdr {
    u64 magic;
    u64 lsn;
    u16 len;
    u8 data[0];
} __attribute__((packed));

struct record_tlr {
    u32 crc;
} __attribute__((packed));

#define __is_page_full_and_committed(page) \
    ((page)->inio == false && (page)->commit_offset == PAGE_SIZE)
#define __is_page_full(page) ((page)->write_offset == PAGE_SIZE)
#define __is_page_inio(page) ((page)->inio)

static struct page *__page_malloc(struct block *block, u64 page_no) {
    struct page *page = umem_malloc(sizeof(struct page));
    if (NULL == page) {
        return NULL;
    }
    page->buf = umem_aligned_alloc(4096, PAGE_SIZE);
    if (NULL == page->buf) {
        umem_free(page);
        return NULL;
    }
    TAILQ_INIT(&page->ops);
    page->block = block;
    page->pgno = page_no;
    page->write_offset = 0;
    page->commit_offset = 0;
    page->inio = 0;
    page->flags = 0;
    return page;
}
static int __pages_grow(void) {
    struct page *page = NULL;
    int err;
    struct block_queue_cursor cur = block_queue_page_alloc();
    if (IS_ERR(cur.block)) {
        return PTR_ERR(cur.block);
    }
    if ((page = __page_malloc(cur.block, cur.page_no)) == NULL) {
        return -ENOMEM;
    }
    spin_lock(&PQ.lock);
    if (PQ.next_page == NULL)
        PQ.next_page = page;
    TAILQ_INSERT_TAIL(&PQ.page_list, page, list);
    spin_unlock(&PQ.lock);
    return 0;
}

static void __page_free(struct page *page) {
    block_queue_page_free(page->block, page->pgno);
    umem_free(page->buf);
    umem_free(page);
}

struct page *page_queue_next(void) {
    struct page *page;
    int err;
retry:
    spin_lock(&PQ.lock);
    while (PQ.next_page && __is_page_full(PQ.next_page)) {
        PQ.next_page = TAILQ_NEXT(PQ.next_page, list);
    }
    page = PQ.next_page;
    while (page && (__is_page_inio(page) || __is_page_full(page))) {
        page = TAILQ_NEXT(page, list);
    }
    if (!page) {
        spin_unlock(&PQ.lock);
        err = __pages_grow();
        if (err) {
            return ERR_PTR(err);
        }
        goto retry;
    } else {
        spin_unlock(&PQ.lock);
    }
    return page;
}

int page_space_available(struct page *page) {
    assert(page->write_offset >= page->commit_offset);
    assert(page->inio == false);
    if (page->commit_offset == page->write_offset) {
        assert(PAGE_SIZE - page->write_offset >
               sizeof(struct record_hdr) + sizeof(struct record_tlr));
        return PAGE_SIZE - page->write_offset - sizeof(struct record_hdr) -
               sizeof(struct record_tlr);
    } else {
        assert(PAGE_SIZE - page->write_offset > sizeof(struct record_tlr));
        return PAGE_SIZE - page->write_offset - sizeof(struct record_tlr);
    }
}

static void __update_stats_endio(u16 waste_io, u16 ops_written) {
    PQ.waste_io += waste_io;
    PQ.ops_written += ops_written;
    PQ.pages_committed++;
    PQ.pages_inio += PQ.pages_written - PQ.pages_committed;
    PQ.pages_inio_samples++;
}

static void __update_stats_doio(void) {
    PQ.pages_written++;
    PQ.pages_inio += PQ.pages_written - PQ.pages_committed;
    PQ.pages_inio_samples++;
}

void page_queue_stats(u64 *pages_written, u64 *pages_committed, u64 *waste_io,
    u64 *ops_written, u64 *pages_inio, u64 *pages_inio_samples) {
    spin_lock(&PQ.lock);
    *pages_written = PQ.pages_written;
    *pages_committed = PQ.pages_committed;
    *waste_io = PQ.waste_io;
    *ops_written = PQ.ops_written;
    *pages_inio = PQ.pages_inio;
    *pages_inio_samples = PQ.pages_inio_samples;
    spin_unlock(&PQ.lock);
}

static void __page_endio(void *data, int res) {
    struct page *page = (struct page *)data;
    struct page_operation *pgop, *tmp;
    u16 count = 0;
    u16 written = page->write_offset - page->commit_offset;

    assert(!TAILQ_EMPTY(&page->ops));
    assert(page->inio);

    pgop = page->head_pgop;
    do {
        assert(pgop->page_offset >= page->commit_offset);
        operation_endio(pgop->op);
        count++;
    } while ((pgop = TAILQ_NEXT(pgop, page_list)));

    spin_lock(&PQ.lock); /* handles write barrier and stats */
    page->commit_offset = page->write_offset;
    /* Make sure commit_offset is visible. Using OPQ.lock. */
    // spinlock takes care of write barrier __sync_synchronize();
    page->inio = 0;
    __update_stats_endio(PAGE_SIZE - written, count);
    spin_unlock(&PQ.lock);
}

static int __schedule_write(struct page *page) {
    spin_lock(&PQ.lock); /* Not needed unless for stats */
    page->inio = 1;
    __update_stats_doio();
    spin_unlock(&PQ.lock);

    int ret = io_uring_schedule_write(PQ.io_uring_idx,
        block_file_descriptor(page->block), page->buf, PAGE_SIZE,
        block_page_offset(page->block, page->pgno), page);
    if (ret) {
        spin_lock(&PQ.lock); /* Not needed unless for stats */
        page->inio = 0;
        __update_stats_endio(0, 0);
        spin_unlock(&PQ.lock);
        return ret;
    }
    return io_uring_flush_pending(PQ.io_uring_idx);
}

int page_write_final(struct page *page, struct page_operation *pgop) {
    struct record_hdr *hdr = page->buf + page->commit_offset;
    struct record_tlr *tlr;
    u32 crc = crc32(0L, Z_NULL, 0);

    assert(page->inio == false);
    if (page->commit_offset == page->write_offset) {
        hdr->magic = RECORD_MAGIC;
        hdr->lsn = wal_seqno++;
        hdr->len = 0;
        page->write_offset = page->commit_offset + sizeof(struct record_hdr);
        page->head_pgop = pgop;
        assert(page->write_offset <= PAGE_SIZE);
    }
    memcpy(&hdr->data[hdr->len], pgop->buf, pgop->len);

    hdr->len += pgop->len;
    tlr = (struct record_tlr *)&hdr->data[hdr->len];
    tlr->crc = crc32(crc, (void *)hdr, hdr->len + sizeof(struct record_hdr));
    pgop->page_offset = page->write_offset;
    page->write_offset = PAGE_SIZE;
    pgop->page = page;
    TAILQ_INSERT_TAIL(&page->ops, pgop, page_list);
    return __schedule_write(page);
}

int page_write_partial(struct page *page, struct page_operation *pgop) {
    struct record_hdr *hdr = page->buf + page->commit_offset;
    struct record_tlr *tlr;
    u32 crc = crc32(0L, Z_NULL, 0);

    assert(page->inio == false);
    if (page->commit_offset == page->write_offset) {
        hdr->magic = RECORD_MAGIC;
        hdr->lsn = wal_seqno++;
        hdr->len = 0;
        page->write_offset = page->commit_offset + sizeof(struct record_hdr);
        page->head_pgop = pgop;
        assert(page->write_offset <= PAGE_SIZE);
    }
    memcpy(&hdr->data[hdr->len], pgop->buf, pgop->len);
    hdr->len += pgop->len;
    pgop->page_offset = page->write_offset;
    page->write_offset += pgop->len;
    assert(page->write_offset <= PAGE_SIZE);
    pgop->page = page;
    TAILQ_INSERT_TAIL(&page->ops, pgop, page_list);
    return 0;
}

struct page_operation *page_head_pgop(struct page *page) {
    assert(page->head_pgop->page_offset >= page->commit_offset);
    return page->head_pgop;
}

int __page_flush(struct page *page, u16 offset) {
    assert(page->write_offset > page->commit_offset);
    assert(page->inio == false);
    if (offset <= page->commit_offset) {
        return 0;
    }
    if (page->inio) {
        if (offset <= page->write_offset) {
            return 0;
        }
        assert(0); /* not expected */
        return -EBUSY;
    }

    struct record_hdr *hdr = page->buf + page->commit_offset;
    struct record_tlr *tlr;
    u32 crc = crc32(0L, Z_NULL, 0);

    assert(page->write_offset >= offset);
    tlr = (struct record_tlr *)&hdr->data[hdr->len];
    tlr->crc = crc32(crc, (void *)hdr, hdr->len + sizeof(struct record_hdr));
    if (PAGE_SIZE - page->write_offset <=
        sizeof(struct record_hdr) + 2 * sizeof(struct record_tlr)) {
        page->write_offset = PAGE_SIZE;
    } else {
        page->write_offset += sizeof(struct record_tlr);
    }
    return __schedule_write(page);
}

int page_flush(struct page *page) {
    return __page_flush(page, page->write_offset);
}

void page_queue_truncate(void) {
    struct page *page;
    struct page_operation *pgop, *tmp;

    spin_lock(&PQ.lock);
    while ((page = TAILQ_FIRST(&PQ.page_list))) {
        spin_unlock(&PQ.lock);

        /* does not need to be under PQ.lock */
        if (__is_page_full_and_committed(page) == false) {
            return;
        }
        TAILQ_FOREACH_SAFE(pgop, &page->ops, page_list, tmp) {
            if (pgop->removed == 1) {
                TAILQ_REMOVE(&page->ops, pgop, page_list);
                if (pgop->malloced) {
                    umem_free(pgop);
                } else {
                    umem_free(pgop->op);
                }
            }
        }
        if (TAILQ_EMPTY(&page->ops)) {
            spin_lock(&PQ.lock);
            TAILQ_REMOVE(&PQ.page_list, page, list);
            spin_unlock(&PQ.lock);
            __page_free(page);
        } else {
            return;
        }
        spin_lock(&PQ.lock);
    }
    spin_unlock(&PQ.lock);
}
static void *endio(void *arg) {
    while (1) {
        io_uring_wait(PQ.io_uring_idx);
    }
}
void __exit_page_queue(void) {
    if (PQ.io_uring_idx >= 0) {
        io_uring_put(PQ.io_uring_idx);
    }
}
int __init_page_queue(void) {
    int err;
    int io_uring_idx = -1;

    spin_lock_init(&PQ.lock);
    TAILQ_INIT(&PQ.page_list);

    if ((PQ.io_uring_idx = io_uring_get(__page_endio)) < 0) {
        return PQ.io_uring_idx;
    }
    pthread_create(&PQ.thread, NULL, endio, NULL);
    return 0;
}
