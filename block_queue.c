#include "block_queue.h"
#include "include/global.h"
#include "spin_lock.h"
#include "umem.h"

struct block {
    struct {
        int fd;
        u64 off;
        u64 len;
        ino_t ino;
    } dev;
    struct {
        u32 inuse;
        u32 total;
    } pages;
    TAILQ_ENTRY(block) list;
};

typedef TAILQ_HEAD(, block) block_list_t;
static struct block_queue {
    struct block_queue_cursor head;
    struct block_queue_cursor tail;
    block_list_t list;
    spinlock_t lock;
    struct {
        u32 inuse;
        u32 total;
    } pages;
} BQ;

static void __block_mem_free(struct block *block) {
    assert(block->pages.inuse);
    spin_lock(&BQ.lock);
    BQ.pages.total -= block->pages.total;
    TAILQ_REMOVE(&BQ.list, block, list);
    close(block->dev.fd);
    umem_free(block);
    spin_unlock(&BQ.lock);
}

static struct block *__block_mem_alloc(void) {
    struct block *block = NULL;

    block = umem_malloc(sizeof(struct block));
    if (!block) {
        return NULL;
    }

    block->dev.fd = -1;
    block->dev.off = 0;
    block->dev.len = 0;
    block->dev.ino = 0;
    block->pages.inuse = 0;
    block->pages.total = 0;

    return block;
}

int block_queue_add(const char *device, u64 off, u64 size) {
    struct block *block = NULL;
    int fd = -1;
    struct stat st;
    int err = 0;

    if (NULL == (block = __block_mem_alloc())) {
        err = -ENOMEM;
        goto err;
    }

    if (0 > (fd = open(device, O_RDWR | O_DIRECT))) {
        err = -errno;
        umem_free(block);
        goto err;
    }

    block->dev.fd = fd;
    block->dev.off = off;
    block->dev.len = size;
    block->pages.inuse = 0;
    block->pages.total = size >> PAGE_SHFT;

    spin_lock(&BQ.lock);
    if (BQ.pages.total == 0) {
        BQ.pages.total = block->pages.total;
        TAILQ_INSERT_TAIL(&BQ.list, block, list);
        BQ.tail.block = BQ.head.block = TAILQ_FIRST(&BQ.list);
        BQ.tail.page_no = BQ.head.page_no = block->dev.off >> PAGE_SHFT;
    } else {
        if (BQ.head.block == BQ.tail.block) {
            spin_unlock(&BQ.lock);
            err = -EBUSY;
            goto err;
        }
        BQ.pages.total += block->pages.total;
        TAILQ_INSERT_AFTER(&BQ.list, BQ.head.block, block, list);
    }
    spin_unlock(&BQ.lock);
    return 0;
err:
    if (fd >= 0) {
        close(fd);
    }
    if (block) {
        umem_free(block);
    }
    return err;
}

void block_queue_page_free(struct block *block, u64 page_no) {
    spin_lock(&BQ.lock);
    assert(BQ.tail.block == block && BQ.tail.page_no == page_no);
    block->pages.inuse--;
    BQ.pages.inuse--;
    BQ.tail.page_no += 1;
    if (BQ.tail.page_no == BQ.tail.block->pages.total) {
        if (BQ.pages.inuse == 0) {
            BQ.tail.block = BQ.head.block;
            BQ.tail.page_no = BQ.head.page_no;
        } else if (block->pages.inuse == 0) {
            BQ.tail.block = TAILQ_NEXT(block, list);
            BQ.tail.page_no = 0;
        } else {
            assert(block->pages.inuse == BQ.pages.inuse);
            BQ.tail.page_no = 0;
        }
    }
    spin_unlock(&BQ.lock);
}

struct block_queue_cursor block_queue_page_alloc(void) {
    struct block_queue_cursor cur;
    struct block *block;
    s64 pgno;

    spin_lock(&BQ.lock);
    if (BQ.pages.inuse == BQ.pages.total) {
        spin_unlock(&BQ.lock);
        cur.block = ERR_PTR(ENOSPC);
        cur.page_no = -1ULL;
        return cur;
    }
    cur.block = BQ.head.block;
    cur.block->pages.inuse++;
    BQ.pages.inuse++;
    cur.page_no = BQ.head.page_no;
    if (cur.block->pages.inuse == cur.block->pages.total) {
        BQ.head.block = TAILQ_NEXT(cur.block, list);
        BQ.head.page_no = 0;
    } else {
        BQ.head.page_no = (BQ.head.page_no + 1) % cur.block->pages.total;
    }
    spin_unlock(&BQ.lock);
    return cur;
}

int block_file_descriptor(struct block *block) {
    return block->dev.fd;
}
int block_page_offset(struct block *block, u64 pgno) {
    return block->dev.off + (pgno << PAGE_SHFT);
}
void __exit_block_queue(void) {
    struct block *block = NULL;
    struct block *tmp = NULL;

    spin_lock(&BQ.lock);
    TAILQ_FOREACH_SAFE(block, &BQ.list, list, tmp) {
        TAILQ_REMOVE(&BQ.list, block, list);
        close(block->dev.fd);
        umem_free(block);
    }
    spin_unlock(&BQ.lock);
}

int __init_block_queue(const char *dev, u64 off, u64 len) {
    spin_lock_init(&BQ.lock);
    TAILQ_INIT(&BQ.list);
    BQ.pages.inuse = 0;
    BQ.pages.total = 0;
    return block_queue_add(dev, off, len);
}
