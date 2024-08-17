#ifndef __WAL_BLOCK_QUEUE_H__
#define __WAL_BLOCK_QUEUE_H__

#define PAGE_SHFT 12
#define PAGE_SIZE (1 << PAGE_SHFT)
#define PAGE_MASK (PAGE_SIZE - 1)

struct block;
struct block_queue_cursor {
    struct block *block;
    u64 page_no;
};
extern int __init_block_queue(const char *path, u64 off, u64 len);
extern void __exit_block_queue(void);
extern int block_queue_add(const char *path, u64 off, u64 len);
extern int block_file_descriptor(struct block *block);
extern int block_page_offset(struct block *block, u64 pgno);
extern struct block_queue_cursor block_queue_page_alloc(void);
extern void block_queue_page_free(struct block *block, u64 pgno); 
#endif // __WAL_BLOCK_QUEUE_H__