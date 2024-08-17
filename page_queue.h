#ifndef __WAL_PAGE_H__
#define __WAL_PAGE_H__
#include "page_operation.h"
struct page;
extern struct page *page_queue_next();
extern u16 page_space_available(struct page *page);
extern int page_write_partial(struct page *page, struct page_operation *pgop);
extern int page_write_final(struct page *page, struct page_operation *pgop);
extern int page_flush(struct page *page);
extern void page_queue_truncate(void);
extern struct page_operation *page_head_pgop(struct page *page);
extern int __init_page_queue(void);
extern void __exit_page_queue(void);
#endif
