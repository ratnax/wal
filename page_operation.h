#ifndef __page_OPERATION_H__
#define __page_OPERATION_H__
struct page;
struct operation;
struct page_operation {
    struct page *page;
    struct operation *op;
    u16 page_offset;
    void *buf;
    u16 len;
    u8 removed : 1;
    u8 malloced : 1;
    u8 flags : 7;
    TAILQ_ENTRY(page_operation) op_list;
    TAILQ_ENTRY(page_operation) page_list;
};
typedef TAILQ_HEAD(page_operation_list, page_operation) page_operation_list_t;
extern void operation_endio(struct operation *op);
extern bool operation_pgop_malloced(struct operation *op,
    struct page_operation *pgop);
#endif
