#ifndef __WAL_OP_QUEUE_H__
#define __WAL_OP_QUEUE_H__
struct operation;
struct page_operation;
typedef void (*op_queue_error_cb_t)(int err);
extern struct operation *op_enqueue(void *operation, u16 len);
extern int op_dequeue(struct operation *op);
extern int op_sync(struct operation *op);
extern bool operation_pgop_malloced(struct operation *op, struct page_operation *pgop);
extern int __init_op_queue(op_queue_error_cb_t error_cb);
extern void __exit_op_queue(void);
#endif // __WAL_OP_QUEUE_H__