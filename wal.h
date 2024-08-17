#ifndef __WAL_H__
#define __WAL_H__
typedef struct operation wal_operation_t;
extern wal_operation_t *wal_enqueue(void *operation, u16 len);
extern int wal_dequeue(wal_operation_t *op);
extern int wal_sync(wal_operation_t *op);
extern void __exit_wal(void);
extern int __init_wal(const char *path, u64 off, u64 len);
#endif // __WAL_H__