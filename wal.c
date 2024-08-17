#include "wal.h"

#include "block_queue.h"
#include "op_queue.h"
#include "page_queue.h"

wal_operation_t *wal_enqueue(void *operation, u16 len) {
    return op_enqueue(operation, len);
}
int wal_dequeue(wal_operation_t *op) {
    return op_dequeue(op);
}
int wal_sync(wal_operation_t *op) {
    return op_sync(op);
}
void __exit_wal(void) {
    __exit_op_queue();
    __exit_page_queue();
    __exit_block_queue();
}
void __wal_error_cb(int err) {
    // assert(0);
    printf("Error from wal: %d\n", err);
    sleep(60);
}
int __init_wal(const char *path, u64 off, u64 len) {
    int err;

    if ((err = __init_block_queue(path, off, len))) {
        return err;
    }
    if ((err = __init_page_queue())) {
        return err;
    }
    if ((err = __init_op_queue(__wal_error_cb))) {
        return err;
    }
    return 0;
}
