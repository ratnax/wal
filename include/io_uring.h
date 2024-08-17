#ifndef __IO_URING_H__
#define __IO_URING_H__
typedef void (*ioring_endio_t)(void *data, int res);
extern int io_uring_get(ioring_endio_t cb);
extern void io_uring_put(int i);

extern int io_uring_is_pending(int i); 
extern int io_uring_schedule_read(int i, int fd, void *buf, size_t len, off_t offset,
                            void *data);
extern int io_uring_schedule_write(int i, int fd, void *buf, size_t len, off_t offset,
                            void *data);
extern int io_uring_flush_pending(int i);
extern int io_uring_wait(int i);
extern void __exit_io_uring(void);
extern int __init_io_uring(int n);
#endif