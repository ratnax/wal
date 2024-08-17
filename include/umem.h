#ifndef __UMEM_H__
#define __UMEM_H__
static void *umem_malloc(size_t size) {
    return malloc(size);
}
static void *umem_calloc(int n, size_t size) {
    return calloc(n, size);
}
static void *umem_aligned_alloc(size_t size, size_t align) {
    return aligned_alloc(align, size);
}
static void umem_free(void *ptr) {
    free(ptr);
}
#endif
