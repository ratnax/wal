#include <stdint.h>
#include <sys/types.h>

#include "io_uring.h"
#include "wal.h"
#define NT 16
uint64_t ops_count;
uint64_t thread_TP[NT];
uint64_t thread_iops[NT];
void *TP(void *arg) {
    u64 ops_now = 0;
    u64 ops_now1 = 0;
    u64 ops_before = 0;
    u64 ops_before1 = 0;

    u64 pages_written;
    u64 pages_committed;
    u64 waste_io;
    u64 ops_written;
    u64 pages_inio;
    u64 pages_inio_samples;

    u64 pages_written_before = 0;
    u64 pages_committed_before = 0;
    u64 waste_io_before = 0;
    u64 ops_written_before = 0;
    u64 pages_inio_before = 0;
    u64 pages_inio_samples_before = 0;

    extern void page_queue_stats(u64 * pages_written, u64 * pages_committed,
        u64 * waste_io, u64 * ops_written, u64 * pages_inio,
        u64 * pages_inio_samples);

    int i;
    while (1) {
        ops_now = 0;
        ops_now1 = 0;
        for (i = 0; i < NT; i++) {
            ops_now += thread_TP[i];
            ops_now1 += thread_iops[i];
        }
        page_queue_stats(&pages_written, &pages_committed, &waste_io,
            &ops_written, &pages_inio, &pages_inio_samples);

        printf(
            "\r%ju MB/sec %ju IOPS %ju backend MB/sec  %ju MB/sec wasted %f "
            "ops/page %f ioqsz",

            (ops_now - ops_before) >> 20, ops_now1 - ops_before1,
            ((pages_committed - pages_committed_before) * 4) / 1024,
            (waste_io - waste_io_before) >> 20,
            (float)(ops_written - ops_written_before) /
                (pages_committed - pages_committed_before),
            (float)(pages_inio - pages_inio_before) /
                (pages_inio_samples - pages_inio_samples_before));
        fflush(stdout);
        sleep(1);
        ops_before = ops_now;
        ops_before1 = ops_now1;
        pages_written_before = pages_written;
        pages_committed_before = pages_committed;
        waste_io_before = waste_io;
        ops_written_before = ops_written;
        pages_inio_before = pages_inio;
        pages_inio_samples_before = pages_inio_samples;
    }
}
#include <stdio.h>

void *run(void *arg) {
    unsigned long thread_id = (unsigned long)arg;
    wal_operation_t *op;
    void *operation = malloc(1024);
#define TXSZ 1
    struct operation *ops[TXSZ];
    int i;
    int j = 0;

    memset(ops, 0, sizeof(ops));
    while (1) {
        int len = 128;  // random() % 1024 + 1;
        memset(operation, 'A' + i, len);
        if (ops[j]) {
            wal_dequeue(ops[j]);
        }

        if (NULL == (op = wal_enqueue(operation, len))) {
            return NULL;
        }

        usleep(1000);
        ops[j] = op;
        j = (j + 1) % TXSZ;
        i = (i + 1) % 26;
        if (len % 10 == 0) {
            wal_sync(op);
            // wal_remove(op);
        }
        thread_TP[thread_id] += len;
        thread_iops[thread_id]++;
    }
}

void __cyg_profile_func_enter(void *func, void *caller)
    __attribute__((no_instrument_function));
void __cyg_profile_func_exit(void *func, void *caller)
    __attribute__((no_instrument_function));
#if 0
void __cyg_profile_func_enter(void *this, void *callsite) {
    /* Function Entry Address */
    fprintf(stdout, "E%p\n", (int *)this);
}

void __cyg_profile_func_exit(void *this, void *callsite) {
    /* Function Exit Address */
    fprintf(stdout, "X%p\n", (int *)this);
}
#endif
#define _GNU_SOURCE
#include <dlfcn.h>
struct xxx {
    void *func;
    void *caller;
    u64 stime;
    u64 etime;
} __attribute__((packed));

__thread struct xxx *xxx;
__thread int nxxx;
struct xxx *addresses[1024];
int count;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
void *base;
void __cyg_profile_func_enter(void *func, void *caller) {
    if (xxx == NULL) {
        xxx = calloc(1024 * 1024, sizeof(struct xxx));
        assert(xxx);
        pthread_mutex_lock(&lock);
        addresses[count++] = xxx;
        pthread_mutex_unlock(&lock);
        nxxx = 0;
    }
    xxx[nxxx].func = func;
    xxx[nxxx].caller = caller;
    xxx[nxxx].stime = __builtin_ia32_rdtsc();
    nxxx++;
    if (nxxx == 1024 * 1024) {
        int i, j;
        for (j = 0; j < count; j++) {
            for (i = 0; i < 1024 * 1024; i++) {
                if (addresses[j][i].func == 0)
                    break;
                printf("%d %s %jx %jx %ju\n", j,
                    addresses[j][i].stime ? "S" : "E",
                    addresses[j][i].func - base, addresses[j][i].caller - base,
                    addresses[j][i].stime ?: addresses[j][i].etime);
            }
        }
        exit(0);
    }

    /*
    Dl_info info;
    if (dladdr(func, &info) && info.dli_sname) {
        printf("Entering function: %s\n", info.dli_sname);
    } else {
        printf("Entering function at address: %p\n", func);
    }
    */
}

void __cyg_profile_func_exit(void *func, void *caller) {
    xxx[nxxx].func = func;
    xxx[nxxx].caller = caller;
    xxx[nxxx].etime = __builtin_ia32_rdtsc();
    nxxx++;
    if (nxxx == 1024 * 1024) {
        int i, j;
        for (j = 0; j < count; j++) {
            for (i = 0; i < 1024 * 1024; i++) {
                if (addresses[j][i].func == 0)
                    break;
                printf("%d %s %jx %jx %ju\n", j,
                    addresses[j][i].stime ? "S" : "E",
                    addresses[j][i].func - base, addresses[j][i].caller - base,
                    addresses[j][i].stime ?: addresses[j][i].etime);
            }
        }
        exit(0);
    }

    /*
        Dl_info info;
        if (dladdr(func, &info) && info.dli_sname) {
            printf("Exiting function: %s\n", info.dli_sname);
        } else {
            printf("Exiting function at address: %p\n", func);
        }
        */
}

void *get_base_address(const char *module_name) {
    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        perror("fopen");
        return NULL;
    }

    void *base_address = NULL;
    char line[256];
    while (fgets(line, sizeof(line), maps_file)) {
        // Check if the line contains the module name
        if (strstr(line, module_name)) {
            // The base address is at the beginning of the line
            sscanf(line, "%lx-", &base_address);
            break;
        }
    }

    fclose(maps_file);
    return base_address;
}

int main() {
    int ret;
    void *operation = malloc(1024);
    struct operation *op;
    int count = 0;
    pthread_t page_flusher;
    pthread_t op_writer;
    int i = 0;
    pthread_t appender[NT];
    pthread_t stat_thread;

    base = get_base_address("wal_test");
    __init_io_uring(8);
    __init_wal("/home/ratna/log.bin", 0, 1024 * 1024);

    pthread_create(&stat_thread, NULL, TP, NULL);
    for (i = 0; i < NT; i++) {
        pthread_create(&appender[i], NULL, run, (void *)(long)i);
    }
    for (i = 0; i < NT; i++) {
        pthread_join(appender[i], NULL);
    }

    /*
    pthread_create(&appender, NULL, run, NULL);
    pthread_create(&appender, NULL, run, NULL);
    pthread_create(&appender, NULL, run, NULL);
    pthread_create(&appender, NULL, run, NULL);
    */

    /*
    while (1) {
        int len = random() % 1024;
        memset(operation, 'A' + i, len);
        if (NULL == (op = wal_append(operation, len))) return ret;
        i = (i + 1) % 26;
    }
  */
    // pthread_join(appender, NULL);
    return 0;
}
