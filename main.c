// file: main.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "main.skel.h"
#include "main.h"

void handle_event(void *ctx, int cpu, void *data, __u32 data_size) {
    struct data_t *event = (struct data_t*) data;

    if (event->op_code == 3) {
        printf("Event Received:\n");
        printf("\t newname: %s\n", event->newpath);
        printf("\t PID: %d\n", event->pid);
        printf("\t UID: %d\n", event->uid);
        printf("\t op code: %d\n", event->op_code);
        printf("\t ax: %ld\n", event->ax);
        printf("\t cx: %ld\n", event->cx);
        printf("\t dx: %ld\n", event->dx);
        printf("\t si: %ld\n", event->si);
        printf("\t di: %ld\n", event->di);
    }

    
}

void handle_sigint(int sig) {
    printf("Terminating\n");
    exit(0);
}

static int libbpf_print(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG || level == LIBBPF_INFO)
        return 0;
    return vfprintf(stderr, format, args);
}


int main(int argc, char *argv[]) {
    struct main_bpf *skel;
    struct perf_buffer_opts pb_opts;
    struct perf_buffer *pb = NULL;
    int err;

    // Set up signal handler to exit
    signal(SIGINT, handle_sigint);

    // Initialize libbpf
    libbpf_set_print(libbpf_print);

    // Load and verify BPF application
    skel = main_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Attach kprobe
    err = main_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    // Set up perf buffer
    pb_opts.sample_cb = handle_event;
    pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 512, &pb_opts);
    if (libbpf_get_error(pb)) {
        pb = NULL;
        fprintf(stderr, "Failed to open perf buffer\n");
        goto cleanup;
    }

    printf("Successfully started! Please Ctrl+C to stop.\n");

    // Poll the perf buffer
    while (1) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(pb);
    main_bpf__destroy(skel);
    return 0;
}
