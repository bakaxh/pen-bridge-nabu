/*
 * Minimal eBPF feasibility probe for the nabu bridge on a kernel without
 * kprobes: attach a BPF_PROG_TYPE_TRACEPOINT program to spi:spi_transfer_stop
 * and, for 81-byte transfers (the NT36523 touch report read), dump the report
 * format byte (point_data[66] = rbuf[67]) and barrel-button byte
 * (point_data[77] = rbuf[78]) via bpf_trace_printk into the global tracing
 * buffer. Read results with:
 *   cat /sys/kernel/tracing/trace
 *
 * Usage: bpf_test <tracepoint_id> <seconds>
 * The tracepoint id comes from /sys/kernel/tracing/events/spi/spi_transfer_stop/id.
 *
 * Build:
 *   zig cc -target aarch64-linux-musl -static -O2 -std=c11 -Wall -Wextra bpf_test.c -o bpf_test
 *
 * This is a diagnostic tool; it never writes kernel memory.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NR_BPF 280L            /* __NR_bpf on aarch64 */
#define NR_PERF 241L           /* __NR_perf_event_open on aarch64 */

#define BPF_PROG_LOAD 5
#define BPF_PROG_TYPE_TRACEPOINT 5

/* bpf instruction opcodes */
#define OP_MOV64_REG 0xbf
#define OP_MOV64_IMM 0xb7
#define OP_ADD64_IMM 0x07
#define OP_CALL 0x85
#define OP_JNE_IMM 0x55
#define OP_JEQ_IMM 0x15
#define OP_LDXW 0x61
#define OP_LDXDW 0x79
#define OP_LDXB 0x71
#define OP_STW_IMM 0x62
#define OP_EXIT 0x95

#define HELPER_PROBE_READ 4
#define HELPER_TRACE_PRINTK 6

struct bpf_insn {
    uint8_t code;
    uint8_t dst_reg : 4;
    uint8_t src_reg : 4;
    int16_t off;
    int32_t imm;
};

struct bpf_attr_prog {
    uint32_t prog_type;
    uint32_t insn_cnt;
    uint64_t insns;
    uint64_t license;
    uint32_t log_level;
    uint32_t log_size;
    uint64_t log_buf;
    uint32_t kern_version;
    uint32_t prog_flags;
};

struct perf_attr {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;
    /* PERF_ATTR_SIZE_VER0 == 64 */
    uint8_t pad[24];
};

static struct bpf_insn prog[64];
static int pc;
static int jumps[16];
static int jump_count;
static int exit_index;

static void emit(uint8_t code, uint8_t dst, uint8_t src, int16_t off, int32_t imm) {
    prog[pc].code = code;
    prog[pc].dst_reg = dst & 0x0f;
    prog[pc].src_reg = src & 0x0f;
    prog[pc].off = off;
    prog[pc].imm = imm;
    pc++;
}

static void mark_jump(void) { jumps[jump_count++] = pc; emit(OP_JNE_IMM, 0, 0, 0, 0); }

static void build(void) {
    pc = 0;
    jump_count = 0;

    /* read ctx->len (record offset 24); keep only 81-byte transfers */
    emit(OP_MOV64_REG, 6, 1, 0, 0);
    emit(OP_MOV64_REG, 1, 10, 0, 0);          /* dst = fp-4 */
    emit(OP_ADD64_IMM, 1, 0, 0, -4);
    emit(OP_MOV64_IMM, 2, 0, 0, 4);           /* size */
    emit(OP_MOV64_REG, 3, 6, 0, 0);           /* src = ctx+24 */
    emit(OP_ADD64_IMM, 3, 0, 0, 24);
    emit(OP_CALL, 0, 0, 0, HELPER_PROBE_READ);
    mark_jump();
    emit(OP_LDXW, 1, 10, -4, 0);
    /* diagnostic: log every transfer length */
    emit(OP_MOV64_REG, 3, 10, 0, 0);
    emit(OP_ADD64_IMM, 3, 0, 0, -4);
    emit(OP_STW_IMM, 10, 0, -64, 0x3d6c0a78); /* "l=\n" + pad */
    emit(OP_MOV64_REG, 1, 10, 0, 0);
    emit(OP_ADD64_IMM, 1, 0, 0, -64);
    emit(OP_MOV64_IMM, 2, 0, 0, 4);
    emit(OP_CALL, 0, 0, 0, HELPER_TRACE_PRINTK);
    emit(OP_LDXW, 1, 10, -4, 0); /* reload len (clobbered by printk) */
    emit(OP_JNE_IMM, 1, 0, 0, 81); jumps[jump_count++] = pc - 1;

    /* xfer = ctx->xfer (record offset 16) */
    emit(OP_MOV64_REG, 1, 10, 0, 0);
    emit(OP_ADD64_IMM, 1, 0, 0, -16);
    emit(OP_MOV64_IMM, 2, 0, 0, 8);
    emit(OP_MOV64_REG, 3, 6, 0, 0);
    emit(OP_ADD64_IMM, 3, 0, 0, 16);
    emit(OP_CALL, 0, 0, 0, HELPER_PROBE_READ);
    mark_jump();
    emit(OP_LDXDW, 7, 10, -16, 0);
    emit(OP_JEQ_IMM, 7, 0, 0, 0); jumps[jump_count++] = pc - 1;

    /* rbuf = xfer->rx_buf (struct spi_transfer offset 8 on 4.14) */
    emit(OP_ADD64_IMM, 7, 0, 0, 8);
    emit(OP_MOV64_REG, 1, 10, 0, 0);
    emit(OP_ADD64_IMM, 1, 0, 0, -16);
    emit(OP_MOV64_IMM, 2, 0, 0, 8);
    emit(OP_MOV64_REG, 3, 7, 0, 0);
    emit(OP_CALL, 0, 0, 0, HELPER_PROBE_READ);
    mark_jump();
    emit(OP_LDXDW, 8, 10, -16, 0);
    emit(OP_JEQ_IMM, 8, 0, 0, 0); jumps[jump_count++] = pc - 1;

    /* dump rbuf[66..73] as two words */
    emit(OP_ADD64_IMM, 8, 0, 0, 66);
    emit(OP_MOV64_REG, 1, 10, 0, 0);
    emit(OP_ADD64_IMM, 1, 0, 0, -16);
    emit(OP_MOV64_IMM, 2, 0, 0, 8);
    emit(OP_MOV64_REG, 3, 8, 0, 0);
    emit(OP_CALL, 0, 0, 0, HELPER_PROBE_READ);
    mark_jump();
    emit(OP_LDXW, 3, 10, -16, 0);
    emit(OP_LDXW, 4, 10, -12, 0);
    emit(OP_STW_IMM, 10, 0, -64, 0x78253d41); /* "A=%x" */
    emit(OP_STW_IMM, 10, 0, -60, 0x0a782520); /* " %x\n" */
    emit(OP_MOV64_REG, 1, 10, 0, 0);
    emit(OP_ADD64_IMM, 1, 0, 0, -64);
    emit(OP_MOV64_IMM, 2, 0, 0, 8);
    emit(OP_CALL, 0, 0, 0, HELPER_TRACE_PRINTK);

    /* dump rbuf[74..81] as two words */
    emit(OP_ADD64_IMM, 8, 0, 0, 74);
    emit(OP_MOV64_REG, 1, 10, 0, 0);
    emit(OP_ADD64_IMM, 1, 0, 0, -16);
    emit(OP_MOV64_IMM, 2, 0, 0, 8);
    emit(OP_MOV64_REG, 3, 8, 0, 0);
    emit(OP_CALL, 0, 0, 0, HELPER_PROBE_READ);
    mark_jump();
    emit(OP_LDXW, 3, 10, -16, 0);
    emit(OP_LDXW, 4, 10, -12, 0);
    emit(OP_STW_IMM, 10, 0, -64, 0x78253d42); /* "B=%x" */
    emit(OP_STW_IMM, 10, 0, -60, 0x0a782520); /* " %x\n" */
    emit(OP_MOV64_REG, 1, 10, 0, 0);
    emit(OP_ADD64_IMM, 1, 0, 0, -64);
    emit(OP_MOV64_IMM, 2, 0, 0, 8);
    emit(OP_CALL, 0, 0, 0, HELPER_TRACE_PRINTK);

    emit(OP_MOV64_IMM, 0, 0, 0, 0);
    exit_index = pc;
    emit(OP_EXIT, 0, 0, 0, 0);

    for (int i = 0; i < jump_count; i++) prog[jumps[i]].off = (int16_t)(exit_index - jumps[i] - 1);
}

static long bpf(int cmd, void *attr) { return syscall(NR_BPF, cmd, attr, sizeof(struct bpf_attr_prog)); }

static char log_buf[1 << 16];

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: bpf_test <tracepoint_id> <seconds> [perf_type] [perf_config] [pid]\n"); return 2; }
    long tp_id = strtol(argv[1], NULL, 10);
    int seconds = atoi(argv[2]);
    long perf_type = argc > 3 ? strtol(argv[3], NULL, 10) : 3;
    long perf_config = argc > 4 ? strtol(argv[4], NULL, 10) : tp_id;
    long pid = argc > 5 ? strtol(argv[5], NULL, 10) : -1;
    long cpu = argc > 6 ? strtol(argv[6], NULL, 10) : -1;

    build();
    static const char license[] = "GPL";

    struct bpf_attr_prog attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    attr.insn_cnt = (uint32_t)pc;
    attr.insns = (uint64_t)(uintptr_t)prog;
    attr.license = (uint64_t)(uintptr_t)license;
    attr.log_level = 1;
    attr.log_size = sizeof(log_buf);
    attr.log_buf = (uint64_t)(uintptr_t)log_buf;

    long fd = bpf(BPF_PROG_LOAD, &attr);
    if (fd < 0) {
        fprintf(stderr, "bpf prog load failed: %s\nlog:\n%s\n", strerror(errno), log_buf);
        return 1;
    }
    printf("prog loaded (%d insns)\n", pc);

    struct perf_attr pa;
    memset(&pa, 0, sizeof(pa));
    pa.type = (uint32_t)perf_type;
    pa.size = sizeof(pa);
    pa.config = (uint64_t)perf_config;
    pa.flags = 1; /* disabled */

    long pfd = syscall(NR_PERF, &pa, pid, cpu, -1L, 0L);
    if (pfd < 0) { fprintf(stderr, "perf_event_open failed: %s (type=%ld config=%ld pid=%ld cpu=%ld)\n", strerror(errno), perf_type, perf_config, pid, cpu); return 1; }
    printf("perf event open ok (type=%ld config=%ld pid=%ld cpu=%ld)\n", perf_type, perf_config, pid, cpu);

    if (ioctl((int)pfd, 0x40042408 /* PERF_EVENT_IOC_SET_BPF */, (void *)(uintptr_t)fd) < 0) {
        fprintf(stderr, "SET_BPF failed: %s\n", strerror(errno));
        return 1;
    }
    if (ioctl((int)pfd, 0x2400 /* PERF_EVENT_IOC_ENABLE */, 0) < 0) {
        fprintf(stderr, "ENABLE failed: %s\n", strerror(errno));
        return 1;
    }
    printf("listening %d s; write pen reports now; then: cat /sys/kernel/tracing/trace\n", seconds);
    sleep((unsigned)seconds);
    ioctl((int)pfd, 0x2401 /* DISABLE */, 0);
    printf("done\n");
    return 0;
}
