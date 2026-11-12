/*
 * Third-party MPP pen barrel-button bridge for Xiaomi Pad 5 (nabu).
 *
 * The Panz ColorOS 17 kernel has no CONFIG_KPROBES, no ftrace function
 * tracer, and no CONFIG_MODULES, but it does expose the static
 * "spi:spi_transfer_stop" tracepoint and CONFIG_BPF_SYSCALL with
 * bpf_probe_read. This daemon therefore loads a hand-assembled eBPF
 * tracepoint program that watches the Novatek touch report transfer
 * (81-byte SPI read into the driver's fixed heap buffer) and copies the
 * 14 report bytes (raw SPI buffer offsets 66..79, i.e. point_data[65..78])
 * into a BPF array ring. The program only reads kernel memory and writes
 * to its own map; it never writes kernel memory and never touches
 * tracefs, so it adds a single bounded read in the SPI completion path.
 *
 * The userspace side polls the ring, applies the same frame state machine
 * as the liuqin bridge (format byte gate, pressure/distance gate, 500 ms
 * release timeout, deduplicated transitions), and injects the barrel
 * buttons as a buttons-only uinput device named
 * "Xiaomi Smart Pen Keyboard" accepted by the XiaomiSmartPenPlus module.
 *
 * Byte mapping (verified empirically on this device with full-report dumps):
 *   slot bytes[i] = rbuf[66+i] = point_data[65+i]
 *   point_data[66] = format        -> bytes[1] (1 while in range, 0xFF leaving)
 *   point_data[71..72] = pressure  -> bytes[6..7]
 *   point_data[77] = MiCode buttons-> bytes[12] (constant 0 on this firmware)
 *   barrel button                  -> bytes[11] (point_data[76]) bit --btn-bit
 *                                     (1 = a barrel button is pressed)
 * The Panz firmware does not distinguish the two physical barrel buttons:
 * both produce the same bit (verified by dumping every report byte while
 * pressing each button separately), so the bridge exposes one configurable
 * button that reports KEY_PAGEDOWN; the action is chosen in the
 * XiaomiSmartPenPlus module UI.
 *
 * Mask 2 (upper side button) -> KEY_PAGEDOWN 109 -> module button 1.
 * Mask 1 (lower side button) -> KEY_PAGEUP   104 -> module button 2.
 * No coordinate, pressure, tilt, or touch events are injected or intercepted.
 *
 * Build, for example:
 *   zig cc -target aarch64-linux-musl -static -O2 -std=c11 \
 *     -Wall -Wextra -Werror dell_pen_bridge.c -o dell_pen_bridge
 *
 * Live:
 *   dell_pen_bridge --stop-file /dev/dell_pen_bridge_nabu/stop \
 *     --status /dev/dell_pen_bridge_nabu/status.json \
 *     --lock /dev/dell_pen_bridge_nabu/native.lock \
 *     [--max-seconds N] [--upper-bit B] [--lower-bit B] [--btn-byte B]
 *
 * Analysis capture (no uinput; writes hex frames to a file):
 *   dell_pen_bridge --dump-seconds 15 --dump-file /sdcard/pen_frames.txt
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#define PEN_NAME "Xiaomi Smart Pen Keyboard"
#define STALE_SECONDS 0.500
#define STATUS_SECONDS 5.0
#define RING_SLOTS 64
#define FRAME_BYTES 64
#define SLOT_SIZE 96 /* u64 timestamp + u32 transfer length + 81 bytes + pad */
#define TP_ID_PATH "/sys/kernel/tracing/events/spi/spi_transfer_stop/id"

_Static_assert(sizeof(struct input_id) == 8, "Linux input_id ABI");
_Static_assert(sizeof(struct uinput_user_dev) == 1116, "Linux legacy uinput ABI");
_Static_assert(KEY_PAGEUP == 104 && KEY_PAGEDOWN == 109, "Linux key codes");
_Static_assert(UI_DEV_CREATE == 0x5501 && UI_DEV_DESTROY == 0x5502, "uinput ioctls");
_Static_assert(UI_SET_EVBIT == 0x40045564 && UI_SET_KEYBIT == 0x40045565,
               "uinput capability ioctls");

/* ---------------------------------------------------------------- bpf ABI */

#define NR_BPF 280L            /* __NR_bpf on aarch64 */
#define NR_PERF 241L           /* __NR_perf_event_open on aarch64 */

#define BPF_MAP_CREATE 0
#define BPF_MAP_LOOKUP_ELEM 1
#define BPF_PROG_LOAD 5
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_PROG_TYPE_TRACEPOINT 5

/* instruction opcodes */
#define OP_MOV64_REG 0xbf
#define OP_MOV64_IMM 0xb7
#define OP_ADD64_IMM 0x07
#define OP_CALL 0x85
#define OP_JEQ_IMM 0x15
#define OP_JNE_IMM 0x55
#define OP_LDXW 0x61
#define OP_LDXDW 0x79
#define OP_LDXB 0x71
#define OP_STXW 0x63
#define OP_STXDW 0x7b
#define OP_STXB 0x73
#define OP_XADDW 0xc3
#define OP_LDDW_MAP 0x18 /* two-slot load, src_reg == 1 marks a map fd */
#define OP_EXIT 0x95

#define HELPER_MAP_LOOKUP 1
#define HELPER_KTIME 5
#define HELPER_PROBE_READ 4

struct bpf_insn {
    uint8_t code;
    uint8_t dst_reg : 4;
    uint8_t src_reg : 4;
    int16_t off;
    int32_t imm;
};

struct bpf_attr_map {
    uint32_t map_type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
};

struct bpf_attr_lookup {
    uint32_t map_fd;
    uint32_t _pad;
    uint64_t key;
    uint64_t value;
    uint64_t flags;
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

static long sys_bpf(int cmd, void *attr, size_t size) {
    return syscall(NR_BPF, cmd, attr, size);
}

static int map_create(void) {
    struct bpf_attr_map attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = SLOT_SIZE;
    attr.max_entries = RING_SLOTS + 1; /* slot 0 = writer counter */
    return (int)sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static int map_lookup(int map_fd, uint32_t key, void *value) {
    struct bpf_attr_lookup attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key = (uint64_t)(uintptr_t)&key;
    attr.value = (uint64_t)(uintptr_t)value;
    return (int)sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/* Assemble the tracepoint program. The program reads the recorded
 * spi_transfer pointer, resolves the fixed report buffer, and appends the
 * 14 report bytes plus a monotonic timestamp to the ring. Jump offsets are
 * patched after emission because every error path exits. */
struct insn_builder {
    struct bpf_insn code[160];
    int pc;
    int jumps[24];
    int jump_count;
    int skips[8];
    int skip_count;
    int skip_target;
    int exit_index;
};

static void emit(struct insn_builder *b, uint8_t opc, uint8_t dst, uint8_t src,
                 int16_t off, int32_t imm) {
    b->code[b->pc].code = opc;
    b->code[b->pc].dst_reg = (uint8_t)(dst & 0x0f);
    b->code[b->pc].src_reg = (uint8_t)(src & 0x0f);
    b->code[b->pc].off = off;
    b->code[b->pc].imm = imm;
    b->pc++;
}

static void jump_to_exit(struct insn_builder *b, uint8_t opc, uint8_t dst, int32_t imm) {
    b->jumps[b->jump_count++] = b->pc;
    emit(b, opc, dst, 0, 0, imm);
}

static void jump_forward(struct insn_builder *b, uint8_t opc, uint8_t dst, int32_t imm) {
    b->skips[b->skip_count++] = b->pc;
    emit(b, opc, dst, 0, 0, imm);
}

static void ld_map(struct insn_builder *b, uint8_t dst, int map_fd) {
    /* ld_imm64: first slot carries the fd, second slot is reserved. */
    emit(b, OP_LDDW_MAP, dst, 1, 0, map_fd);
    emit(b, 0, 0, 0, 0, 0);
}

static int assemble(struct insn_builder *b, int map_fd) {
    memset(b, 0, sizeof(*b));
    emit(b, OP_MOV64_REG, 6, 1, 0, 0); /* r6 = ctx */

    /* len = ctx->len (record offset 24); record every transfer length */
    emit(b, OP_MOV64_REG, 1, 10, 0, 0);
    emit(b, OP_ADD64_IMM, 1, 0, 0, -4);
    emit(b, OP_MOV64_IMM, 2, 0, 0, 4);
    emit(b, OP_MOV64_REG, 3, 6, 0, 0);
    emit(b, OP_ADD64_IMM, 3, 0, 0, 24);
    emit(b, OP_CALL, 0, 0, 0, HELPER_PROBE_READ);
    jump_to_exit(b, OP_JNE_IMM, 0, 0);

    /* xfer = ctx->xfer (record offset 16) */
    emit(b, OP_MOV64_REG, 1, 10, 0, 0);
    emit(b, OP_ADD64_IMM, 1, 0, 0, -16);
    emit(b, OP_MOV64_IMM, 2, 0, 0, 8);
    emit(b, OP_MOV64_REG, 3, 6, 0, 0);
    emit(b, OP_ADD64_IMM, 3, 0, 0, 16);
    emit(b, OP_CALL, 0, 0, 0, HELPER_PROBE_READ);
    jump_to_exit(b, OP_JNE_IMM, 0, 0);
    emit(b, OP_LDXDW, 7, 10, -16, 0);
    jump_to_exit(b, OP_JEQ_IMM, 7, 0);

    /* rbuf = xfer->rx_buf (struct spi_transfer offset 8 on 4.14) */
    emit(b, OP_ADD64_IMM, 7, 0, 0, 8);
    emit(b, OP_MOV64_REG, 1, 10, 0, 0);
    emit(b, OP_ADD64_IMM, 1, 0, 0, -16);
    emit(b, OP_MOV64_IMM, 2, 0, 0, 8);
    emit(b, OP_MOV64_REG, 3, 7, 0, 0);
    emit(b, OP_CALL, 0, 0, 0, HELPER_PROBE_READ);
    jump_to_exit(b, OP_JNE_IMM, 0, 0);
    emit(b, OP_LDXDW, 7, 10, -16, 0);
    jump_to_exit(b, OP_JEQ_IMM, 7, 0);
    /* r7 = rbuf stays resident */

    /* counter slot lookup (key 0) */
    emit(b, 0x62, 10, 0, -12, 0); /* *(u32*)(fp-12) = 0 */
    ld_map(b, 1, map_fd);
    emit(b, OP_MOV64_REG, 2, 10, 0, 0);
    emit(b, OP_ADD64_IMM, 2, 0, 0, -12);
    emit(b, OP_CALL, 0, 0, 0, HELPER_MAP_LOOKUP);
    jump_to_exit(b, OP_JEQ_IMM, 0, 0);
    emit(b, OP_MOV64_REG, 9, 0, 0, 0); /* r9 = counter value pointer */

    /* slot key = (counter & 63) + 1 */
    emit(b, OP_LDXW, 1, 9, 0, 0);
    emit(b, OP_MOV64_IMM, 2, 0, 0, 63);
    /* AND64 reg: BPF_ALU64|BPF_AND|BPF_X = 0x5f */
    emit(b, 0x5f, 1, 2, 0, 0);
    emit(b, OP_ADD64_IMM, 1, 0, 0, 1);
    emit(b, OP_STXW, 10, 1, -8, 0); /* *(u32*)(fp-8) = key */

    ld_map(b, 1, map_fd);
    emit(b, OP_MOV64_REG, 2, 10, 0, 0);
    emit(b, OP_ADD64_IMM, 2, 0, 0, -8);
    emit(b, OP_CALL, 0, 0, 0, HELPER_MAP_LOOKUP);
    jump_to_exit(b, OP_JEQ_IMM, 0, 0);
    emit(b, OP_MOV64_REG, 8, 0, 0, 0); /* r8 = slot value pointer */

    /* slot->timestamp = ktime_get_ns() (monotonic, matches userspace clock) */
    emit(b, OP_CALL, 0, 0, 0, HELPER_KTIME);
    emit(b, OP_STXDW, 8, 0, 0, 0);

    /* slot->len = transfer length (slot offset 8) */
    emit(b, OP_LDXW, 1, 10, -4, 0);
    emit(b, OP_STXW, 8, 1, 8, 0);

    /* only the 81-byte pen report carries report bytes */
    emit(b, OP_LDXW, 1, 10, -4, 0);
    jump_forward(b, OP_JNE_IMM, 1, 81);

    /* read the whole 81-byte report buffer rbuf[0..80] onto the stack */
    emit(b, OP_MOV64_REG, 1, 10, 0, 0);
    emit(b, OP_ADD64_IMM, 1, 0, 0, -128);
    emit(b, OP_MOV64_IMM, 2, 0, 0, FRAME_BYTES);
    emit(b, OP_MOV64_REG, 3, 7, 0, 0);
    emit(b, OP_CALL, 0, 0, 0, HELPER_PROBE_READ);
    jump_to_exit(b, OP_JNE_IMM, 0, 0);

    /* copy them into the slot at value+12 */
    emit(b, OP_MOV64_REG, 2, 8, 0, 0);
    emit(b, OP_ADD64_IMM, 2, 0, 0, 12);
    for (int i = 0; i < FRAME_BYTES; ++i) {
        emit(b, OP_LDXB, 1, 10, (int16_t)(-128 + i), 0);
        emit(b, OP_STXB, 2, 1, (int16_t)i, 0);
    }

    b->skip_target = b->pc;

    /* counter += 1 (atomic) */
    emit(b, OP_MOV64_IMM, 0, 0, 0, 1);
    emit(b, OP_XADDW, 9, 0, 0, 0);

    emit(b, OP_MOV64_IMM, 0, 0, 0, 0);
    b->exit_index = b->pc;
    emit(b, OP_EXIT, 0, 0, 0, 0);
    for (int i = 0; i < b->jump_count; ++i)
        b->code[b->jumps[i]].off = (int16_t)(b->exit_index - b->jumps[i] - 1);
    for (int i = 0; i < b->skip_count; ++i)
        b->code[b->skips[i]].off = (int16_t)(b->skip_target - b->skips[i] - 1);
    return b->pc;
}

static int load_prog(struct insn_builder *builder, int insn_count) {
    static const char license[] = "GPL";
    static char log_buf[1 << 16];
    struct bpf_attr_prog attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    attr.insn_cnt = (uint32_t)insn_count;
    attr.insns = (uint64_t)(uintptr_t)builder->code;
    attr.license = (uint64_t)(uintptr_t)license;
    attr.log_level = 1;
    attr.log_size = sizeof(log_buf);
    attr.log_buf = (uint64_t)(uintptr_t)log_buf;
    int fd = (int)sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) fprintf(stderr, "bpf verifier log:\n%s\n", log_buf);
    return fd;
}

/* One perf event per CPU; the tracepoint fires in the touch IRQ thread's
 * CPU context. cpu=-1 is rejected by this kernel, so enumerate CPUs. */
static int attach_all(int prog_fd, uint32_t tp_id, int *fds, int max) {
    int count = 0;
    for (int cpu = 0; cpu < max; ++cpu) {
        struct perf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.type = 2; /* PERF_TYPE_TRACEPOINT */
        attr.size = sizeof(attr);
        attr.config = tp_id;
        attr.flags = 1; /* disabled until attached */
        long fd = syscall(NR_PERF, &attr, (long)-1, (long)cpu, -1L, 0L);
        if (fd < 0) continue;
        if (ioctl((int)fd, 0x40042408 /* PERF_EVENT_IOC_SET_BPF */,
                  (void *)(uintptr_t)prog_fd) < 0) {
            close((int)fd);
            continue;
        }
        if (ioctl((int)fd, 0x2400 /* PERF_EVENT_IOC_ENABLE */, 0) < 0) {
            close((int)fd);
            continue;
        }
        fds[count++] = (int)fd;
    }
    return count;
}

/* ------------------------------------------------------------- bridge core */

struct options {
    const char *stop_path;
    const char *status_path;
    const char *lock_path;
    const char *dump_path;
    unsigned max_seconds;
    bool max_given;
    unsigned dump_seconds;
    unsigned btn_bit;
    unsigned btn_byte;
};

struct counters {
    uint64_t raw;
    uint64_t valid;
    uint64_t stale;
    uint64_t malformed;
    uint64_t transitions;
    uint64_t timeouts;
    uint64_t mask_frames[4];
};

struct frame {
    double stamp; /* monotonic seconds */
    uint32_t len; /* SPI transfer length */
    unsigned mask;
    unsigned char bytes[FRAME_BYTES];
};

struct bridge {
    const struct options *options;
    struct counters counts;
    int map_fd;
    int prog_fd;
    int perf_fds[16];
    int perf_count;
    int uinput_fd;
    int lock_fd;
    bool uinput_created;
    uint32_t consumed;
    unsigned mask;
    double started;
    double last_fresh;
    double last_status;
    bool status_dirty;
    bool status_error_reported;
    const char *reason;
    const char *state;
};

enum frame_result { FRAME_IGNORE, FRAME_VALID, FRAME_INVALID };

static volatile sig_atomic_t requested_signal;

static void on_signal(int number) {
    requested_signal = number;
}

static double mono_time(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1.0;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

static void error_message(const char *stage) {
    fprintf(stderr, "dell_pen_bridge: error %s (errno=%d)\n", stage, errno);
}

static int write_complete(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    while (length) {
        ssize_t count = write(fd, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (count == 0) errno = EIO;
            return -1;
        }
        cursor += (size_t)count;
        length -= (size_t)count;
    }
    return 0;
}

static void input_event_set(struct input_event *event, unsigned code, int value) {
    memset(event, 0, sizeof(*event));
    event->type = EV_KEY;
    event->code = (uint16_t)code;
    event->value = value;
}

static int emit_events(int fd, struct input_event *events, size_t count) {
    size_t remaining = count * sizeof(*events);
    unsigned char *cursor = (unsigned char *)events;
    while (remaining) {
        ssize_t amount = write(fd, cursor, remaining);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0 || (size_t)amount % sizeof(*events) != 0) {
            if (amount >= 0) errno = EIO;
            return -1;
        }
        cursor += amount;
        remaining -= (size_t)amount;
    }
    return 0;
}

static int set_mask(struct bridge *bridge, unsigned mask, const char *reason) {
    if (bridge->mask == mask) return 0;
    struct input_event events[3];
    size_t count = 0;
    unsigned released = bridge->mask & ~mask;
    unsigned pressed = mask & ~bridge->mask;
    if (released & 2) input_event_set(&events[count++], KEY_PAGEDOWN, 0);
    if (released & 1) input_event_set(&events[count++], KEY_PAGEUP, 0);
    if (pressed & 2) input_event_set(&events[count++], KEY_PAGEDOWN, 1);
    if (pressed & 1) input_event_set(&events[count++], KEY_PAGEUP, 1);
    memset(&events[count], 0, sizeof(events[count]));
    events[count++].type = EV_SYN;
    if (emit_events(bridge->uinput_fd, events, count) < 0) return -1;
    bridge->mask = mask;
    ++bridge->counts.transitions;
    bridge->reason = reason;
    bridge->status_dirty = true;
    return 0;
}

static int release_both(struct bridge *bridge) {
    if (!bridge->uinput_created) return 0;
    struct input_event events[3];
    input_event_set(&events[0], KEY_PAGEDOWN, 0);
    input_event_set(&events[1], KEY_PAGEUP, 0);
    memset(&events[2], 0, sizeof(events[2]));
    events[2].type = EV_SYN;
    int result = emit_events(bridge->uinput_fd, events, 3);
    if (result == 0 && bridge->mask != 0) ++bridge->counts.transitions;
    bridge->mask = 0;
    bridge->status_dirty = true;
    return result;
}

static int create_device(struct bridge *bridge) {
    bridge->uinput_fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (bridge->uinput_fd < 0)
        bridge->uinput_fd = open("/dev/input/uinput", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (bridge->uinput_fd < 0) return -1;
    if (ioctl(bridge->uinput_fd, UI_SET_EVBIT, EV_SYN) < 0 ||
        ioctl(bridge->uinput_fd, UI_SET_EVBIT, EV_KEY) < 0 ||
        ioctl(bridge->uinput_fd, UI_SET_KEYBIT, KEY_PAGEUP) < 0 ||
        ioctl(bridge->uinput_fd, UI_SET_KEYBIT, KEY_PAGEDOWN) < 0) return -1;
    struct uinput_user_dev description;
    memset(&description, 0, sizeof(description));
    memcpy(description.name, PEN_NAME, sizeof(PEN_NAME));
    description.id.bustype = BUS_VIRTUAL;
    description.id.version = 1;
    /* No Xiaomi vendor/product ID claim; the module checks the name only. */
    ssize_t amount;
    do {
        amount = write(bridge->uinput_fd, &description, sizeof(description));
    } while (amount < 0 && errno == EINTR);
    if (amount != (ssize_t)sizeof(description)) {
        if (amount >= 0) errno = EIO;
        return -1;
    }
    if (ioctl(bridge->uinput_fd, UI_DEV_CREATE) < 0) return -1;
    bridge->uinput_created = true;
    return 0;
}

static int status_write(struct bridge *bridge, double now) {
    char temporary[PATH_MAX];
    int size = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld",
                        bridge->options->status_path, (long)getpid());
    if (size < 0 || (size_t)size >= sizeof(temporary)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    char text[1024];
    const struct counters *c = &bridge->counts;
    size = snprintf(text, sizeof(text),
        "{\"version\":2,\"status\":\"%s\",\"reason\":\"%s\","
        "\"pid\":%ld,\"mask\":%u,\"uptime_seconds\":%.3f,"
        "\"raw_frames\":%" PRIu64 ",\"valid_frames\":%" PRIu64 ","
        "\"stale_frames\":%" PRIu64 ",\"malformed_frames\":%" PRIu64 ","
        "\"transitions\":%" PRIu64 ",\"timeouts\":%" PRIu64 ","
        "\"mask_frames\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]}\n",
        bridge->state, bridge->reason, (long)getpid(), bridge->mask,
        now >= bridge->started ? now - bridge->started : 0.0,
        c->raw, c->valid, c->stale, c->malformed,
        c->transitions, c->timeouts,
        c->mask_frames[0], c->mask_frames[1], c->mask_frames[2], c->mask_frames[3]);
    if (size < 0 || (size_t)size >= sizeof(text)) {
        errno = EOVERFLOW;
        return -1;
    }
    int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    int result = write_complete(fd, text, (size_t)size);
    int saved = errno;
    if (close(fd) < 0 && result == 0) {
        result = -1;
        saved = errno;
    }
    if (result == 0 && rename(temporary, bridge->options->status_path) < 0) {
        result = -1;
        saved = errno;
    }
    if (result != 0) {
        (void)unlink(temporary);
        errno = saved;
        return -1;
    }
    bridge->last_status = now;
    bridge->status_dirty = false;
    return 0;
}

/* Any existing stop marker ends the run. Errors other than ENOENT also stop
 * the daemon rather than silently losing its externally controlled stop path. */
static int stop_requested(const char *path) {
    struct stat status;
    if (lstat(path, &status) == 0) return 1;
    return errno == ENOENT ? 0 : -1;
}

static int acquire_lock(struct bridge *bridge) {
    if (!bridge->options->lock_path) return 0;
    bridge->lock_fd = open(bridge->options->lock_path,
                          O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (bridge->lock_fd < 0 || flock(bridge->lock_fd, LOCK_EX | LOCK_NB) < 0) return -1;
    char pid[40];
    int length = snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
    if (ftruncate(bridge->lock_fd, 0) < 0 || lseek(bridge->lock_fd, 0, SEEK_SET) < 0 ||
        write_complete(bridge->lock_fd, pid, (size_t)length) < 0) return -1;
    /* Never unlink a flock file: replacing its inode would defeat exclusivity. */
    return 0;
}

static int install_signals(void) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = on_signal;
    if (sigemptyset(&action.sa_mask) < 0) return -1;
    if (sigaction(SIGTERM, &action, NULL) < 0 ||
        sigaction(SIGINT, &action, NULL) < 0 ||
        sigaction(SIGHUP, &action, NULL) < 0) return -1;
    action.sa_handler = SIG_IGN;
    return sigaction(SIGPIPE, &action, NULL);
}

/* Start the BPF source: map, program, per-CPU perf attachment. Only reads
 * kernel memory and writes to the daemon's own map. */
static int bpf_start(struct bridge *bridge) {
    bridge->map_fd = -1;
    bridge->prog_fd = -1;
    bridge->perf_count = 0;
    int map_fd = map_create();
    if (map_fd < 0) {
        error_message("bpf_map_create");
        return -1;
    }
    bridge->map_fd = map_fd;
    struct insn_builder builder;
    int count = assemble(&builder, map_fd);
    bridge->prog_fd = load_prog(&builder, count);
    if (bridge->prog_fd < 0) {
        error_message("bpf_prog_load");
        return -1;
    }
    uint32_t tp_id = 0;
    FILE *id = fopen(TP_ID_PATH, "re");
    if (!id) {
        error_message("tracepoint_id_open");
        return -1;
    }
    if (fscanf(id, "%u", &tp_id) != 1 || tp_id == 0) {
        fclose(id);
        error_message("tracepoint_id_read");
        return -1;
    }
    fclose(id);
    bridge->perf_count = attach_all(bridge->prog_fd, tp_id,
                                    bridge->perf_fds, (int)(sizeof(bridge->perf_fds) /
                                                            sizeof(bridge->perf_fds[0])));
    if (bridge->perf_count == 0) {
        error_message("perf_attach");
        return -1;
    }
    /* Start consuming from the current counter; do not replay stale frames. */
    uint32_t counter = 0;
    unsigned char slot[SLOT_SIZE];
    if (map_lookup(bridge->map_fd, 0, slot) == 0) memcpy(&counter, slot, sizeof(counter));
    bridge->consumed = counter;
    return 0;
}

static void bpf_stop(struct bridge *bridge) {
    for (int i = 0; i < bridge->perf_count; ++i) close(bridge->perf_fds[i]);
    bridge->perf_count = 0;
    if (bridge->prog_fd >= 0) close(bridge->prog_fd);
    if (bridge->map_fd >= 0) close(bridge->map_fd);
    bridge->prog_fd = bridge->map_fd = -1;
}

/* Consume newly published ring slots. Returns 0 on success, -1 on a hard
 * map error, 1 when new frames were consumed. */
static int bpf_poll(struct bridge *bridge, struct frame *out, unsigned *count) {
    unsigned char slot[SLOT_SIZE];
    if (map_lookup(bridge->map_fd, 0, slot) < 0) {
        error_message("map_lookup_counter");
        return -1;
    }
    uint32_t counter;
    memcpy(&counter, slot, sizeof(counter));
    *count = 0;
    if (counter == bridge->consumed) return 0;
    /* The ring holds RING_SLOTS frames; a wrap skips overwritten slots. */
    uint32_t available = counter - bridge->consumed;
    uint32_t first = available > RING_SLOTS ? counter - RING_SLOTS
                                            : bridge->consumed + 1;
    for (uint32_t n = first; n <= counter; ++n) {
        uint32_t key = ((n - 1) & (RING_SLOTS - 1)) + 1;
        if (map_lookup(bridge->map_fd, key, slot) < 0) {
            error_message("map_lookup_slot");
            return -1;
        }
        uint64_t stamp_ns;
        memcpy(&stamp_ns, slot, sizeof(stamp_ns));
        out[*count].stamp = (double)stamp_ns / 1000000000.0;
        memcpy(&out[*count].len, slot + 8, sizeof(uint32_t));
        memset(out[*count].bytes, 0, FRAME_BYTES);
        if (out[*count].len == 81)
            memcpy(out[*count].bytes, slot + 12, FRAME_BYTES);
        ++*count;
        if (*count >= 256) break;
    }
    bridge->consumed = counter;
    bridge->counts.raw += *count;
    return 1;
}

static unsigned button_mask(const struct bridge *bridge, const struct frame *frame) {
    unsigned byte = frame->bytes[bridge->options->btn_byte];
    return byte & (1U << bridge->options->btn_bit) ? 2U : 0U;
}

/* Only the 81-byte pen report carries report bytes. bytes[i] = rbuf[i], so
 * point_data[j] = bytes[j+1]. Button state is taken from the configured
 * button byte; calibration dumps decide the exact byte and bit. */
static enum frame_result classify(const struct bridge *bridge, struct frame *frame) {
    if (frame->len != 81) return FRAME_IGNORE;
    unsigned format = frame->bytes[10]; /* point_data[66] */
    if (format == 0xff) {
        frame->mask = 0;
        return FRAME_VALID;
    }
    if (format != 1) return FRAME_INVALID;
    frame->mask = button_mask(bridge, frame);
    return FRAME_VALID;
}

static int accept_frame(struct bridge *bridge, const struct frame *frame) {
    double now = mono_time();
    if (now < 0.0) return -1;
    double age = now - frame->stamp;
    if (age > STALE_SECONDS || age < -STALE_SECONDS) {
        ++bridge->counts.stale;
        return set_mask(bridge, 0, "stale_frame");
    }
    /* Base expiry on the originating frame, not a delayed poll. */
    bridge->last_fresh = frame->stamp < now ? frame->stamp : now;
    ++bridge->counts.valid;
    ++bridge->counts.mask_frames[frame->mask];
    return set_mask(bridge, frame->mask, "frame");
}

static int msleep(long ms) {
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    while (nanosleep(&req, &req) < 0 && errno == EINTR) continue;
    return 0;
}

static int run_live(const struct options *options) {
    struct bridge bridge;
    memset(&bridge, 0, sizeof(bridge));
    bridge.options = options;
    bridge.uinput_fd = bridge.lock_fd = -1;
    bridge.state = "starting";
    bridge.reason = "startup";
    bridge.started = mono_time();
    int result = 1;
    bool own_lock = false;
    if (bridge.started < 0.0) {
        error_message("clock");
        return 1;
    }
    if (install_signals() < 0) {
        error_message("signals");
        return 1;
    }
    pid_t supervisor = getppid();
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0) {
        error_message("parent_watch");
        return 1;
    }
    bool parent_missing = supervisor <= 1 || getppid() != supervisor;
    if (acquire_lock(&bridge) < 0) {
        error_message("lock");
        if (bridge.lock_fd >= 0) close(bridge.lock_fd);
        return 1;
    }
    own_lock = true;
    if (parent_missing || requested_signal) {
        bridge.reason = "parent_exit";
        result = 0;
        goto cleanup;
    }
    int marker = stop_requested(options->stop_path);
    if (marker != 0) {
        bridge.reason = marker > 0 ? "stop_file" : "stop_file_error";
        result = marker > 0 ? 0 : 1;
        if (marker < 0) error_message("stop_file");
        goto cleanup;
    }
    if (bpf_start(&bridge) < 0) {
        bridge.reason = "bpf_error";
        goto cleanup;
    }
    if (create_device(&bridge) < 0) {
        bridge.reason = "uinput_error";
        error_message("uinput_create");
        goto cleanup;
    }
    bridge.state = "running";
    bridge.status_dirty = true;
    if (status_write(&bridge, mono_time()) < 0) {
        bridge.reason = "status_error";
        bridge.status_error_reported = true;
        error_message("status");
        goto cleanup;
    }
    fprintf(stdout, "dell_pen_bridge: started pid=%ld perf=%d\n",
            (long)getpid(), bridge.perf_count);
    fflush(stdout);

    /* Creation and InputReader discovery are asynchronous. Suppress startup
     * presses for the first second; stale queued input remains rejected. */
    double accept_after = mono_time() + 1.0;
    struct frame frames[256];
    for (;;) {
        double now = mono_time();
        if (now < 0.0) {
            bridge.reason = "clock_error";
            error_message("clock");
            break;
        }
        if (requested_signal) {
            bridge.reason = "signal";
            result = 0;
            break;
        }
        marker = stop_requested(options->stop_path);
        if (marker != 0) {
            bridge.reason = marker > 0 ? "stop_file" : "stop_file_error";
            result = marker > 0 ? 0 : 1;
            if (marker < 0) error_message("stop_file");
            break;
        }
        if (options->max_seconds && now - bridge.started >= options->max_seconds) {
            bridge.reason = "max_seconds";
            result = 0;
            break;
        }
        if (bridge.mask && now - bridge.last_fresh >= STALE_SECONDS) {
            ++bridge.counts.timeouts;
            if (set_mask(&bridge, 0, "timeout") < 0) {
                bridge.reason = "uinput_error";
                error_message("uinput_release");
                break;
            }
        }
        if (bridge.status_dirty || now - bridge.last_status >= STATUS_SECONDS) {
            if (status_write(&bridge, now) < 0) {
                bridge.reason = "status_error";
                bridge.status_error_reported = true;
                error_message("status");
                break;
            }
        }

        unsigned count = 0;
        int polled = bpf_poll(&bridge, frames, &count);
        if (polled < 0) {
            bridge.reason = "bpf_poll_error";
            break;
        }
        if (polled > 0 && mono_time() >= accept_after) {
            int failed = 0;
            for (unsigned i = 0; i < count; ++i) {
                enum frame_result verdict = classify(&bridge, &frames[i]);
                if (verdict == FRAME_IGNORE) continue;
                if (verdict == FRAME_INVALID) {
                    ++bridge.counts.malformed;
                    continue;
                }
                if (accept_frame(&bridge, &frames[i]) < 0) {
                    failed = 1;
                    break;
                }
                if (bridge.status_dirty && status_write(&bridge, mono_time()) < 0) {
                    bridge.reason = "status_error";
                    bridge.status_error_reported = true;
                    failed = 2;
                    break;
                }
            }
            if (failed == 1) {
                bridge.reason = "uinput_error";
                break;
            }
            if (failed == 2) {
                error_message("status");
                break;
            }
        }
        msleep(bridge.mask ? 10 : 30);
    }

cleanup:
    if (bridge.uinput_created) {
        if (release_both(&bridge) < 0) {
            error_message("final_release");
            result = 1;
        }
        /* Give InputReader time to observe UP before the device disappears. */
        struct timespec grace = {.tv_sec = 0, .tv_nsec = 100000000};
        (void)nanosleep(&grace, NULL);
        if (ioctl(bridge.uinput_fd, UI_DEV_DESTROY) < 0) {
            error_message("uinput_destroy");
            result = 1;
        }
    }
    if (bridge.uinput_fd >= 0) close(bridge.uinput_fd);
    bpf_stop(&bridge);
    bridge.mask = 0;
    bridge.state = result == 0 ? "stopped" : "error";
    if (own_lock && status_write(&bridge, mono_time()) < 0 && !bridge.status_error_reported)
        error_message("final_status");
    fprintf(stdout, "dell_pen_bridge: stopped reason=%s frames=%" PRIu64
            " transitions=%" PRIu64 "\n", bridge.reason, bridge.counts.valid,
            bridge.counts.transitions);
    fflush(stdout);
    if (bridge.lock_fd >= 0) close(bridge.lock_fd);
    return result;
}

/* Capture mode: no uinput, no state machine; records every consumed frame
 * as "seq stamp hexbytes" for offline byte-position analysis. */
static int run_dump(const struct options *options) {
    struct bridge bridge;
    memset(&bridge, 0, sizeof(bridge));
    bridge.options = options;
    bridge.uinput_fd = bridge.lock_fd = -1;
    if (install_signals() < 0) {
        error_message("signals");
        return 1;
    }
    if (bpf_start(&bridge) < 0) return 1;
    int fd = open(options->dump_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        error_message("dump_open");
        bpf_stop(&bridge);
        return 1;
    }
    fprintf(stdout, "dell_pen_bridge: dumping %u s to %s\n",
            options->dump_seconds, options->dump_path);
    fflush(stdout);
    double deadline = mono_time() + options->dump_seconds;
    struct frame frames[256];
    uint64_t seq = 0;
    int result = 0;
    for (;;) {
        double now = mono_time();
        if (requested_signal || now < 0.0 || now >= deadline) break;
        unsigned count = 0;
        int polled = bpf_poll(&bridge, frames, &count);
        if (polled < 0) {
            result = 1;
            break;
        }
        for (unsigned i = 0; i < count; ++i) {
            char line[320];
            int size = snprintf(line, sizeof(line), "%" PRIu64 " %.9f %u", seq++,
                                frames[i].stamp, frames[i].len);
            if (frames[i].len == 81)
                for (unsigned j = 0; j < FRAME_BYTES; ++j)
                    size += snprintf(line + size, sizeof(line) - (size_t)size, " %02x",
                                     frames[i].bytes[j]);
            size += snprintf(line + size, sizeof(line) - (size_t)size, "\n");
            if (write_complete(fd, line, (size_t)size) < 0) {
                error_message("dump_write");
                result = 1;
                break;
            }
        }
        msleep(15);
    }
    if (close(fd) < 0) result = 1;
    bpf_stop(&bridge);
    fprintf(stdout, "dell_pen_bridge: dump done frames=%" PRIu64 "\n", seq);
    fflush(stdout);
    return result;
}

static void usage(FILE *output) {
    fprintf(output,
        "Usage: dell_pen_bridge --stop-file PATH --status PATH [--lock PATH]\n"
        "                       [--max-seconds N] [--btn-byte B] [--btn-bit B]\n"
        "       dell_pen_bridge --dump-seconds N --dump-file PATH\n"
        "       dell_pen_bridge --help\n"
        "N=0 (default) runs until stopped. Live paths must be absolute.\n"
        "Defaults: btn-byte=11 (point_data[76]), btn-bit=0.\n");
}

static int parse_unsigned(const char *value, unsigned max, unsigned *out) {
    if (!isdigit((unsigned char)value[0])) return -1;
    char *end;
    errno = 0;
    unsigned long number = strtoul(value, &end, 10);
    if (errno || *end || number > max) return -1;
    *out = (unsigned)number;
    return 0;
}

static int parse_options(int argc, char **argv, struct options *options) {
    memset(options, 0, sizeof(*options));
    options->btn_bit = 0;
    options->btn_byte = 78; /* point_data[77], the MiCode button byte */
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--help")) {
            if (argc != 2) return -1;
            return 1;
        }
        if (i + 1 >= argc) return -1;
        const char *name = argv[i];
        const char *value = argv[++i];
        if (!*value) return -1;
        if (!strcmp(name, "--max-seconds")) {
            if (options->max_given) return -1;
            if (parse_unsigned(value, UINT_MAX, &options->max_seconds) < 0) return -1;
            options->max_given = true;
        } else if (!strcmp(name, "--dump-seconds")) {
            if (options->dump_seconds) return -1;
            if (parse_unsigned(value, 86400, &options->dump_seconds) < 0) return -1;
        } else if (!strcmp(name, "--btn-byte")) {
            if (parse_unsigned(value, FRAME_BYTES - 1, &options->btn_byte) < 0) return -1;
        } else if (!strcmp(name, "--btn-bit")) {
            if (parse_unsigned(value, 7, &options->btn_bit) < 0) return -1;
        } else {
            const char **slot = NULL;
            if (!strcmp(name, "--stop-file")) slot = &options->stop_path;
            else if (!strcmp(name, "--status")) slot = &options->status_path;
            else if (!strcmp(name, "--lock")) slot = &options->lock_path;
            else if (!strcmp(name, "--dump-file")) slot = &options->dump_path;
            else return -1;
            if (*slot) return -1;
            *slot = value;
        }
    }
    if (options->dump_path) {
        if (!options->dump_seconds || options->stop_path || options->status_path ||
            options->max_given)
            return -1;
        if (options->dump_path[0] != '/' || strlen(options->dump_path) > PATH_MAX - 48)
            return -1;
        return 0;
    }
    if (!options->stop_path || !options->status_path) return -1;
    const char *paths[3] = {options->stop_path, options->status_path, options->lock_path};
    for (unsigned i = 0; i < 3; ++i) {
        if (!paths[i]) continue;
        if (paths[i][0] != '/' || strlen(paths[i]) > PATH_MAX - 48) return -1;
        for (unsigned j = 0; j < i; ++j) {
            if (paths[j] && !strcmp(paths[i], paths[j])) return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    struct options options;
    int parsed = parse_options(argc, argv, &options);
    if (parsed != 0) {
        usage(parsed > 0 ? stdout : stderr);
        return parsed > 0 ? 0 : 2;
    }
    if (options.dump_path) return run_dump(&options);
    return run_live(&options);
}
