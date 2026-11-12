/*
 * Dual barrel-button bridge for Xiaomi Pad 5 (nabu), ColorOS 17 (Panz kernel).
 *
 * v0.3.0: the SPI/eBPF report sniffer is gone. On the current fixed kernel the
 * Novatek digitizer exposes the two physical barrel buttons of the Lenovo
 * Precision Pen 2 as independent EV_KEY events on /dev/input/event4:
 *
 *   BTN_STYLUS  (0x14b) DOWN/UP  -> pen key 1
 *   BTN_STYLUS2 (0x14c) DOWN/UP  -> pen key 2
 *
 * This daemon opens that evdev node (read-only: evdev supports multiple
 * readers, so the original pen / hover / writing path used by InputReader is
 * never intercepted or altered), tracks the two button states independently
 * and injects the mirrored key events through the exact same uinput device
 * that was validated on-device:
 *
 *   device name "Xiaomi Smart Pen Keyboard", EV_SYN + EV_KEY with
 *   KEY_PAGEUP (104) and KEY_PAGEDOWN (109), BUS_VIRTUAL, events reported
 *   as one or more EV_KEY records followed by a single EV_SYN SYN_REPORT.
 *
 * Button mapping (verified on-device; flip the two #defines if the physical
 * buttons turn out to be swapped, nothing else changes):
 *
 *   pen key 1 (BTN_STYLUS)  -> KEY_PAGEDOWN 109
 *   pen key 2 (BTN_STYLUS2) -> KEY_PAGEUP   104
 *
 * State machine: each button has its own bool. A physical DOWN that arrives
 * while the virtual state is already pressed is ignored (no duplicate DOWN),
 * likewise a stray UP. The two buttons can be pressed and released in any
 * order and simultaneously; releasing one never releases the other. If the
 * evdev node disappears (driver reload, USB gadget detach) any pressed keys
 * are released and the states reset; on reconnect the current physical state
 * is synced via EVIOCGKEY so a button held across a reconnect is restored.
 *
 * Service integration: single instance via flock, stop-file polling, atomic
 * JSON status output, TERM/INT/HUP handling, bounded --max-seconds runs, and
 * a release + UI_DEV_DESTROY + grace period on exit so InputReader observes
 * the UP events before the virtual device disappears. The daemon does NOT
 * set PR_SET_PDEATHSIG: it must survive the short-lived su -c shell that
 * started it (KernelSU module lifecycle is handled by control.sh).
 *
 * Build (see build_module.py):
 *   zig cc -target aarch64-linux-musl -static -O2 -std=c11 \
 *     -Wall -Wextra -Werror dell_pen_bridge.c -o dell-pen-bridge
 *
 * Live:
 *   dell-pen-bridge --stop-file /dev/dell_pen_bridge_nabu/stop \
 *     --status /dev/dell_pen_bridge_nabu/status.json \
 *     --lock /dev/dell_pen_bridge_nabu/native.lock \
 *     [--event-node /dev/input/event4] [--max-seconds N]
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#define PEN_NAME "Xiaomi Smart Pen Keyboard"
#define DEFAULT_EVENT_NODE "/dev/input/event4"
#define STATUS_SECONDS 5.0
#define POLL_TIMEOUT_MS 200
#define REOPEN_DELAY_MS 1000
#define STARTUP_SUPPRESS_SECONDS 1.0

_Static_assert(sizeof(struct input_id) == 8, "Linux input_id ABI");
_Static_assert(sizeof(struct uinput_user_dev) == 1116, "Linux legacy uinput ABI");
_Static_assert(KEY_PAGEUP == 104 && KEY_PAGEDOWN == 109, "Linux key codes");
_Static_assert(UI_DEV_CREATE == 0x5501 && UI_DEV_DESTROY == 0x5502, "uinput ioctls");
_Static_assert(UI_SET_EVBIT == 0x40045564 && UI_SET_KEYBIT == 0x40045565,
               "uinput capability ioctls");

/* ------------------------------------------------------------- bridge core */

struct options {
    const char *stop_path;
    const char *status_path;
    const char *lock_path;
    const char *event_node;
    unsigned max_seconds;
    bool max_given;
};

struct counters {
    uint64_t key1_downs;   /* BTN_STYLUS -> KEY_PAGEDOWN DOWN injections */
    uint64_t key2_downs;   /* BTN_STYLUS2 -> KEY_PAGEUP DOWN injections */
    uint64_t transitions;  /* any injected DOWN or UP */
    uint64_t read_errors;  /* evdev read failures that triggered reconnect */
    uint64_t reconnects;   /* successful reopenings of the event node */
};

struct bridge {
    const struct options *options;
    struct counters counts;
    int uinput_fd;
    int ev_fd;
    int lock_fd;
    bool uinput_created;
    bool pen_key1_pressed;
    bool pen_key2_pressed;
    double started;
    double last_status;
    bool status_dirty;
    bool status_error_reported;
    const char *reason;
    const char *state;
};

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

static void input_event_set(struct input_event *event, unsigned type, unsigned code,
                            int value) {
    memset(event, 0, sizeof(*event));
    event->type = (uint16_t)type;
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

/* Inject exactly one virtual key transition: one EV_KEY record followed by
 * one EV_SYN SYN_REPORT, the same reporting order as the validated build. */
static int inject_key(struct bridge *bridge, unsigned code, int value,
                      const char *label) {
    struct input_event events[2];
    input_event_set(&events[0], EV_KEY, code, value);
    input_event_set(&events[1], EV_SYN, SYN_REPORT, 0);
    if (emit_events(bridge->uinput_fd, events, 2) < 0) return -1;
    ++bridge->counts.transitions;
    bridge->status_dirty = true;
    fprintf(stdout, "dell_pen_bridge: %s %s\n", label, value ? "DOWN" : "UP");
    fflush(stdout);
    return 0;
}

/* Independent per-button state machine. Idempotent: repeated DOWN or UP for
 * an already-settled state is dropped, so no duplicates and no lost releases.
 * pen_key1/pen_key2 never touch each other. */
static int apply_button(struct bridge *bridge, bool *pressed, bool down,
                        unsigned code, const char *label) {
    if (*pressed == down) return 0;
    if (inject_key(bridge, code, down ? 1 : 0, label) < 0) return -1;
    *pressed = down;
    if (down) {
        if (code == KEY_PAGEDOWN) ++bridge->counts.key1_downs;
        else ++bridge->counts.key2_downs;
    }
    return 0;
}

static int release_all(struct bridge *bridge) {
    int result = 0;
    if (bridge->pen_key1_pressed &&
        apply_button(bridge, &bridge->pen_key1_pressed, false, KEY_PAGEDOWN,
                     "key1 BTN_STYLUS->KEY_PAGEDOWN") < 0)
        result = -1;
    if (bridge->pen_key2_pressed &&
        apply_button(bridge, &bridge->pen_key2_pressed, false, KEY_PAGEUP,
                     "key2 BTN_STYLUS2->KEY_PAGEUP") < 0)
        result = -1;
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
        "{\"version\":3,\"status\":\"%s\",\"reason\":\"%s\","
        "\"pid\":%ld,\"key1_pressed\":%s,\"key2_pressed\":%s,"
        "\"uptime_seconds\":%.3f,"
        "\"key1_downs\":%" PRIu64 ",\"key2_downs\":%" PRIu64 ","
        "\"transitions\":%" PRIu64 ",\"read_errors\":%" PRIu64 ","
        "\"reconnects\":%" PRIu64 "}\n",
        bridge->state, bridge->reason, (long)getpid(),
        bridge->pen_key1_pressed ? "true" : "false",
        bridge->pen_key2_pressed ? "true" : "false",
        now >= bridge->started ? now - bridge->started : 0.0,
        c->key1_downs, c->key2_downs, c->transitions,
        c->read_errors, c->reconnects);
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

/* ------------------------------------------------------------- evdev input */

/* Open the physical pen event node read-only. evdev fans every event out to
 * all open readers, so this never consumes or blocks the original pen events.
 * Verify the node actually claims both barrel buttons to catch a wrong node
 * (e.g. after the digitizer re-enumerates at a different /dev/input/eventN). */
static int open_event_node(const struct options *options, int *out_fd) {
    int fd = open(options->event_node, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    unsigned char key_bits[(BTN_STYLUS2 / 8) + 1];
    memset(key_bits, 0, sizeof(key_bits));
    if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(key_bits)), key_bits) < 0 ||
        !(key_bits[BTN_STYLUS / 8] & (1 << (BTN_STYLUS % 8))) ||
        !(key_bits[BTN_STYLUS2 / 8] & (1 << (BTN_STYLUS2 % 8)))) {
        fprintf(stderr, "dell_pen_bridge: %s does not report BTN_STYLUS/BTN_STYLUS2\n",
                options->event_node);
        close(fd);
        errno = ENODEV;
        return -1;
    }
    *out_fd = fd;
    return 0;
}

/* Sync the daemon state with the physical key state (EVIOCGKEY) right after
 * the node opens, so a button held across daemon start or reconnect neither
 * sticks DOWN forever nor sends an UP with no preceding DOWN. */
static int sync_initial_state(struct bridge *bridge) {
    unsigned char states[KEY_MAX / 8 + 1];
    memset(states, 0, sizeof(states));
    if (ioctl(bridge->ev_fd, EVIOCGKEY(sizeof(states)), states) < 0) return -1;
    bool key1 = (states[BTN_STYLUS / 8] >> (BTN_STYLUS % 8)) & 1;
    bool key2 = (states[BTN_STYLUS2 / 8] >> (BTN_STYLUS2 % 8)) & 1;
    if (key1 && !bridge->pen_key1_pressed &&
        apply_button(bridge, &bridge->pen_key1_pressed, true, KEY_PAGEDOWN,
                     "key1 BTN_STYLUS->KEY_PAGEDOWN") < 0)
        return -1;
    if (key2 && !bridge->pen_key2_pressed &&
        apply_button(bridge, &bridge->pen_key2_pressed, true, KEY_PAGEUP,
                     "key2 BTN_STYLUS2->KEY_PAGEUP") < 0)
        return -1;
    return 0;
}

/* Consume pending input_events from the pen node. Returns 0 on success,
 * -1 when the node failed and must be reopened. */
static int drain_events(struct bridge *bridge, double suppress_until) {
    for (;;) {
        struct input_event event;
        ssize_t amount = read(bridge->ev_fd, &event, sizeof(event));
        if (amount < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        if (amount == 0) {
            errno = ENODEV;
            return -1;
        }
        if ((size_t)amount < sizeof(event)) {
            /* evdev never returns partial events; treat a short read as fatal. */
            errno = EIO;
            return -1;
        }
        if (event.type != EV_KEY) continue;
        double now = mono_time();
        bool suppressed = now >= 0.0 && now < suppress_until;
        if (event.code == BTN_STYLUS) {
            if (event.value == 1 && !suppressed &&
                apply_button(bridge, &bridge->pen_key1_pressed, true, KEY_PAGEDOWN,
                             "key1 BTN_STYLUS->KEY_PAGEDOWN") < 0)
                return -1;
            if (event.value == 0 &&
                apply_button(bridge, &bridge->pen_key1_pressed, false, KEY_PAGEDOWN,
                             "key1 BTN_STYLUS->KEY_PAGEDOWN") < 0)
                return -1;
            /* value 2 = autorepeat; the virtual device declares no REP bit,
             * so repeats are ignored. */
        } else if (event.code == BTN_STYLUS2) {
            if (event.value == 1 && !suppressed &&
                apply_button(bridge, &bridge->pen_key2_pressed, true, KEY_PAGEUP,
                             "key2 BTN_STYLUS2->KEY_PAGEUP") < 0)
                return -1;
            if (event.value == 0 &&
                apply_button(bridge, &bridge->pen_key2_pressed, false, KEY_PAGEUP,
                             "key2 BTN_STYLUS2->KEY_PAGEUP") < 0)
                return -1;
        }
    }
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
    bridge.uinput_fd = bridge.ev_fd = bridge.lock_fd = -1;
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
    /* No PR_SET_PDEATHSIG on purpose: the daemon must outlive the su -c
     * shell that launched it. Lifetime is controlled by stop-file/signals. */
    if (acquire_lock(&bridge) < 0) {
        error_message("lock");
        if (bridge.lock_fd >= 0) close(bridge.lock_fd);
        return 1;
    }
    own_lock = true;
    int marker = stop_requested(options->stop_path);
    if (marker != 0) {
        bridge.reason = marker > 0 ? "stop_file" : "stop_file_error";
        result = marker > 0 ? 0 : 1;
        if (marker < 0) error_message("stop_file");
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
    fprintf(stdout, "dell_pen_bridge: started pid=%ld node=%s\n",
            (long)getpid(), options->event_node);
    fflush(stdout);

    /* Creation and InputReader discovery are asynchronous. Suppress startup
     * presses for the first second; the state sync only injects a DOWN for a
     * physically held button after the suppression window. */
    double suppress_until = mono_time() + STARTUP_SUPPRESS_SECONDS;
    double next_reopen = 0.0;
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

        if (bridge.ev_fd < 0) {
            if (now >= next_reopen) {
                if (open_event_node(options, &bridge.ev_fd) < 0) {
                    next_reopen = now + REOPEN_DELAY_MS / 1000.0;
                } else {
                    ++bridge.counts.reconnects;
                    bridge.status_dirty = true;
                    fprintf(stdout, "dell_pen_bridge: event node %s opened\n",
                            options->event_node);
                    fflush(stdout);
                    /* The uinput device has long been discovered by now, so
                     * clear the suppression window after a reconnect. */
                    suppress_until = 0.0;
                    if (sync_initial_state(&bridge) < 0) {
                        error_message("key_state_sync");
                        close(bridge.ev_fd);
                        bridge.ev_fd = -1;
                        next_reopen = now + REOPEN_DELAY_MS / 1000.0;
                    }
                }
            }
        }

        if (bridge.ev_fd >= 0) {
            struct pollfd descriptor = {.fd = bridge.ev_fd, .events = POLLIN, .revents = 0};
            int ready = poll(&descriptor, 1, POLL_TIMEOUT_MS);
            if (ready < 0) {
                if (errno != EINTR) {
                    bridge.reason = "poll_error";
                    error_message("poll");
                    break;
                }
            } else if (ready > 0) {
                if (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    ++bridge.counts.read_errors;
                    fprintf(stderr, "dell_pen_bridge: event node lost, will reopen\n");
                    if (release_all(&bridge) < 0) {
                        bridge.reason = "uinput_error";
                        error_message("uinput_release");
                        break;
                    }
                    close(bridge.ev_fd);
                    bridge.ev_fd = -1;
                    next_reopen = mono_time() + REOPEN_DELAY_MS / 1000.0;
                } else if (descriptor.revents & POLLIN) {
                    if (drain_events(&bridge, suppress_until) < 0) {
                        ++bridge.counts.read_errors;
                        fprintf(stderr, "dell_pen_bridge: event read failed (errno=%d),"
                                " will reopen\n", errno);
                        if (release_all(&bridge) < 0) {
                            bridge.reason = "uinput_error";
                            error_message("uinput_release");
                            break;
                        }
                        close(bridge.ev_fd);
                        bridge.ev_fd = -1;
                        next_reopen = mono_time() + REOPEN_DELAY_MS / 1000.0;
                    }
                }
            }
        } else {
            msleep(REOPEN_DELAY_MS / 10);
        }

        if (bridge.status_dirty || now - bridge.last_status >= STATUS_SECONDS) {
            if (status_write(&bridge, mono_time()) < 0) {
                bridge.reason = "status_error";
                bridge.status_error_reported = true;
                error_message("status");
                break;
            }
        }
    }

cleanup:
    if (bridge.uinput_created) {
        if (release_all(&bridge) < 0) {
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
    if (bridge.ev_fd >= 0) close(bridge.ev_fd);
    if (bridge.uinput_fd >= 0) close(bridge.uinput_fd);
    bridge.state = result == 0 ? "stopped" : "error";
    if (own_lock && status_write(&bridge, mono_time()) < 0 && !bridge.status_error_reported)
        error_message("final_status");
    fprintf(stdout, "dell_pen_bridge: stopped reason=%s key1_downs=%" PRIu64
            " key2_downs=%" PRIu64 " transitions=%" PRIu64 "\n",
            bridge.reason, bridge.counts.key1_downs, bridge.counts.key2_downs,
            bridge.counts.transitions);
    fflush(stdout);
    if (bridge.lock_fd >= 0) close(bridge.lock_fd);
    return result;
}

static void usage(FILE *output) {
    fprintf(output,
        "Usage: dell-pen-bridge --stop-file PATH --status PATH [--lock PATH]\n"
        "                       [--event-node PATH] [--max-seconds N]\n"
        "       dell-pen-bridge --help\n"
        "N=0 (default) runs until stopped. Live paths must be absolute.\n"
        "Defaults: event-node=/dev/input/event4\n"
        "Mapping: BTN_STYLUS -> KEY_PAGEDOWN (109), BTN_STYLUS2 -> KEY_PAGEUP (104).\n");
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
    options->event_node = DEFAULT_EVENT_NODE;
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
        } else {
            const char **slot = NULL;
            bool is_node = strcmp(name, "--event-node") == 0;
            if (!strcmp(name, "--stop-file")) slot = &options->stop_path;
            else if (!strcmp(name, "--status")) slot = &options->status_path;
            else if (!strcmp(name, "--lock")) slot = &options->lock_path;
            else if (is_node) slot = &options->event_node;
            else return -1;
            if (is_node) {
                if (strcmp(options->event_node, DEFAULT_EVENT_NODE) != 0) return -1;
            } else if (*slot) {
                return -1; /* path options may appear at most once */
            }
            if (value[0] != '/' || strlen(value) > PATH_MAX - 48) return -1;
            const char *existing[3] = {options->stop_path, options->status_path,
                                       options->lock_path};
            for (unsigned j = 0; j < 3; ++j)
                if (existing[j] && !strcmp(existing[j], value)) return -1;
            *slot = value;
        }
    }
    if (!options->stop_path || !options->status_path) return -1;
    return 0;
}

int main(int argc, char **argv) {
    struct options options;
    int parsed = parse_options(argc, argv, &options);
    if (parsed != 0) {
        usage(parsed > 0 ? stdout : stderr);
        return parsed > 0 ? 0 : 2;
    }
    return run_live(&options);
}
