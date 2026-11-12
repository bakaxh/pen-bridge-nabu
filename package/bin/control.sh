#!/system/bin/sh
# nabu pen-button bridge (evdev edition). The daemon reads the two physical
# barrel buttons (BTN_STYLUS / BTN_STYLUS2) directly from the pen's evdev node
# and injects independent virtual keys through uinput. No calibration, no BPF,
# no kernel memory access; the node auto-reopens if it disappears.
MODDIR=$(CDPATH= cd "$(dirname "$0")/.." && pwd) || exit 1
RUNDIR=/dev/dell_pen_bridge_nabu
CONFDIR=/data/adb/dell_pen_bridge_nabu
CONF=$CONFDIR/bridge.conf
NATIVE=$MODDIR/bin/dell-pen-bridge
MODE=${1:-status}

if [ -x /data/adb/ksu/bin/busybox ]; then
  BB=/data/adb/ksu/bin/busybox
elif [ -x /data/adb/magisk/busybox ]; then
  BB=/data/adb/magisk/busybox
else
  BB=busybox
fi

setup_runtime() {
  [ ! -L "$RUNDIR" ] || return 1
  if [ ! -d "$RUNDIR" ]; then mkdir -m 700 "$RUNDIR" || return 1; fi
  chown 0:0 "$RUNDIR" || return 1
  chmod 700 "$RUNDIR" || return 1
}

start_ticks() {
  # comm may contain spaces; remove it before counting the remaining fields.
  sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'
}

owned_pid() {
  PID=
  [ -f "$1" ] || return 1
  read -r candidate ticks < "$1"
  case "$candidate:$ticks" in *[!0-9:]*|:|*:) return 1 ;; esac
  [ "$candidate" -gt 1 ] 2>/dev/null || return 1
  [ "$(start_ticks "$candidate")" = "$ticks" ] || return 1
  commandline=$(tr '\000' ' ' < "/proc/$candidate/cmdline" 2>/dev/null)
  case "$commandline" in *"$2"*) PID=$candidate; return 0 ;; esac
  return 1
}

native_alive() {
  if owned_pid "$RUNDIR/native.pid" "$NATIVE"; then return 0; fi
  # A signal can arrive before the PID file is committed. Only our actual
  # direct child with the expected executable may be used as a fallback.
  [ -n "${CHILD:-}" ] || return 1
  parent=$(sed 's/.*) //' "/proc/$CHILD/stat" 2>/dev/null | awk '{print $2}')
  [ "$parent" = "$$" ] || return 1
  commandline=$(tr '\000' ' ' < "/proc/$CHILD/cmdline" 2>/dev/null)
  case "$commandline" in *"$NATIVE"*) PID=$CHILD; return 0 ;; esac
  return 1
}
service_alive() { owned_pid "$RUNDIR/service.pid" "$MODDIR/bin/control.sh run"; }

stop_native() {
  if native_alive; then
    kill -TERM "$PID" 2>/dev/null
    tries=0
    while native_alive && [ "$tries" -lt 3 ]; do sleep 1; tries=$((tries+1)); done
    if native_alive; then kill -KILL "$PID" 2>/dev/null; fi
  fi
}

cleanup_run() {
  trap - EXIT HUP INT TERM
  stop_native
  # Never block cleanup waiting for an unverified live process.
  if [ -n "${CHILD:-}" ]; then
    child_state=$(sed 's/.*) //' "/proc/$CHILD/stat" 2>/dev/null | awk '{print $1}')
    case "$child_state" in ''|Z) wait "$CHILD" 2>/dev/null ;; esac
  fi
  rm -f "$RUNDIR/native.pid" "$RUNDIR/service.pid"
  echo '已停止，按键已释放。'
  # service.lock stays on disk. Unlinking a held lock permits a second owner.
}

native_flags() {
  FLAGS="--stop-file $RUNDIR/stop --status $RUNDIR/status.json --lock $RUNDIR/native.lock"
  if [ -f "$CONF" ]; then
    . "$CONF" || return 1
    case "${EVENT_NODE:-}" in /*) FLAGS="$FLAGS --event-node $EVENT_NODE" ;; esac
  fi
}

run_service() {
  setup_runtime || exit 1
  exec 9> "$RUNDIR/service.lock" || exit 1
  "$BB" flock -n 9 || { echo '已有桥接进程运行'; exit 0; }
  # Optional bounded staging test; normal module runs until explicitly stopped.
  LIMIT=${2:-0}
  case "$LIMIT" in ''|*[!0-9]*) echo '无效的运行时限'; exit 1 ;; esac
  [ "$LIMIT" -le 3600 ] || exit 1
  for flag in disable remove paused; do [ ! -e "$MODDIR/$flag" ] || exit 0; done
  "$BB" sh "$MODDIR/bin/check.sh" || exit 1
  native_flags || exit 1
  native_alive && { echo '已有独立桥接进程，拒绝重复启动'; exit 1; }
  if grep -Fq 'N: Name="Xiaomi Smart Pen Keyboard"' /proc/bus/input/devices; then
    echo '已有同名笔设备，请先停止其他测试程序。'; exit 1
  fi
  rm -f "$RUNDIR/stop"
  printf '%s %s\n' "$$" "$(start_ticks $$)" > "$RUNDIR/service.pid.tmp"
  mv "$RUNDIR/service.pid.tmp" "$RUNDIR/service.pid"
  CHILD=
  trap cleanup_run EXIT
  trap 'exit 0' HUP INT TERM
  # shellcheck disable=SC2086
  "$NATIVE" $FLAGS --max-seconds "$LIMIT" &
  CHILD=$!
  printf '%s %s\n' "$CHILD" "$(start_ticks "$CHILD")" > "$RUNDIR/native.pid.tmp"
  mv "$RUNDIR/native.pid.tmp" "$RUNDIR/native.pid"
  # Let EventHub discover the device; the daemon suppresses queued presses.
  sleep 1
  native_alive || { echo '按键程序启动失败'; cat "$RUNDIR/run.log" 2>/dev/null; exit 1; }
  echo '运行中：笔键1→PAGEDOWN，笔键2→PAGEUP（在 Notein 按键自定义中配置动作）。'
  while native_alive; do
    if [ -e "$MODDIR/disable" ] || [ -e "$MODDIR/remove" ] || \
       [ -e "$MODDIR/paused" ] || [ -e "$RUNDIR/stop" ]; then break; fi
    sleep 2
  done
  exit 0
}

start_service() {
  setup_runtime || return 1
  for flag in disable remove paused; do
    if [ -e "$MODDIR/$flag" ]; then echo '模块当前已停用或暂停'; return 1; fi
  done
  if service_alive; then echo '已经运行'; return 0; fi
  "$BB" sh "$MODDIR/bin/check.sh" || return 1
  [ ! -e "$RUNDIR/run.log" ] || mv -f "$RUNDIR/run.log" "$RUNDIR/run.previous.log"
  nohup "$BB" setsid "$BB" sh "$MODDIR/bin/control.sh" run > "$RUNDIR/run.log" 2>&1 < /dev/null &
}

stop_service() {
  setup_runtime || return 1
  touch "$RUNDIR/stop"
  if service_alive; then kill -TERM "$PID" 2>/dev/null; fi
  tries=0
  while service_alive && [ "$tries" -lt 6 ]; do sleep 1; tries=$((tries+1)); done
  if service_alive; then
    stop_native
    if service_alive; then kill -KILL "$PID"; fi
  fi
  # Acquire the same service lock before orphan cleanup. Never race a live owner.
  exec 8> "$RUNDIR/service.lock" || return 1
  lock_tries=0
  until "$BB" flock -n 8; do
    lock_tries=$((lock_tries+1))
    [ "$lock_tries" -lt 8 ] || { echo '停止超时，未清理其他进程的资源'; return 1; }
    sleep 0.5
  done
  stop_native
  rm -f "$RUNDIR/native.pid" "$RUNDIR/service.pid"
  echo '桥接已停止'
}

# Bounded button test: run the daemon for 30 seconds, then show counters so
# the user can verify both barrel buttons independently: key1_downs (笔键 1)
# and key2_downs (笔键 2) should increment separately.
button_test() {
  "$BB" sh "$MODDIR/bin/check.sh" || exit 1
  setup_runtime || exit 1
  if service_alive || native_alive; then echo '请先 control.sh stop'; exit 1; fi
  echo '请让笔悬浮或接触屏幕，分别按动两个侧键数次（30 秒）…'
  "$BB" sh "$MODDIR/bin/control.sh" run 30 || exit 1
  sleep 1
  echo '--- 测试结果 ---'
  cat "$RUNDIR/status.json" 2>/dev/null || echo '无状态输出'
  echo 'key1_downs（笔键1→PAGEDOWN）与 key2_downs（笔键2→PAGEUP）'
  echo '分别大于 0 且互不影响，表示双键状态机正常。'
}

case "$MODE" in
  run) run_service "$@" ;;
  start) start_service ;;
  boot)
    tries=0
    while [ "$(/system/bin/getprop sys.boot_completed)" != 1 ] && [ "$tries" -lt 60 ]; do
      sleep 2; tries=$((tries+1))
    done
    [ "$(/system/bin/getprop sys.boot_completed)" = 1 ] && start_service
    ;;
  stop) stop_service ;;
  test) button_test ;;
  toggle)
    if [ -e "$MODDIR/disable" ] || [ -e "$MODDIR/remove" ]; then
      echo '请先在 Root 管理器启用模块，或取消卸载。'; exit 1
    fi
    if [ -e "$MODDIR/paused" ]; then
      rm -f "$MODDIR/paused"
      start_service || exit 1
      sleep 2
      if native_alive; then echo '已恢复，动作仍在焦点笔 Plus 中设置。'; else cat "$RUNDIR/run.log"; exit 1; fi
    else
      touch "$MODDIR/paused"
      stop_service || exit 1
      echo '已暂停；再次点击动作按钮恢复。'
    fi
    ;;
  status)
    if native_alive; then echo '运行中'; else echo '未运行'; fi
    [ ! -f "$RUNDIR/status.json" ] || cat "$RUNDIR/status.json"
    ;;
  *) echo '用法：control.sh start|stop|status|toggle|test'; exit 2 ;;
esac
