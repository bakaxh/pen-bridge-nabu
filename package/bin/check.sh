#!/system/bin/sh
# Environment guard for nabu (evdev edition). Run at installation AND before
# each activation. The daemon only needs the pen's evdev node and uinput.
fail() { echo "不启动：$*"; exit 1; }
[ "$(id -u)" = 0 ] || fail "需要 Root"
[ "$(/system/bin/getprop ro.product.device)" = nabu ] || fail "仅支持小米平板 5（nabu）"
[ -c /dev/uinput ] || fail "系统不提供 uinput"
# Pen barrel buttons: BTN_STYLUS / BTN_STYLUS2 on /dev/input/event4 (verified).
[ -e /dev/input/event4 ] || fail "缺少 /dev/input/event4（触控笔事件节点）"
# Optional override; keep the default node requirement unless configured.
NODE=/dev/input/event4
if [ -f /data/adb/dell_pen_bridge_nabu/bridge.conf ]; then
  . /data/adb/dell_pen_bridge_nabu/bridge.conf 2>/dev/null || true
  case "${EVENT_NODE:-}" in /*) NODE=$EVENT_NODE ;; esac
fi
[ -e "$NODE" ] || fail "事件节点 $NODE 不存在"
echo '设备与内核 evdev 校验通过'
