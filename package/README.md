# Third-party Pen Button Bridge for Xiaomi Pad 5 (nabu)

将第三方 MPP 触控笔（联想 Precision Pen 2 等）的两个物理侧键桥接为
`Xiaomi Smart Pen Keyboard` 虚拟输入设备的两个独立按键，由 Notein 直接识别
并在其按键自定义设置中分别配置动作。

v0.3.0 起不再使用 eBPF/SPI 抓取方案。当前已修复的内核把两个笔键作为独立
EV_KEY 事件上报到触控笔事件节点（实测 `/dev/input/event4`）：

| 物理按键 | evdev 事件 | 虚拟按键 |
|---|---|---|
| 笔键 1 | `BTN_STYLUS` | `KEY_PAGEDOWN` (109) |
| 笔键 2 | `BTN_STYLUS2` | `KEY_PAGEUP` (104) |

## 工作原理

1. 守护进程以只读方式打开 `/dev/input/event4`。evdev 会把事件分发给所有
   打开的读取者，因此**不会拦截或破坏**原始触控笔事件，悬浮与书写路径
   （InputReader → Notein 的 Xiaomi Pen 识别）完全不受影响。
2. 每个按键维护独立的布尔状态；`DOWN/UP` 幂等去重，双键可同时按下、独立
   释放，不存在误释放或状态卡死。
3. 经 uinput 注入与 v0.2.0 实测验证完全相同的虚拟设备：名称
   `Xiaomi Smart Pen Keyboard`、能力 `EV_SYN+EV_KEY(KEY_PAGEUP/KEY_PAGEDOWN)`、
   `BUS_VIRTUAL`，上报顺序为 EV_KEY×N + EV_SYN(SYN_REPORT)。
4. 事件节点断开（驱动重载等）时自动释放已按下的虚拟键、重置状态，并按
   1 s 周期重连；重连后用 `EVIOCGKEY` 同步物理按键实际状态，不会卡键。
5. 单实例 flock 锁、stop 文件、原子 JSON 状态输出、TERM/INT/HUP 信号处理、
   `--max-seconds` 受限运行、退出前先释放按键再销毁虚拟设备（100 ms 缓冲）。
   故意**不设置** `PR_SET_PDEATHSIG`，避免被短命的 `su -c` shell 带走。

## 安装

1. 小米平板 5（nabu）刷 ColorOS 17（已修复内核），Root（KernelSU 或 Magisk）。
2. 刷入本模块 zip（`dist/Pen-Bridge-nabu-Root-vX.zip`）并重启，开机自动启动。
3. 在 Notein 按键自定义设置中为按键 1（PAGEDOWN）和按键 2（PAGEUP）分别
   配置动作。
4. 验证：

   ```sh
   su
   /data/adb/modules/dell_pen_bridge_nabu/bin/control.sh test
   # 分别按两个侧键数次后看 key1_downs / key2_downs 是否分别递增
   ```

## 控制

- KernelSU / Magisk 模块动作按钮 = `control.sh toggle`（暂停 / 恢复）。
- `control.sh start|stop|status|test`。
- 可选 `/data/adb/dell_pen_bridge_nabu/bridge.conf`：`EVENT_NODE=/dev/input/eventN`
  覆盖默认事件节点（如内核更新后节点编号变化）。
- 若实测两键物理对应关系相反：只需交换源码顶部 `BTN_STYLUS→KEY_PAGEDOWN` 与
  `BTN_STYLUS2→KEY_PAGEUP` 的映射并重新编译，底层事件读取机制不变。

## 安全说明

- 只注入 `KEY_PAGEDOWN` / `KEY_PAGEUP` 两个按键，不触碰坐标、压力、tilt、
  触摸事件，不修改 Notein，不使用 LSPosed，不做 manufacture 伪装。
- 只读 evdev 节点，不写任何内核内存，不加载任何 BPF 程序。

## 构建

```sh
python build_module.py            # 需要 zig（编译 aarch64-linux-musl 静态二进制）
python build_module.py --package-only
```
