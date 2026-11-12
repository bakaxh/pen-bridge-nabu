#!/system/bin/sh
MODDIR=${0%/*}
/data/adb/ksu/bin/busybox sh "$MODDIR/bin/control.sh" stop
# Runtime lives in tmpfs and vanishes on reboot. Keep lock inodes intact here.
