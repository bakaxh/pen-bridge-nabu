#!/system/bin/sh
MODDIR=${0%/*}
exec /data/adb/ksu/bin/busybox sh "$MODDIR/bin/control.sh" toggle
