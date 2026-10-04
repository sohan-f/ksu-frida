MODDIR=${0%/*}
SEC_DIR=/data/local/tmp/libsec
BUSYBOX_BIN=/data/adb/ksu/bin/busybox

[ -f "$BUSYBOX_BIN" ] || exit 0
mkdir -p "$SEC_DIR"

if [ ! -f "$SEC_DIR/libsecmon.so" ] && [ -f "$MODDIR/gadget/libsecmon.so.xz" ]; then
  cp -f "$MODDIR/gadget/libsecmon.so.xz" "$SEC_DIR/libsecmon.so.xz"
  $BUSYBOX_BIN unxz -f "$SEC_DIR/libsecmon.so.xz"
fi

if [ ! -f "$SEC_DIR/libsecmon32.so" ] && [ -f "$MODDIR/gadget/libsecmon32.so.xz" ]; then
  cp -f "$MODDIR/gadget/libsecmon32.so.xz" "$SEC_DIR/libsecmon32.so.xz"
  $BUSYBOX_BIN unxz -f "$SEC_DIR/libsecmon32.so.xz"
fi

if [ ! -f "$SEC_DIR/config.json" ] && [ -f "$MODDIR/gadget/config.json.example" ]; then
  cp "$MODDIR/gadget/config.json.example" "$SEC_DIR/config.json"
fi

if [ ! -f "$SEC_DIR/libsecmon.config.so" ]; then
  echo '{"interaction":{"type":"listen","address":"127.0.0.1","port":27042,"on_port_conflict":"pick-next"}}' > "$SEC_DIR/libsecmon.config.so"
fi
