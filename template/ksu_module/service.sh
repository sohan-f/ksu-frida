MODDIR=${0%/*}
SEC_DIR=/data/local/tmp/libsec
BUSYBOX_BIN=/data/adb/ksu/bin/busybox

if [ ! -f "$BUSYBOX_BIN" ]; then
  echo "KsuFrida: busybox missing at $BUSYBOX_BIN, skipping boot setup" >&2
  exit 0
fi
mkdir -p "$SEC_DIR"
chmod 0711 "$SEC_DIR"

# Always refresh from the module dir (root-owned): a planted symlink or
# tampered .so in world-writable $SEC_DIR must never survive a boot.
refresh_gadget() {
  xz_name=$1
  so_name=$2
  [ -f "$MODDIR/gadget/$xz_name" ] || return 0
  if [ -f "$MODDIR/gadget/$xz_name.sha256sum" ]; then
    want=$(cat "$MODDIR/gadget/$xz_name.sha256sum")
    got=$($BUSYBOX_BIN sha256sum "$MODDIR/gadget/$xz_name" 2>/dev/null | cut -d' ' -f1)
    if [ "$got" != "$want" ]; then
      echo "KsuFrida: gadget hash mismatch for $xz_name, skipping" >&2
      return 0
    fi
  fi
  rm -f "$SEC_DIR/$xz_name" "$SEC_DIR/$so_name"
  cp -f "$MODDIR/gadget/$xz_name" "$SEC_DIR/$xz_name" || return 0
  if ! $BUSYBOX_BIN unxz -f "$SEC_DIR/$xz_name"; then
    echo "KsuFrida: failed to decompress $xz_name" >&2
    rm -f "$SEC_DIR/$so_name"
    return 0
  fi
  chmod 0644 "$SEC_DIR/$so_name"
}

refresh_gadget "libsecmon.so.xz" "libsecmon.so"
refresh_gadget "libsecmon32.so.xz" "libsecmon32.so"

if [ ! -e "$SEC_DIR/config.json" ] && [ ! -L "$SEC_DIR/config.json" ] && [ -f "$MODDIR/gadget/config.json.example" ]; then
  rm -f "$SEC_DIR/config.json"
  cp "$MODDIR/gadget/config.json.example" "$SEC_DIR/config.json"
  chmod 0644 "$SEC_DIR/config.json"
fi

if [ ! -e "$SEC_DIR/libsecmon.config.so" ] && [ ! -L "$SEC_DIR/libsecmon.config.so" ]; then
  rm -f "$SEC_DIR/libsecmon.config.so"
  echo '{"interaction":{"type":"listen","address":"127.0.0.1","port":27042,"on_port_conflict":"pick-next"}}' > "$SEC_DIR/libsecmon.config.so"
  chmod 0644 "$SEC_DIR/libsecmon.config.so"
fi
