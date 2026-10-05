SKIPUNZIP=1

MODULE_ID=@MODULE_ID@

if [ -z "$KSU" ]; then
  abort "! KernelSU is required (Magisk is not supported)"
fi

if [ "$BOOTMODE" != true ]; then
  abort "! Install from KernelSU Manager"
fi

TMP_MODULE_DIR=/data/local/tmp/libsec

if [ "$ARCH" != "arm" ] && [ "$ARCH" != "arm64" ] && [ "$ARCH" != "x86" ] && [ "$ARCH" != "x64" ]; then
  abort "! Unsupported platform: $ARCH"
else
  ui_print "- Device platform: $ARCH"
fi

: "${ZIPFILE:?ZIPFILE is not set}"
: "${MODPATH:?MODPATH is not set}"
: "${TMPDIR:?TMPDIR is not set}"

BUSYBOX_BIN=/data/adb/ksu/bin/busybox

if [ ! -f "$BUSYBOX_BIN" ]; then
  abort "! unable to locate KernelSU busybox ($BUSYBOX_BIN)"
fi

ui_print "- Using busybox: $BUSYBOX_BIN"

ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
if [ ! -f "$TMPDIR/verify.sh" ]; then
  ui_print    "*********************************************************"
  ui_print    "! Unable to extract verify.sh!"
  ui_print    "! This zip may be corrupted, please try downloading again"
  abort "*********************************************************"
fi
. "$TMPDIR/verify.sh"

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop' "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh' "$MODPATH"
extract "$ZIPFILE" 'service.sh' "$MODPATH"

mkdir -p "$MODPATH/webroot"
extract "$ZIPFILE" 'webroot/index.html' "$MODPATH/webroot" true
extract "$ZIPFILE" 'webroot/main.js' "$MODPATH/webroot" true

LIB32_NAME="armeabi-v7a.so"
LIB64_NAME="arm64-v8a.so"
LIB32_DEST="$MODPATH/zygisk"
LIB64_DEST="$MODPATH/zygisk"

[ "$ARCH" = "x86" ] || [ "$ARCH" = "x64" ] && LIB32_NAME="x86.so"
[ "$ARCH" = "x86" ] || [ "$ARCH" = "x64" ] && LIB64_NAME="x86_64.so"

mkdir -p "$LIB32_DEST"
mkdir -p "$LIB64_DEST"

ui_print "- Extracting 32-bit libraries"
extract "$ZIPFILE" "lib/$LIB32_NAME" "$LIB32_DEST" true

if [ "$IS64BIT" = true ]; then
  ui_print "- Extracting 64-bit libraries"
  extract "$ZIPFILE" "lib/$LIB64_NAME" "$LIB64_DEST" true
fi

ui_print "- Installing bundled frida gadget"

GADGET_DIR="$MODPATH/gadget"
mkdir -p "$GADGET_DIR"
mkdir -p "$TMP_MODULE_DIR"

extract "$ZIPFILE" "gadget/libgadget-$ARCH.so.xz" "$GADGET_DIR" true
mv -f "$GADGET_DIR/libgadget-$ARCH.so.xz" "$GADGET_DIR/libsecmon.so.xz"
rm -f "$TMP_MODULE_DIR/libsecmon.so.xz" "$TMP_MODULE_DIR/libsecmon.so"
cp -f "$GADGET_DIR/libsecmon.so.xz" "$TMP_MODULE_DIR/libsecmon.so.xz"
$BUSYBOX_BIN unxz -f "$TMP_MODULE_DIR/libsecmon.so.xz" || abort "! failed to decompress gadget (storage full?)"

if [ "$IS64BIT" = true ]; then
  ARCH32="arm"
  [ "$ARCH" = "x64" ] && ARCH32="x86"

  extract "$ZIPFILE" "gadget/libgadget-$ARCH32.so.xz" "$GADGET_DIR" true
  mv -f "$GADGET_DIR/libgadget-$ARCH32.so.xz" "$GADGET_DIR/libsecmon32.so.xz"
  rm -f "$TMP_MODULE_DIR/libsecmon32.so.xz" "$TMP_MODULE_DIR/libsecmon32.so"
  cp -f "$GADGET_DIR/libsecmon32.so.xz" "$TMP_MODULE_DIR/libsecmon32.so.xz"
  $BUSYBOX_BIN unxz -f "$TMP_MODULE_DIR/libsecmon32.so.xz" || abort "! failed to decompress 32-bit gadget (storage full?)"
fi

extract "$ZIPFILE" "config.json.example" "$GADGET_DIR" true
rm -f "$TMP_MODULE_DIR/config.json.example"
cp -f "$GADGET_DIR/config.json.example" "$TMP_MODULE_DIR/config.json.example"
extract "$ZIPFILE" "gadget/gadget.version" "$GADGET_DIR" true

if [ ! -e "$TMP_MODULE_DIR/config.json" ] && [ ! -L "$TMP_MODULE_DIR/config.json" ]; then
  rm -f "$TMP_MODULE_DIR/config.json"
  cp "$TMP_MODULE_DIR/config.json.example" "$TMP_MODULE_DIR/config.json"
fi
if [ ! -e "$TMP_MODULE_DIR/libsecmon.config.so" ] && [ ! -L "$TMP_MODULE_DIR/libsecmon.config.so" ]; then
  rm -f "$TMP_MODULE_DIR/libsecmon.config.so"
  echo '{"interaction":{"type":"listen","address":"127.0.0.1","port":27042,"on_port_conflict":"pick-next"}}' > "$TMP_MODULE_DIR/libsecmon.config.so"
fi

set_perm_recursive "$TMP_MODULE_DIR" 0 0 0711 0644
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/service.sh" 0 0 0755
