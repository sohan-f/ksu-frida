LOCAL_PATH := $(call my-dir)

# ── Rust core (all module logic: config, inject, remap, child gating) ──────────
# Built by Gradle task :module:buildRustLibrary (cargo-ndk) before ndk-build runs.
include $(CLEAR_VARS)
LOCAL_MODULE := ksufrida_rust
ifeq ($(TARGET_ARCH_ABI),arm64-v8a)
RUST_TRIPLE := aarch64-linux-android
else ifeq ($(TARGET_ARCH_ABI),armeabi-v7a)
RUST_TRIPLE := armv7-linux-androideabi
else ifeq ($(TARGET_ARCH_ABI),x86)
RUST_TRIPLE := i686-linux-android
else ifeq ($(TARGET_ARCH_ABI),x86_64)
RUST_TRIPLE := x86_64-linux-android
endif
LOCAL_SRC_FILES := ../rust/target/$(RUST_TRIPLE)/release/libksufrida_rust.a
include $(PREBUILT_STATIC_LIBRARY)

# ── C++ shell (Zygisk ABI entry + Dobby shim) + vendored xDL ───────────────────
include $(CLEAR_VARS)

XDL_FILES := $(wildcard $(LOCAL_PATH)/xdl/*.c)

LOCAL_MODULE := zygiskfrida
LOCAL_SRC_FILES := main_zygisk.cpp dobby_shim.cpp $(XDL_FILES:$(LOCAL_PATH)/%=%)
LOCAL_STATIC_LIBRARIES := cxx dobby ksufrida_rust
LOCAL_C_INCLUDES := $(LOCAL_PATH)/xdl/include
LOCAL_LDLIBS := -llog -ldl -lm
LOCAL_LDFLAGS := -Wl,--version-script,$(LOCAL_PATH)/exports.map

include $(BUILD_SHARED_LIBRARY)

$(call import-module,prefab/cxx)
$(call import-module,prefab/dobby)
