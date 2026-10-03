APP_ABI      := armeabi-v7a arm64-v8a x86 x86_64
APP_CPPFLAGS := -std=c++17 -fno-exceptions -fno-rtti -fvisibility=hidden -fvisibility-inlines-hidden
APP_STL      := none
APP_PLATFORM := android-21
# 16 KB page-size devices (NDK < r28 does not align segments by default)
APP_LDFLAGS  += -Wl,-z,max-page-size=16384
