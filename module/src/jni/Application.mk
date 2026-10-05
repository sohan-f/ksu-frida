APP_ABI      := armeabi-v7a arm64-v8a x86 x86_64
APP_CPPFLAGS := -std=c++17 -fno-exceptions -fno-rtti -fvisibility=hidden -fvisibility-inlines-hidden -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fno-omit-frame-pointer
APP_STL      := none
APP_PLATFORM := android-31
# 16 KB page-size devices (NDK < r28 does not align segments by default)
APP_LDFLAGS  += -Wl,-z,max-page-size=16384 -Wl,-z,relro -Wl,-z,now
