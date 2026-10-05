#include <sys/types.h>

#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

extern "C" bool ksufrida_check_and_inject(const char *app_name);

class MyModule : public zygisk::ModuleBase {
 public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        // Both pointers can be null (OOM).
        if (args == nullptr || args->nice_name == nullptr) {
            this->api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        const char *raw_app_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (raw_app_name == nullptr) {
            env->ExceptionClear();
            this->api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        // The JNI pointer stays valid until released; the Rust side copies it synchronously.
        bool keep = ksufrida_check_and_inject(raw_app_name);
        this->env->ReleaseStringUTFChars(args->nice_name, raw_app_name);

        if (!keep) {
            this->api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void postServerSpecialize(const ServerSpecializeArgs *args) override {
        (void)args;
        this->api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

 private:
    Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MyModule)
