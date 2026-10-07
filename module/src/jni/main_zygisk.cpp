#include <sys/types.h>

#include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

extern "C" bool ksufrida_handle_app(JNIEnv *env, jstring name);

class MyModule : public zygisk::ModuleBase {
 public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (this->api == nullptr) {
            return;
        }
        const jstring name = (args != nullptr) ? args->nice_name : nullptr;
        if (!ksufrida_handle_app(this->env, name)) {
            this->api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void postServerSpecialize(const ServerSpecializeArgs *args) override {
        (void)args;
        if (this->api == nullptr) {
            return;
        }
        this->api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

 private:
    Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(MyModule)
