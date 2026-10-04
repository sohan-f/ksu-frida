#include <string>

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
        // Both pointers can be null (OOM); std::string(nullptr) is UB.
        if (args->nice_name == nullptr) {
            this->api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        const char *raw_app_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (raw_app_name == nullptr) {
            this->api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        std::string app_name = std::string(raw_app_name);
        this->env->ReleaseStringUTFChars(args->nice_name, raw_app_name);

        if (!ksufrida_check_and_inject(app_name.c_str())) {
            this->api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }

 private:
    Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MyModule)
