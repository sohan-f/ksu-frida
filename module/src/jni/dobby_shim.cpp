#include <dobby.h>

extern "C" int ksufrida_dobby_hook(void *addr, void *replace, void **orig) {
    if (addr == nullptr || replace == nullptr || orig == nullptr) {
        return -1;
    }
    return DobbyHook(addr, replace, orig);
}
