
#include <dobby.h>

extern "C" int ksufrida_dobby_hook(void *addr, void *replace, void **orig) {
    return DobbyHook(addr, replace, orig);
}
