#include "u-lib.hh"

void process_main() {
    while (true) {
        // wait for any child
        sys_waitpid(0);
    }
}
