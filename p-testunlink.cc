#include "u-lib.hh"

void process_main() {
    printf("Testing unlinking (assuming clean file system)...\n");

    // open
    printf("%s:%d: open...\n", __FILE__, __LINE__);
    int fd = sys_open("dickinson.txt", OF_WRITE);
    assert_gt(fd, 2);

    printf("%s:%d: close...\n", __FILE__, __LINE__);
    int status = sys_close(fd);
    assert_eq(status, 0);

    printf("%s:%d: unlink...\n", __FILE__, __LINE__);
    status = sys_unlink("dickinson.txt");
    assert_eq(status, 0);

    printf("%s:%d: sync...\n", __FILE__, __LINE__);
    status = sys_sync(1);
    assert_eq(status, 0);

    fd = sys_open("dickinson.txt", OF_WRITE);
    // file should be gone
    assert_le(fd, 0);

    printf("testunlink succeeded.\n");
    sys_exit(0);
}
