#include "u-lib.hh"
void process_main() {
    printf("Testing renaming (assuming clean file system)...\n");

    printf("%s:%d: open...\n", __FILE__, __LINE__);
    int fd = sys_open("dickinson.txt", OF_WRITE);
    assert_gt(fd, 2);

    printf("%s:%d: move...\n", __FILE__, __LINE__);
    int status = sys_rename("dickinson.txt", "new.txt");
    assert_eq(status, 0);

    printf("%s:%d: close...\n", __FILE__, __LINE__);
    status = sys_close(fd);
    assert_eq(status, 0);

    printf("%s:%d: open...\n", __FILE__, __LINE__);
    fd = sys_open("new.txt", OF_READ);
    assert_ge(fd, 2);

    printf("%s:%d: read...\n", __FILE__, __LINE__);
    char buf[200] = { 0 };
    int n = sys_read(fd, buf, 10);
    assert_eq(n, 10);

    printf("%s:%d: close...\n", __FILE__, __LINE__);
    status = sys_close(fd);
    assert_eq(status, 0);

    printf("%s:%d: sync...\n", __FILE__, __LINE__);
    status = sys_sync(2);
    assert_eq(status, 0);

    printf("%s:%d: open...\n", __FILE__, __LINE__);
    fd = sys_open("emerson.txt", OF_WRITE);
    assert_ge(fd, 2);

    printf("%s:%d: rename with clobber...\n", __FILE__, __LINE__);
    status = sys_rename("emerson.txt", "new.txt");
    assert_eq(status, 0);

    printf("%s:%d: close...\n", __FILE__, __LINE__);
    status = sys_close(fd);
    assert_eq(status, 0);

    printf("%s:%d: sync...\n", __FILE__, __LINE__);
    status = sys_sync(2);
    assert_eq(status, 0);

    printf("%s:%d: open...\n", __FILE__, __LINE__);
    fd = sys_open("new.txt", OF_READ);
    assert_ge(fd, 2);

    printf("%s:%d: read new...\n", __FILE__, __LINE__);
    n = sys_read(fd, buf, 10);
    assert_memeq(buf, "When piped", 10);

    printf("%s:%d: close...\n", __FILE__, __LINE__);
    status = sys_close(fd);
    assert_eq(status, 0);

    printf("testrename succeeded.\n");
    sys_exit(0);
}
