// https://man.openbsd.org/fuse_main.3
#define FUSE_USE_VERSION 31
#include <errno.h>
#include <fuse3/fuse.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

static int fs_readdir(const char *path, void *data, fuse_fill_dir_t filler,
           off_t off, struct fuse_file_info *ffi, enum fuse_readdir_flags flags)
{
    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(data, ".", NULL, 0, 0);
    filler(data, "..", NULL, 0, 0);
    filler(data, "file", NULL, 0, 0);
    return 0;
}

static int fs_read(const char *path, char *buf, size_t size, off_t off,
        struct fuse_file_info *ffi)
{
    size_t len;
    const char *file_contents = "fuse filesystem example\n";

    len = strlen(file_contents);

    if (off < len) {
        if (off + size > len)
            size = len - off;
        memcpy(buf, file_contents + off, size);
    } else
        size = 0;

    return size;
}

static int fs_open(const char *path, struct fuse_file_info *ffi)
{
    if (strncmp(path, "/file", 10) != 0)
        return -ENOENT;

    if ((ffi->flags & 3) != O_RDONLY)
        return -EACCES;

    return 0;
}

static int fs_getattr(const char *path, struct stat *st, struct fuse_file_info *fi)
{
    (void) fi; // Suppress unused parameter warning
    memset(st, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        st->st_mode = 0755 | S_IFDIR;
        st->st_nlink = 2;
    } else if (strcmp(path, "/file") == 0) {
        st->st_mode = 0644 | S_IFREG;
        st->st_nlink = 1;
        st->st_size = strlen("fuse filesystem example\n");
    } else {
        return -ENOENT;
    }
    return 0;
}

struct fuse_operations fsops = {
    .readdir = fs_readdir,
    .read = fs_read,
    .open = fs_open,
    .getattr = fs_getattr,
};

int main(int argc, char **argv)
{
    return fuse_main(argc, argv, &fsops, NULL);
}