// https://man.openbsd.org/fuse_main.3
//https://libfuse.github.io/doxygen/structfuse__operations.html
#define FUSE_USE_VERSION 31
#include <errno.h>
#include <fuse3/fuse.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stddef.h>
#include <dirent.h>
#include <sys/types.h>

#define MAX_FILEPATH_LENGTH 4096

struct options {
    char *username;
    char *host_ip;
    char *remote_path;
    char *local_cache;
} options;

#define OPTION(t, p) {t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("--user=%s", username),
    OPTION("--host-ip=%s", host_ip),
    OPTION("--remote-path=%s", remote_path),
    OPTION("--local-cache=%s", local_cache),
    FUSE_OPT_END
};

static void *myfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void) conn;
    printf("Initializing FUSE NFS...\n");
    printf("Options - User: %s, Host IP: %s, Remote Path: %s, Local Cache: %s\n",
           options.username, options.host_ip, options.remote_path, options.local_cache);
    return NULL;
}

static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    printf("myfs_getattr called with path: %s\n", path);

    // Turns out you have to deal with root dir!
    // https://www.qualys.com/2021/07/20/cve-2021-33910/cve-2021-33910-crasher.c
    // 0755 is basically giving read,write privilege i.e. it is like chmod +x 
    // https://superuser.com/questions/404592/chmod-equivalence-of-x-and-0755

    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755; // Directory with permissions
        stbuf->st_nlink = 2; // Default link count for directories
        return 0;
    }

    char cache_fp[MAX_FILEPATH_LENGTH];
    
    int res = stat(cache_fp, stbuf);
    if (res == -1) {
        perror("Error in myfs_getattr - stat");
        return -errno;
    }
    return 0;
}


static struct fuse_operations myfs_operations = {
    .init = myfs_init,
    .getattr = myfs_getattr,
    // .create = myfs_create,
    // .write = myfs_write,
    // .readdir = myfs_readdir,
    // .read = myfs_read
};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    
    // Random defaults
    options.username = strdup("rwik");
    options.host_ip = strdup("127.0.0.1");
    options.remote_path = strdup("/remote/default");
    options.local_cache = strdup("/tmp/myfs_cache");

    int fuse_opt_parse_ret = fuse_opt_parse(&args, &options, option_spec, NULL);
    if (fuse_opt_parse_ret == -1){
        return 1;
    }

    int ret = fuse_main(args.argc, args.argv, &myfs_operations, NULL);
    fuse_opt_free_args(&args);
    return ret;
}