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

#define MAX_FILEPATH_LENGTH 8192
#define MAX_COMMAND_LENGTH (MAX_FILEPATH_LENGTH * 2 + 32)

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

// Remove everything from cache before starting
// Clear all files from the local cache directory
void clear_local_cache(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) {
        perror("Error opening cache directory in clear_local_cache");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // Construct the full path to the file
        char file_path[MAX_FILEPATH_LENGTH];
        snprintf(file_path, sizeof(file_path), "%s/%s", path, entry->d_name);

        // Remove the file
        if (remove(file_path) == -1) {
            perror("Error removing file in clear_local_cache");
        } else {
            printf("Removed file: %s\n", file_path);
        }
    }

    closedir(dir);
}


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
    snprintf(cache_fp, sizeof(cache_fp), "%s%s", options.local_cache, path);

    int res = stat(cache_fp, stbuf);
    if (res == -1) {
        perror("Error in myfs_getattr - stat");
        return -errno;
    }
    return 0;
}

static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
                        off_t offset, struct fuse_file_info *fi, 
                        enum fuse_readdir_flags flags) {

    // give complete path
    if (strcmp(path, "/") != 0)
        return -ENOENT;

    // Synchronize remote directory to local cache
    char command[MAX_COMMAND_LENGTH];
    snprintf(command, sizeof(command), "rsync -a --delete %s/ %s/", options.remote_path, options.local_cache);
    int result = system(command);
    if (result != 0) {
        return -errno;
    }
    
    // Adding . and .. , so that it comes up in `ls` command
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    // opening up local cache directory
    DIR *dp = opendir(options.local_cache);
    if (dp == NULL) {
        return -errno;
    }

    struct dirent *de;
    // Going through the directory
    // https://stackoverflow.com/questions/8420234/why-shift-12-bit-for-d-type-in-fusexmp
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;

        if (filler(buf, de->d_name, &st, 0, 0)) {
            break; }
    }

    closedir(dp);

    return 0;
}

// Create, Write and Read Files
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {

    char cache_fp[MAX_FILEPATH_LENGTH];
    snprintf(cache_fp, sizeof(cache_fp), "%s%s", options.local_cache, path);

    int fd = creat(cache_fp, mode);
    if (fd == -1) {
        perror("Error creating file");
        return -errno;
    }
    close(fd);

    char remote_fp[MAX_FILEPATH_LENGTH];
    snprintf(remote_fp, sizeof(remote_fp), "%s%s", options.remote_path, path);

    char command[MAX_COMMAND_LENGTH];
    snprintf(command, sizeof(command), "rsync '%s' '%s'", cache_fp, remote_fp);
    // rsync
    int result = system(command);
    if (result != 0) {
        fprintf(stderr, "ERsync problem in myfs_create\n");
        return -errno;
    }

    return 0;
}

static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    char cache_fp[MAX_FILEPATH_LENGTH];
    snprintf(cache_fp, sizeof(cache_fp), "%s%s", options.local_cache, path);

    int fd = open(cache_fp, O_WRONLY);
    if (fd < 0) {
        perror("Error opening file");
        return -errno;
    }

    int res = pwrite(fd, buf, size, offset);
    if (res == -1) {
        perror("Error writing to file");
        close(fd);
        return -errno;
    }
    close(fd);

    char remote_fp[MAX_FILEPATH_LENGTH];
    snprintf(remote_fp, sizeof(remote_fp), "%s%s", options.remote_path, path);

    char command[MAX_COMMAND_LENGTH];
    // cache to remote
    snprintf(command, sizeof(command), "rsync '%s' '%s'", cache_fp, remote_fp);
    int result = system(command);
    if (result != 0) {
        fprintf(stderr, "Error syncing file to remote path\n");
        return -errno;
    }

    return res;
}

static struct fuse_operations myfs_operations = {
    .init = myfs_init,
    .getattr = myfs_getattr,
    .create = myfs_create,
    .write = myfs_write,
    .readdir = myfs_readdir,
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

    clear_local_cache(options.local_cache);

    int ret = fuse_main(args.argc, args.argv, &myfs_operations, NULL);
    fuse_opt_free_args(&args);
    return ret;
}