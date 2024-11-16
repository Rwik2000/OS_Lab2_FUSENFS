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
#include <assert.h>

#include <libssh2.h>
#include <libssh2_sftp.h>
#include <sys/types.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define MAX_FILEPATH_LENGTH 8192
#define MAX_COMMAND_LENGTH (MAX_FILEPATH_LENGTH * 2 + 32)
#define DATA_TRANSFER_SIZE 4 * 1024 * 1024

static struct options {
    const char *username;
    const char *host_ip;
    const char *remote_path;
    const char *local_cache;
    const char *public_key_fname;
    const char *private_key_fname;
} options;


static struct sftp_state {
    int sock;
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftp_session;
    const char *fingerprint;
} sftp_state = {0, NULL, NULL, NULL};

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }

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
    // https://github.com/libssh2/libssh2/blob/master/example/sftpdir.c#L103
    int rc;
    uint32_t hostaddr;
    hostaddr = inet_addr(options.host_ip);

    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        exit(EXIT_FAILURE);
    }

    sftp_state.sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;

    if(sftp_state.sock == LIBSSH2_INVALID_SOCKET) {
        fprintf(stderr, "failed to create socket.\n");
        goto shutdown;
    }

    if(connect(sftp_state.sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in))) {
        fprintf(stderr, "failed to connect.\n");
        goto shutdown;
    }

    sftp_state.session = libssh2_session_init();
    if(!sftp_state.session) {
        fprintf(stderr, "Could not initialize SSH session.\n");
        goto shutdown;
    }

    libssh2_session_set_blocking(sftp_state.session, 1);

    rc = libssh2_session_handshake(sftp_state.session, sftp_state.sock);
    if(rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
        goto shutdown;
    }

    sftp_state.fingerprint = libssh2_hostkey_hash(sftp_state.session, LIBSSH2_HOSTKEY_HASH_SHA1);
    fprintf(stderr, "Fingerprint: ");
    for(int i = 0; i < 20; i++) {
        fprintf(stderr, "%02X ", (unsigned char)sftp_state.fingerprint[i]);
    }
    fprintf(stderr, "\n");

    if(libssh2_userauth_publickey_fromfile(sftp_state.session, options.username,
                                               options.public_key_fname, options.private_key_fname,
                                               "")) {
            fprintf(stderr, "Authentication by public key failed.\n");
            goto shutdown;
        }

    fprintf(stderr, "libssh2_sftp_init().\n");
    sftp_state.sftp_session = libssh2_sftp_init(sftp_state.session);

    if(!sftp_state.sftp_session) {
        fprintf(stderr, "Unable to init SFTP session\n");
        goto shutdown;
    }

    // required or else leads to segmentation fault
    return NULL;

shutdown:
    if (sftp_state.session) {
        libssh2_session_disconnect(sftp_state.session, "Normal Shutdown");
        libssh2_session_free(sftp_state.session);
    }

    if(sftp_state.sock != LIBSSH2_INVALID_SOCKET) {
        shutdown(sftp_state.sock, 2);
         close(sftp_state.sock);
    }

    libssh2_exit();
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
    snprintf(cache_fp, sizeof(cache_fp), "%s%s", options.local_cache, path); // Changed to local_cache

    // File exists locally, get attributes from the local cache
    if (access(cache_fp, F_OK) == 0) {
        int res = stat(cache_fp, stbuf);
        if (res == -1) {
            perror("Error in myfs_getattr - stat");
            return -errno;
        }
        return 0;
    }

    // if (File not found in local cache):
    //          check remote server via SFTP

    char remote_fp[MAX_FILEPATH_LENGTH];
    snprintf(remote_fp, sizeof(remote_fp), "%s%s", options.remote_path, path);

    LIBSSH2_SFTP_ATTRIBUTES attrs;
    int rc = libssh2_sftp_stat(sftp_state.sftp_session, remote_fp, &attrs);
    if (rc != 0) {
        fprintf(stderr, "Error in myfs_getattr - sftp_stat failed (%s, %d)\n", remote_fp, rc);
        return -ENOENT;
    }

    // Populate the stbuf structure from SFTP attributes
    if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) {
        stbuf->st_size = attrs.filesize;
    }
    if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
        stbuf->st_mode = attrs.permissions; 
    }
    if (attrs.flags & LIBSSH2_SFTP_ATTR_UIDGID) {
        stbuf->st_uid = attrs.uid; // User ID
        stbuf->st_gid = attrs.gid; // Group ID
    }
    if (attrs.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
        stbuf->st_atime = attrs.atime; // Access time
        stbuf->st_mtime = attrs.mtime; // Mod time
    }

    return 0;
}


// Helper function to construct file paths
static int construct_filepath(char *dest, size_t dest_size, const char *base, const char *path) {
    if (snprintf(dest, dest_size, "%s%s", base, path) >= dest_size) {
        fprintf(stderr, "Error: Filepath exceeds buffer size\n");
        return -ENAMETOOLONG;
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
    char remote_dir[MAX_FILEPATH_LENGTH];
    if (construct_filepath(remote_dir, sizeof(remote_dir), options.remote_path, path) < 0) {
        return -ENAMETOOLONG;
    }

    LIBSSH2_SFTP_HANDLE *dir_handle = libssh2_sftp_opendir(sftp_state.sftp_session, remote_dir);
    if (!dir_handle) {
        fprintf(stderr, "Error: Failed to open directory %s\n", remote_dir);
        return -ENOENT;
    }

    // Adding . and .. , so that it comes up in `ls` command
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    char *filedata = malloc(1024); // Allocate memory for directory entry names
    if (!filedata) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        libssh2_sftp_closedir(dir_handle);
        return -ENOMEM;
    }

    while(1) {
        LIBSSH2_SFTP_ATTRIBUTES attrs;
        ssize_t name_len = libssh2_sftp_readdir(dir_handle, filedata, 1024 - 1, &attrs);
        if (name_len <= 0) {
            break; // Exit when no more entries
        }
        filedata[name_len] = '\0'; // Ensure null-terminated string

        struct stat st = {0};
        if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) {
            st.st_size = attrs.filesize;
        }
        if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
            st.st_mode = attrs.permissions;
        }

        if (filler(buf, filedata, &st, 0, 0)) {
            break; // Stop adding entries if filler buffer is full
        }
    }

    free(filedata); // Free allocated memory
    libssh2_sftp_closedir(dir_handle);
    return 0;
}


static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    fprintf(stderr, "Creating File: %s\n", path);

    // Local cache file path
    char cache_fp[MAX_FILEPATH_LENGTH];
    snprintf(cache_fp, sizeof(cache_fp), "%s%s", options.local_cache, path);

    // Remote file path
    char remote_fp[MAX_FILEPATH_LENGTH];
    snprintf(remote_fp, sizeof(remote_fp), "%s%s", options.remote_path, path);

    // Create the local cache file
    int fd = creat(cache_fp, mode);
    if (fd == -1) {
        perror("Error creating local cache file");
        return -errno;
    }
    close(fd);

    // Open the remote file for writing via SFTP
    // https://libssh2.org/libssh2_sftp_open_ex.html
    int flags = LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC;
    LIBSSH2_SFTP_HANDLE *fh = libssh2_sftp_open(
        sftp_state.sftp_session, 
        remote_fp, 
        flags, 
        LIBSSH2_SFTP_S_IRWXU | LIBSSH2_SFTP_S_IRWXG | LIBSSH2_SFTP_S_IRWXO);

    if (!fh) {
        fprintf(stderr, "Error opening remote file %s for writing\n", remote_fp);
        return -ENOENT;
    }

    // Write a placeholder to the remote file to ensure creation
    char placeholder = '\0';
    if (libssh2_sftp_write(fh, &placeholder, 1) != 1) {
        fprintf(stderr, "Error writing placeholder to remote file\n");
        libssh2_sftp_close(fh);
        return -EIO;
    }

    // Close the remote file handle
    libssh2_sftp_close(fh);

    fprintf(stderr, "File successfully created locally and remotely: %s\n", path);
    return 0;
}


static int myfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char cache_fp[MAX_FILEPATH_LENGTH];

    snprintf(cache_fp, sizeof(cache_fp), "%s%s", options.local_cache, path);

    int fd = open(cache_fp, O_RDONLY);
    if (fd == -1) {
        perror("Error in myfs_read - open");
        return -errno;
    }

    // Seek to the specified offset
    if (lseek(fd, offset, SEEK_SET) == -1) {
        perror("Error seeking in cache file");
        close(fd);
        return -errno;
    }

    // Read the specified number of bytes into the buffer
    ssize_t bytes_read = read(fd, buf, size);
    if (bytes_read < 0) {
        perror("Error reading from cache file");
        close(fd);
        return -errno;
    }

    close(fd);
    return bytes_read;
}


static int myfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {

    char cache_fp[MAX_FILEPATH_LENGTH];
    snprintf(cache_fp, sizeof(cache_fp), "%s%s", options.local_cache, path);

    int fd = open(cache_fp, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        perror("Error opening file");
        return -errno;
    }

    // Perform a positional write to avoid extra lseek calls
    int res = pwrite(fd, buf, size, offset);
    if (res == -1) {
        perror("Error writing to file");
        close(fd);
        return -errno;
    }

    close(fd);

    return res;
}


static int myfs_open(const char *path, struct fuse_file_info *fi) {
    fprintf(stderr, "Opening file: %s\n", path);

    // Construct local cache and remote file paths
    char cache_path[MAX_FILEPATH_LENGTH];
    snprintf(cache_path, sizeof(cache_path), "%s%s", options.local_cache, path);

    char remote_path[MAX_FILEPATH_LENGTH];
    snprintf(remote_path, sizeof(remote_path), "%s%s", options.remote_path, path);

    // Check if the file exists in the local cache
    if (access(cache_path, F_OK) == 0) {
        fprintf(stderr, "File already cached: %s\n", cache_path);
        return 0;
    }

    fprintf(stderr, "Fetching and caching file: %s -> %s\n", remote_path, cache_path);

    // Open the remote file
    // https://libssh2.org/libssh2_sftp_close_handle.html
    LIBSSH2_SFTP_HANDLE *remote_file = libssh2_sftp_open(sftp_state.sftp_session, remote_path, 
                                                         LIBSSH2_FXF_READ, LIBSSH2_SFTP_S_IRWXU);
    if (!remote_file) {
        fprintf(stderr, "Error: Unable to open remote file %s\n", remote_path);
        return -ENOENT;
    }

    // Create the local cache file
    // https://www.gnu.org/software/libc/manual/html_node/Permission-Bits.html
    int local_cache_fd = creat(cache_path, S_IRUSR | S_IROTH | S_IRGRP | S_IWUSR );
    if (local_cache_fd < 0) {
        perror("Error creating local cache file");
        libssh2_sftp_close(remote_file);
        return -errno;
    }

    // Transfer file data in chunks
    char buffer[DATA_TRANSFER_SIZE];
    ssize_t bytes_read;
    while ((bytes_read = libssh2_sftp_read(remote_file, buffer, sizeof(buffer))) > 0) {
        if (write(local_cache_fd, buffer, bytes_read) != bytes_read) {
            perror("Error writing to cache file");
            close(local_cache_fd);
            libssh2_sftp_close(remote_file);
            return -errno;
        }
    }

    if (bytes_read < 0) {
        fprintf(stderr, "Error reading from remote file: %s\n", remote_path);
    }

    close(local_cache_fd);
    libssh2_sftp_close(remote_file);
    
    if (bytes_read < 0) {
        return -EIO;
    }
    return 0;

}


static void myfs_destroy(void *private_data)
{
    libssh2_sftp_shutdown(sftp_state.sftp_session);
    libssh2_session_disconnect(sftp_state.session, "Normal Shutdown");
    libssh2_session_free(sftp_state.session);
    close(sftp_state.sock);
    fprintf(stderr, "all done\n");
    libssh2_exit();
}


static int myfs_release(const char *path, struct fuse_file_info *fi) {

    // Skip write-back if the file was opened in read-only mode
    if (!(fi->flags & (O_WRONLY | O_RDWR))) {
        fprintf(stderr, "Read-only release for file: %s\n", path);
        return 0;
    }

    // Construct remote and local file paths
    char remote_fp[MAX_FILEPATH_LENGTH];
    snprintf(remote_fp, sizeof(remote_fp), "%s%s", options.remote_path, path);

    char local_fp[MAX_FILEPATH_LENGTH];
    snprintf(local_fp, sizeof(local_fp), "%s%s", options.local_cache, path);

    // Open the local cache file
    int local_cache_fd = open(local_fp, O_RDONLY);
    if (local_cache_fd < 0) {
        perror("Error opening local cache file for reading");
        return -errno;
    }

    // Open the remote file for writing via SFTP
    LIBSSH2_SFTP_HANDLE *remote_fh = libssh2_sftp_open(
        sftp_state.sftp_session, remote_fp, LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC, 0644);
    if (!remote_fh) {
        perror("Error opening remote file for writing via SFTP");
        close(local_cache_fd);
        return -ENOENT;
    }

    // Allocate buffer for transferring file data
    char *buffer = malloc(DATA_TRANSFER_SIZE);
    if (!buffer) {
        perror("Error allocating buffer for file transfer");
        libssh2_sftp_close(remote_fh);
        close(local_cache_fd);
        return -ENOMEM;
    }

    // Transfer data from the local cache to the remote file
    ssize_t bytes_read;
    while ((bytes_read = read(local_cache_fd, buffer, DATA_TRANSFER_SIZE)) > 0) {
        ssize_t total_written = 0;
        while (total_written < bytes_read) {
            ssize_t bytes_written = libssh2_sftp_write(
                remote_fh, buffer + total_written, bytes_read - total_written);
            if (bytes_written < 0) {
                fprintf(stderr, "Error writing to remote file: %zd\n", bytes_written);
                free(buffer);
                libssh2_sftp_close(remote_fh);
                close(local_cache_fd);
                return -EIO;
            }
            total_written += bytes_written;
        }
    }

    if (bytes_read < 0) {
        fprintf(stderr, "Error reading local cache file: %zd\n", bytes_read);
    }

    // Clean up resources
    free(buffer);
    libssh2_sftp_close(remote_fh);
    close(local_cache_fd);

    // Return success or error based on the read operation
    if (bytes_read < 0) {
        return -EIO;
    }

    fprintf(stderr, "Released file: %s\n", path);
    return 0;
}

static const struct fuse_operations fusenfs_oper = {
	.init       = myfs_init,
	.getattr	= myfs_getattr,
	.readdir	= myfs_readdir,
    .create     = myfs_create,
	.read		= myfs_read,
    .write      = myfs_write,
	.open		= myfs_open,
    .release    = myfs_release,
};

int main(int argc, char *argv[])
{
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    options.host_ip = strdup("192.168.47.236");
    options.username = strdup("rwik");
    options.remote_path = strdup("/home/rwik/oslab2");
    options.local_cache = strdup("/tmp/mycache");
    options.public_key_fname = strdup("/home/rwik/.ssh/id_rsa.pub");
    options.private_key_fname = strdup("home/rwik/.ssh/id_rsa");

	ret = fuse_main(args.argc, args.argv, &fusenfs_oper, NULL);
	fuse_opt_free_args(&args);
	return ret;
}