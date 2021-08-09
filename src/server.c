#define _GNU_SOURCE 1 /* for renameat2 */
#include <netinet/in.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <strings.h> /* for bzero */
#include <fcntl.h> /* for open flag parameter */
#include <sys/sendfile.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/resource.h> /* for getrlimit function */

#include "common.h"
#include "util.h"


/* for epoll */
typedef struct {
    int epfd; /* epoll file descriptor */
    int listen_fd; /* server listening socket */
    rpc_t **connections; /* listening to all connections */ 
} server_context;


/* The function will be called when the system tries
   to read the contents of a directory */
static int server_readdir(rpc_t *rpc, char *full_path)
{
    int ret, opendir_errno;
    struct dirent *dp;
    DIR *dirp;

    dirp = opendir(full_path);
    opendir_errno = errno;

    LOG("opendir(%s) returned %p (%m)", full_path, dirp);

    if (dirp == NULL) {
        /* If failed to open - send error to client */
        
        ret = rpc_reply_status(rpc, -1, opendir_errno);
        if (ret < 0) {
            return ret;
        }

        return 0;
    }

    /* succeseded to do the operation */
    ret = rpc_reply_status(rpc, 0, 0);
    if (ret < 0) {
        return ret;
    }

    /* Read directory contents */
    dp = readdir(dirp);
    while (dp != NULL) {
        ret = rpc_readdir_reply(rpc, dp->d_name);
        if (ret < 0) {
            closedir(dirp);
            return ret;
        }

        dp = readdir(dirp);
    }
    closedir(dirp);

    /* When getting empty string -
       it's end of contents in this directory */
    return rpc_readdir_reply(rpc, "");
}

/* The function will be called when the system tries
   to get the attributes of the file stbuf is containing */
static int server_getattr(rpc_t *rpc, const char *full_path)
{
    int ret, stat_ret, stat_errno;
    struct stat stbuf;

    stat_ret = lstat(full_path, &stbuf); /* stat ret==0 if operation succedded */
    stat_errno = errno;

    LOG("stat(%s) returned %d (%m) mode %u", full_path, stat_ret, stbuf.st_mode);

    ret = rpc_reply_status(rpc, stat_ret, stat_errno);
    if (ret < 0) { /* if the sending of the status failed*/
        return ret;
    }

    if (stat_ret >= 0) {
        /* Send stbuf only in case of operation success */
        ret = rpc_getattr_reply(rpc, &stbuf);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

/* do make directory */
static int server_mkdir(rpc_t *rpc, mode_t mode, const char *full_path)
{
    int ret, mkdir_errno, mkdir_ret;

    mkdir_ret = mkdir(full_path, mode);
    mkdir_errno = errno;

    LOG("mkdir(%s) returned %d (%m)", full_path, mkdir_ret);

    ret = rpc_reply_status(rpc,  mkdir_ret, mkdir_errno);
    if (ret < 0) {
        return ret;
    }

    if (mkdir_ret >= 0) {
        /* Send result 0 only in case of operation success */
        ret = rpc_mkdir_reply(rpc, 0);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

/* do remove directory */
static int server_rmdir(rpc_t *rpc, const char *full_path)
{
    int ret, rmdir_errno, rmdir_ret;

    rmdir_ret = rmdir(full_path);
    rmdir_errno = errno;

    LOG("rmdir(%s) returned %d (%m)", full_path, rmdir_ret);

    ret = rpc_reply_status(rpc, rmdir_ret, rmdir_errno);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/* do open file */
static int server_open(rpc_t *rpc, const char *full_path, int flags)
{
    int ret, open_errno, open_ret;

    open_ret = open(full_path, flags);
    open_errno = errno;

    LOG("open(%s, flags=0x%x) returned %d (%m)", full_path, flags, open_ret);

    ret = rpc_reply_status(rpc, open_ret, open_errno);
    if (ret < 0) {
        return ret;
    }

    if (open_ret >= 0) {
        /* Send result 0 only in case of operation success */
        ret = rpc_open_reply(rpc, open_ret);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

/* do release an open file */
static int server_release(rpc_t *rpc, int fd)
{
    int ret, release_errno, release_ret;

    release_ret = close(fd);
    release_errno = errno;

    LOG("close(%d) returned %d (%m)", fd, release_ret);

    ret = rpc_reply_status(rpc, release_ret, release_errno);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/* do unlink to a file */ 
static int server_unlink(rpc_t *rpc, const char *full_path)
{
    int ret, unlink_errno, unlink_ret;

    unlink_ret = remove(full_path);
    unlink_errno = errno;

    LOG("unlink returned %d (%m)", unlink_ret);

    ret = rpc_reply_status(rpc, unlink_ret, unlink_errno);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/* do read a file */
static int server_read(rpc_t *rpc, uint64_t fd, off_t offset, size_t size)
{
    int ret;
    struct stat stbuf;
    off_t fsize;
    ssize_t bytes_sent;
    size_t size_to_read;

    fstat(fd, &stbuf);

    fsize = stbuf.st_size;
    LOG("file size=%jd", fsize);

    /* in case of en empty fd or problem with fd */
    if (fsize <= offset) {
        // send 0-size data here
        size_to_read = 0;
    } else {
        size_to_read = min(fsize - offset, size);
    }

    ret = rpc_reply_status(rpc, 0, 0);
    if (ret < 0) {
        return ret;
    }

    ret = rpc_read_size_reply(rpc, size_to_read);
    if (ret < 0) {
        return ret;
    }

    if (size_to_read > 0) {
        bytes_sent = sendfile(rpc->sockfd, fd, &offset, size_to_read);

        LOG("sendfile(to=%d, from=%lu, offset=%zu, size=%zu) returned %ld",
             rpc->sockfd, fd, offset, size_to_read, bytes_sent);

        /* Expect exact size to be sent */
        assert(size_to_read == bytes_sent);
    }

    return 0;
}

/* do write to a file */
static int server_write(rpc_t *rpc, int fd, off_t offset, size_t size)
{
    off_t curr_offset = offset;
    ssize_t bytes_recv, curr_size, ret_lseek;
    size_t bytes_write;
    char buf[ONE_KB];
    int ret;

    LOG("fd=%d size=%zu offset=%jd", fd, size, offset);

    /* lseek to offset */
    ret_lseek = lseek(fd, curr_offset, SEEK_SET);

    /* check return value of seek */
    if (ret_lseek < 0) {
        LOG_ERROR("lseek(fd=%d offset=%zd) returned %zd: %m", fd,
                  curr_offset, ret_lseek);
        return ret_lseek;
    }
    
    curr_size = size;
    while (curr_size > 0) {
        curr_size = min(curr_size, sizeof(buf));
        
        bytes_recv = recv(rpc->sockfd, buf, curr_size, MSG_WAITALL);
        LOG("recv(size=%zu) returned %zd", curr_size, bytes_recv);

        if (bytes_recv < 0) {
            LOG_ERROR("failed to receive from socket %d: %m", rpc->sockfd);
            return bytes_recv;
        }

        bytes_write = write(fd, buf, bytes_recv);
        if (bytes_write < 0) {
            LOG_ERROR("failed to write %zu bytes to file %d: %m", bytes_write, fd);
            return bytes_write;
        }
        
        curr_size -= bytes_write;
    }

    /* if everything is written */
    assert(curr_size == 0);
    
    ret = rpc_reply_status(rpc, 0, 0);
    if (ret < 0) {
        return ret;
    }
    
    ret = rpc_write_size_reply(rpc, size);
    if(ret < 0)  {
        return ret;
    }
    
    return 0;
}  

/* do create a file */
static int server_create(rpc_t *rpc, const char *full_path, mode_t mode)
{
    int ret, create_errno, create_ret;

    create_ret = creat(full_path, mode);
    create_errno = errno;

    LOG("create(%s, mode=0x%x) returned %d (%m)", full_path,
        create_ret, mode);

    ret = rpc_reply_status(rpc, create_ret, create_errno);
    if (ret < 0) {
        return ret;
    }

    if (create_ret >= 0) {
        /* Send result 0 only in case of operation success */
        ret = rpc_create_reply(rpc, create_ret);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

/* do change the permission bits of a file */
static int server_chmod(rpc_t *rpc, const char *full_path, mode_t mode)
{
    int ret, chmod_errno, chmod_ret;

    chmod_ret = chmod(full_path, mode);
    chmod_errno = errno;

    LOG("chmod(%s) returned %d (%m)", full_path, chmod_ret);

    ret = rpc_reply_status(rpc, chmod_ret, chmod_errno);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/* do change the access and modification times of a file with nanosecond resolution */
static int server_utimens(rpc_t *rpc, const char *full_path)
{
    int ret, utimens_errno, utimens_ret;
    struct timespec tv[2];

    ret = recv(rpc->sockfd, tv, sizeof(tv), MSG_WAITALL);
    if (ret < 0) {
        return ret;
    }

    utimens_ret = utimensat(-1, full_path, tv, 0);
    utimens_errno = errno;

    LOG("utimensat(%s) returned %d (%m)", full_path, utimens_ret);

    ret = rpc_reply_status(rpc, utimens_ret, utimens_errno);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/* change the owner and group */
static int server_chown(rpc_t *rpc, const char *full_path)
{
    int ret, chown_errno, chown_ret;
    ugid_struct ugid;

    ret = recv(rpc->sockfd, &ugid, sizeof(ugid_struct), MSG_WAITALL);
    if (ret < 0) {
        return ret;
    }

    chown_ret = chown(full_path, ugid.uid, ugid.gid);
    chown_errno = errno;

    LOG("chown(%s, uid=%u gid=%u) returned %d (%m)", 
        full_path, ugid.uid, ugid.gid, chown_ret);

    ret = rpc_reply_status(rpc, chown_ret, chown_errno);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/* do rename a file */
static int server_rename(rpc_t *rpc, const char *full_path, const char *root_path,
                         size_t new_name_len, unsigned int flags)
{
    int ret, rename_errno, rename_ret;
    char new_path[PATH_MAX];
    size_t root_path_len;

    root_path_len = strlen(root_path);
    strcpy(new_path, root_path);

    ret = recv(rpc->sockfd, &new_path[root_path_len], new_name_len, MSG_WAITALL);
    if (ret < 0) {
        return ret;
    }

    new_path[new_name_len + root_path_len] = '\0';
    ret = renameat2(-1, full_path,-1, new_path, flags);
    rename_errno = errno;

    if (ret < 0) {
        return ret;
    }

    LOG ("renameat(%s, flags=0x%d) returned %d (%m)", full_path, flags, rename_ret);

    ret = rpc_reply_status(rpc, rename_ret, rename_errno);
    if (ret < 0) {
        return ret;
    }
  
    return 0;
}

/* do change the size of a file */
static int server_truncate(rpc_t *rpc, const char *full_path, off_t offset)
{
    int ret, truncate_errno, truncate_ret;

    ret = truncate(full_path, offset);
    truncate_errno = errno;
    if (ret < 0) {
        return ret;
    }

    LOG("truncate(%s, offset=%jd) returned %d (%m)", full_path, offset, truncate_ret);

    ret = rpc_reply_status(rpc, truncate_ret, truncate_errno);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/* do symbolic link to a file */
static int server_symlink(rpc_t *rpc, const char *full_path, size_t to_len)
{
    int ret, symlink_errno, symlink_ret;
    char to_path[PATH_MAX];

    ret = recv(rpc->sockfd, to_path, to_len, MSG_WAITALL);
    if (ret < 0) {
        return ret;
    }

    to_path[to_len] = '\0';
    ret = symlink(to_path, full_path);
    symlink_errno = errno;
    
    LOG("symlink(%s->%s) returned %d (%m) (%s)", 
         full_path, to_path, symlink_ret, strerror(symlink_errno));
    ret = rpc_reply_status(rpc, symlink_ret, symlink_errno);
    if (ret < 0) {
        return ret;
    }
    return 0;
}

/* do hard link to a file */
static int server_link(rpc_t *rpc, const char *full_path, const char *root_path, size_t to_len)
{
    int ret, link_errno, link_ret;
    char to_path[PATH_MAX];
    size_t root_path_len;

    root_path_len = strlen(root_path);
    strcpy(to_path, root_path);

    ret = recv(rpc->sockfd, &to_path[root_path_len], to_len, MSG_WAITALL);
    if (ret < 0) {    
        return ret;
    }

    to_path[to_len + root_path_len] = '\0';
    ret = link(full_path, to_path);
    link_errno = errno;

    LOG("link(%s, %s) returned %d (%m)", full_path, to_path, link_ret);

    if (ret < 0) {
        return ret;
    }

    ret = rpc_reply_status(rpc, link_ret, link_errno);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

/* do read the target of a symbolic link */
static int server_read_link(rpc_t *rpc, const char *full_path) 
{
    char buf[PATH_MAX];
    ssize_t char_number;
    int ret, bytes_sent, read_link_errno;

    /* readlink into buf */
    char_number = readlink(full_path, buf, sizeof(buf));
    read_link_errno = errno;

    LOG("readlink(%s) returned %zd (%m)", full_path, char_number);

    /* reply_status according to readlink return value and errno */
    ret = rpc_reply_status(rpc, char_number, read_link_errno);
    if (ret < 0) {
        return ret;
    }

    /* rpc_read_size_reply (if all good) - to send the length of buf contents */
    ret = rpc_read_size_reply(rpc, char_number);
    if (ret < 0) {
        return ret;
    }

    /*  send() the buf with the size returned from readlink and passed
        to rpc_size_reply */
    bytes_sent = send(rpc->sockfd, buf, char_number, 0);
    
    assert(bytes_sent == char_number);

    return 0;
}

/* handel every type of client's request */
static int handle_request(rpc_t *rpc, const char *root_path)
{
    char client_rel_path[PATH_MAX], full_path[PATH_MAX];
    int recv_len, ret;
    struct dirent *dir;
    operation_t op;
    mode_t mode;
    uint64_t fd;
    size_t size;
    off_t offset;
    uint32_t path_length;

    /* Get the operation */
    LOG("receving next operation");

    ret = rpc_recv_request(rpc, &op, &mode, client_rel_path, &fd, &size, &offset, &path_length);
    
    LOG("recieved operation=%s(%d) mode=%d path='%s' fd=%d path_length=%d",
        operation_names[op], op, mode, client_rel_path, (int)fd, path_length);

    if (ret < 0) {
        LOG_ERROR("failed to receive the operation");
        return ret;
    }

    /* Concatenate root path and relative path to get the full
       absolute path */
    snprintf(full_path, sizeof(full_path), "%s%s", root_path, client_rel_path);

    switch (op) {
    case READ_DIR:
        ret = server_readdir(rpc, full_path);
        break;
    case GET_ATTR:
        ret = server_getattr(rpc, full_path);
        break;
    case MK_DIR:
        ret = server_mkdir(rpc, mode, full_path);
        break;
    case RM_DIR:
        ret = server_rmdir(rpc, full_path);
        break;
    case OPEN:
        ret = server_open(rpc, full_path, mode);
        break;
    case RELEASE:
        ret = server_release(rpc, fd);
        break;
    case UNLINK:
        ret = server_unlink(rpc, full_path);
        break;
    case READ:
        ret = server_read(rpc, fd, offset, size);
        break;
    case WRITE:
        ret = server_write(rpc, fd, offset, size);
        break;
    case CREATE:
        ret = server_create(rpc, full_path, mode);
        break;
    case CHMOD:
        ret = server_chmod(rpc, full_path, mode);
        break;
    case CHOWN:
        ret = server_chown(rpc, full_path);
        break;
    case UTIMENS:
        ret = server_utimens(rpc, full_path);
        break;
    case RENAME:
        ret = server_rename(rpc, full_path, root_path, size, mode);
        break;
    case TRUNCATE:
        ret = server_truncate(rpc, full_path, offset);
        break;
    case SYMLINK:
        ret = server_symlink(rpc, full_path, size);
        break;
    case READ_LINK:
        ret = server_read_link(rpc, full_path);
        break;
    case LINK:
        ret = server_link(rpc, full_path, root_path, size);
        break;
    default:
        LOG("Fatal: unknown operation %d", op);
        ret = -EINVAL; /* Illegal command */
        break;
    }

    /* Command communication failed - terminate the connection */
    if (ret < 0) {
        return ret;
    }

    return ret;
}
/*go through again */
static int server_main(server_context *context, const char *root_path)
{
    struct epoll_event ev_server[MAX_EVENTS];
	struct epoll_event new_ev;
    int nfds, fd;
    rpc_t *rpc;
    struct rlimit r_lim;
    int ret;

    /*says how many open files can be opened 
    1)fd numbers are consucutive 
    2)upper limit on fd number 
    it's to know what is thew size of connections array
    */
    ret = getrlimit(RLIMIT_NOFILE, &r_lim);
    if (ret < 0) {
        LOG_ERROR("getrlimit() returned %d (%m)", ret);
        return ret;
    }

    context->connections = malloc(r_lim.rlim_cur * sizeof(*context->connections));
    /*listen fd is the socket that the sever is waiting for connections
       epfd presents the set of epoll set - sockets that exist in the sever */
    new_ev.data.fd = context->listen_fd;
	new_ev.events = EPOLLIN; /*for read */ 
	epoll_ctl(context->epfd, EPOLL_CTL_ADD, context->listen_fd, &new_ev);

    LOG("Server listening");
    for (;;) {
        nfds = epoll_wait(context->epfd, ev_server, MAX_EVENTS, TIMEOUT); 
        if (nfds < 0) {
            LOG_ERROR("problem with epoll wait");
            return nfds;
        }

        LOG("nfds %d epfd is %d and listen fd is %d", nfds, context->epfd, context->listen_fd);

        for (int i = 0; i < nfds; i++) {   
            fd = ev_server[i].data.fd;
            if (fd == context->listen_fd) { 
                /* event fd is context listen_fd , that means a connect request comes */
                rpc = (rpc_t *)malloc(sizeof(rpc_t));
                if (rpc == NULL) {
                    LOG_ERROR("cannot allocate memory for rpc struct");
                    return -1;
                }

                ret = rpc_accept(rpc,context->listen_fd);
                if (ret == -1) {
					LOG_ERROR("accept failed--connect_fd is %d", ret);
					continue;
				}
                
                LOG("add new fd %d rpc %p", fd, rpc);
                context->connections[rpc->sockfd] = rpc; 

				new_ev.data.fd = rpc->sockfd;
                new_ev.events = EPOLLIN;
				ret = epoll_ctl(context->epfd, EPOLL_CTL_ADD, rpc->sockfd, &new_ev); /* add connect_fd to epoll fd list */
                if (ret < 0) {
                    LOG_ERROR("error in epoll_ctl");
                    return ret;
                }
			} else {
                rpc = context->connections[fd];
                LOG("handling fd %d rpc %p", fd, rpc);
                assert(fd == rpc->sockfd);
                ret = handle_request(rpc, root_path);
                if (ret < 0) {
                    LOG("request is not exist");
                    context->connections[fd] = NULL;
                    close(context->listen_fd);
                    free(rpc); /* when we want to free a bad connection */
                    return ret;
                }
            }  
        }
    }

    free(context->connections);
    return 0;
}

int main(int argc, char *argv[])
{
    int enable, connect_fd;
    socklen_t len;
    struct sockaddr_in servaddr, client;
    server_context context;

    if (argc != 2) {
        LOG_ERROR("Did not get path to the folder");
        return -1;
    }

    context.epfd = epoll_create(1);/*the size parameter is ignored */
    if (context.epfd < 0 ) {
		LOG("epoll_create() failed: %m");
		return -1;
	}

    /* Socket create and verification */
    context.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (context.listen_fd < 0) {
        LOG_ERROR("socket() failed: %m");
        exit(0);
    }

    LOG("socket successfully created");

    bzero(&servaddr, sizeof(servaddr));

    /* Allow reusing server port */
    enable = 1;
    setsockopt(context.listen_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    /* Assign ip and port */
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    /* Binding newly created socket to given IP and verification */
    if ((bind(context.listen_fd, (SA *)&servaddr, sizeof(servaddr))) != 0) {
        LOG_ERROR("bind() failed: %m");
        return -1;
    }

    LOG("Socket successfully binded");

    /* Server is ready to listen and verification */
    if ((listen(context.listen_fd, MAX_FD)) != 0) {
        LOG_ERROR("listen() failed: %m");
        return -1;
    }

    server_main(&context, argv[1]);
    close(context.listen_fd);

    return 0;
}