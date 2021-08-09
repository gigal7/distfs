#include <arpa/inet.h>
#include <assert.h>

#include "common.h"
#include "util.h"

/* Send generic rpc message from client to server */
static int rpc_send_request(rpc_t *rpc, operation_t op, int mode, const char *path,
                            int *status, int fd, size_t size, off_t offset,
                            const void *buf, int size_buf)
{
    rpc_request_header_t request = {0};
    rpc_reply_header_t reply;
    struct iovec iov[3];
    struct msghdr msg = {};
    int ret;

    request.op = op;
    request.mode = mode;
    request.path_length = strlen(path);
    request.fd = fd;
    request.offset = offset;
    request.size = size;
    iov[0].iov_base = &request;
    iov[0].iov_len = sizeof(request);
    iov[1].iov_base = (void*)path;
    iov[1].iov_len = request.path_length;
    iov[2].iov_base = (void*)buf;
    iov[2].iov_len = size_buf;
    msg.msg_iov = iov;
    msg.msg_iovlen = 3;

    LOG("sending RPC request op=%d (%s) mode=%d path='%s' fd=%d offset=%zd size=%zd",
        op, operation_names[op], mode, path, fd, offset, size);

    ret = sendmsg(rpc->sockfd, &msg, 0);
    if (ret < 0) {
        LOG_ERROR("sendmsg() returned %d: %m", ret);
        return ret;
    }

    /* Expect all data to be sent */
    assert(ret == (sizeof(request) + request.path_length + size_buf));

    /* Receive status respose from the server (whether the opertion was
       successful or not) */
    ret = recv(rpc->sockfd, &reply, sizeof(reply), MSG_WAITALL);
    if (ret < 0) {
        LOG_ERROR("recv(reply) returned %d: %m", ret);
        return ret;
    }

    LOG("received status %d", reply.status);
    *status = reply.status;
    return 0;
}

/* Send rpc request to the server */
int rpc_getattr_request(rpc_t *rpc, const char *path, struct stat *stbuf)
{
    int status,ret;

    ret = rpc_send_request(rpc, GET_ATTR, 0, path, &status, -1, -1,-1, 0, 0);
    if (ret < 0) {
        return ret;
    }

    if (status < 0) {
        return status;
    }

    /* Recv stbuf from the server */
    ret = recv(rpc->sockfd, stbuf, sizeof(*stbuf), MSG_WAITALL);
    if (ret < 0) {
        LOG_ERROR("recv(stbuf) returned %d: %m", ret);
        return ret;
    }

    return 0;
}

/* Send read directory request to the server and then get list of
   names from the server. For each name we receive, call filler(name, arg)filler */
int rpc_readdir_request(rpc_t *rpc, const char *path, readdir_filler_t filler, void *arg)
{
	char name[NAME_MAX];
    int name_len;
    int status;
    int ret;

	ret = rpc_send_request(rpc, READ_DIR, 0, path, &status, -1, -1, -1, 0, 0);
    if (ret < 0) {
        return ret;
    }

    if (status < 0) {
        return status;
    }

	for (;;) {
		ret = recv(rpc->sockfd, &name_len, sizeof(name_len), MSG_WAITALL);
        if (ret < 0) {
			LOG_ERROR("recv(name_len) returned %d: %m", ret);
			return ret;
		}

        if (name_len == 0) {
            LOG("got all files");
            return 0;
        }

		ret = recv(rpc->sockfd, name, name_len, MSG_WAITALL);
        if (ret < 0) {
			LOG_ERROR("recv(name, length=%d) returned %d: %m", name_len, ret);
			return ret;
		}

		name[name_len] = '\0';
        LOG("name='%s' len %d", name, name_len);
		filler(name, arg);
	}
}

/* send make directory request to server */
int rpc_mkdir_request(rpc_t *rpc, const char *path, mode_t mode)
{
    int status, ret, result;

    ret = rpc_send_request(rpc, MK_DIR, mode, path, &status, -1, -1, -1, 0, 0);
    if (ret < 0) {
        return ret;
    }

    if (status < 0) {
        return status;
    }

    ret = recv(rpc->sockfd, &result, sizeof(result), MSG_WAITALL);
    if (ret < 0) {
        LOG_ERROR("recv(result=%d) returned %d: %m", result, ret);
        return ret;
    }

    if (result != 0) {
        LOG_ERROR("result=%d %m", result);
        return result;
    }

    return 0;
}

/* send remove directory request to server */
int rpc_rmdir_request(rpc_t *rpc, const char *path)
{
    int status, ret;
    
    ret = rpc_send_request(rpc, RM_DIR, 0, path, &status, -1, -1,-1, 0, 0);
    if (ret < 0) {
        return ret;
    }

    return status;
}

/* send open file request to server */
int rpc_open_request(rpc_t *rpc, const char *path, int flags)
{
    int status, ret, fd;

    ret = rpc_send_request(rpc, OPEN, flags, path, &status, -1, -1, -1, 0, 0);
    if (ret < 0) {
        return ret;
    }

    if (status < 0) {
        return status;
    }

    ret = recv(rpc->sockfd, &fd, sizeof(fd), MSG_WAITALL);
    if (ret < 0) {
        LOG_ERROR("recv(fd=%d) returned %d: %m", fd, ret);
        return ret;
    }

    return fd;
}

/* Release an open file */
int rpc_release_request(rpc_t *rpc, uint64_t fd)
{
    int status, ret;
    ret = rpc_send_request(rpc, RELEASE, 0, "", &status, fd, -1, -1, 0, 0);
    if (ret < 0) {
        LOG_ERROR("recv(fd=%d) returned %d: %m", (int)fd, ret);
        return ret;
    }

    return status;
}

/* Remove a file */
int rpc_unlink_request(rpc_t *rpc, const char *path)
{
    int status, ret;
    ret = rpc_send_request(rpc, UNLINK, 0, path, &status, -1, -1, -1, 0, 0);
    if (ret < 0) {
        LOG_ERROR("recv(fd=%d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    return status;
}

/* send request to read a file to server */
ssize_t rpc_read_request(rpc_t *rpc, char *buf, uint64_t fd, size_t size, off_t offset)
{
    int status, ret;
    size_t fsize;

    ret = rpc_send_request(rpc, READ, 0, "", &status, fd, size, offset, 0, 0);
    if (ret < 0) {
        LOG_ERROR("recv(fd %d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    /* Recv the file size */
    ret = recv(rpc->sockfd, &fsize, sizeof(fsize), MSG_WAITALL);
    if (ret < 0) {
        LOG_ERROR("recv(fd %d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    /* Recv the file contents */
    if (fsize > 0) {
        ret = recv(rpc->sockfd, buf, fsize, MSG_WAITALL);
        if (ret < 0) {
            return ret;
        }

        /* Expect all data to be received */
        assert(ret == fsize);
    }
    
    LOG("fsize=%zu", fsize);
    return fsize;
}

/* send request to write on a file to server */
ssize_t rpc_write_request(rpc_t *rpc, const char *buf, uint64_t fd, size_t size,
                          off_t offset)
{
    int status, ret,buf_size;
    size_t fsize;
   
    ret = rpc_send_request(rpc, WRITE, 0, "", &status, fd, size, offset, buf, size);
    if (ret < 0) {
        LOG_ERROR("recv(fd %d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    /* Recv the written size */
    ret = recv(rpc->sockfd, &fsize, sizeof(fsize), MSG_WAITALL);
    if (ret < 0) {
        LOG_ERROR("recv(fd %d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    LOG("fsize=%zu", fsize);
    return fsize;
}

/* send request to create and open a file to server */
int rpc_create_request(rpc_t *rpc, const char *path, mode_t mode)
{
    int status, ret, fd;

    ret = rpc_send_request(rpc, CREATE, mode, path, &status, -1, -1, -1, 0, 0);
    if (ret < 0) {
        return ret;
    }

    if (status < 0) {
        return status;
    }

    ret = recv(rpc->sockfd, &fd, sizeof(fd), MSG_WAITALL);
    if (ret < 0) {
        LOG_ERROR("recv(fd %d) returned %d: %m", fd, ret);
        return ret;
    }

    return fd;
}

/* send request to change the permission bits of a file to server  */
int rpc_chmod_request(rpc_t *rpc, const char *path, mode_t mode)
{
    int status, ret, result;

    ret = rpc_send_request(rpc, CHMOD, mode, path, &status, -1, -1, -1, 0, 0);
    if (ret < 0) {
        LOG_ERROR("recv(fd=%d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    return status;
}

/* send request to change the access and modification times of a file with nanosecond resolution to server */
int rpc_utimens_request(rpc_t *rpc, const char *path, const struct timespec *tv)
{
    int status, ret, size;

    ret = rpc_send_request(rpc, UTIMENS, 0, path, &status, -1, -1, -1, tv,
                           sizeof(*tv) * 2);
    if (ret < 0) {
        LOG_ERROR("recv(fd=%d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    return status;
}

/* send request to change the owner and group of a file to server  */
int rpc_chown_request(rpc_t *rpc, const char *path, const ugid_struct *ugid)
{
    int status, ret, result;

    ret = rpc_send_request(rpc, CHOWN, 0, path, &status, -1, -1, -1, ugid, sizeof(*ugid));
    if (ret < 0) {
        LOG_ERROR("recv(fd=%d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    return status;
}

/* send request to rename a file to server  */
int rpc_rename_request(rpc_t *rpc, const char *old_name, const char *new_name,
                       unsigned int flags)
{
    size_t new_name_len = strlen(new_name);
    int status, ret, result;

    ret = rpc_send_request(rpc, RENAME, flags, old_name, &status, -1, new_name_len, 
                           -1, new_name, new_name_len);
    if (ret < 0) {
        LOG_ERROR("recv(fd=%d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    return status;
}

/* send request to change the size of a file to server*/
int rpc_truncate_request(rpc_t *rpc, const char *path, off_t offset)
{
    int status, ret, result;

    ret = rpc_send_request(rpc, TRUNCATE, 0, path, &status, -1, -1, offset, 0, 0);
    if (ret < 0) {
        LOG_ERROR("recv(fd=%d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    return status;
}

/* send request to create a symbolic link to a file to server*/
int rpc_symlink_request(rpc_t *rpc, const char *from, const char *to)
{
    size_t to_len = strlen(to);
    int status, ret, result;

    ret = rpc_send_request(rpc, SYMLINK, 0, from, &status, -1, to_len, -1, 
                           to, to_len);
    if (ret < 0) {
        LOG_ERROR("recv(fd=%d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    return status;
}

/* send request to create a hard link to a file to server*/
int rpc_link_request(rpc_t *rpc, const char *from, const char *to)
{
    size_t to_len = strlen(to);
    int status, ret, result;

    ret = rpc_send_request(rpc, LINK, 0, from, &status, -1, to_len, -1, to, to_len);
    if (ret < 0) {
        LOG_ERROR("recv(fd %d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    return status;
}

/* send request to read the target of a symbolic link to server*/
int rpc_read_link_request(rpc_t *rpc, const char *path, char *buf, size_t buf_size)
{
    int status, ret, result;
    char link_path[PATH_MAX];
    size_t link_size;

    /* send rpc request */
    ret = rpc_send_request(rpc, READ_LINK, 0, path, &status, -1 , 0, 
                           -1, NULL, 0);
    if (ret < 0) {
        LOG_ERROR("recv(fd %d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }
    
    /* Recv the link buffer size */
    ret = recv(rpc->sockfd, &link_size, sizeof(link_size), MSG_WAITALL);
    if (ret < 0) {
        LOG_ERROR("recv(fd %d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    /* Recv the link content */
    ret = recv(rpc->sockfd, link_path, link_size, MSG_WAITALL);
    if (ret < 0) {
        LOG_ERROR("recv(fd=%d) returned %d: %m", rpc->sockfd, ret);
        return ret;
    }

    /* If user buffer is smaller than actual size, copy the
       minimal portion */
    memcpy(buf, link_path, min(link_size, buf_size));
    return 0; 
}

/* Socket create and varification */
int rpc_connect(rpc_t *rpc, const char *server_addr)
{
    struct sockaddr_in servaddr;
    int ret;

    LOG("connecting to %s", server_addr);
    ret = socket(AF_INET, SOCK_STREAM, 0);
    if (ret < 0) {
        LOG_ERROR("socket() returned %d: %m", ret);
        return ret;
    }

    rpc->sockfd = ret;

    /* Assign ip and port */
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(server_addr);
    servaddr.sin_port = htons(PORT);

    /* Connect the client socket to server socket */
    ret = connect(rpc->sockfd, (SA*)&servaddr, sizeof(servaddr));
    if (ret < 0) {
        LOG_ERROR("connect() returned %d: %m", ret);
        return ret;
    }

    LOG("socket %d conected to %s", rpc->sockfd, server_addr);
    return 0;
}