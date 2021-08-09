#include <assert.h>

#include "util.h"
#include "common.h"


/* Sending the length and the name of the content in requested directory */
int rpc_readdir_reply(rpc_t *rpc, char *name)
{
    int ret;
    int len = strlen(name);

    LOG("send readdir reply name '%s' length %d", name, len);

    ret = send(rpc->sockfd, &len, sizeof(len), 0);
    if (ret < 0) {
        LOG_ERROR("send(len) returned %d: %m", ret);
        return ret;
    }

    ret = send(rpc->sockfd, name, strlen(name), 0);
    if (ret < 0) {
        LOG_ERROR("send(name) returned %d and name of content is %s: %m",
                  ret, name);
        return ret;
    }

    return 0;
}

/* Get the file status from server to get back to client*/
int rpc_getattr_reply(rpc_t *rpc, const struct stat *file_stat)
{
    int ret;

    LOG("send getattr reply mode %d size %jd", file_stat->st_mode, 
        file_stat->st_size);

    ret = send(rpc->sockfd, file_stat, sizeof(*file_stat), 0);
    if (ret < 0) {
        LOG_ERROR("send(stat) returned %d: %m", ret);
        return ret;
    }

    return 0;
}

/* Get the mkdir status from server to get back to client*/
int rpc_mkdir_reply(rpc_t *rpc, int result) 
{
    int ret;

    LOG("send mkdir reply result %d", result);

    ret = send(rpc->sockfd, &result, sizeof(result), 0);
    if (ret < 0) {
        LOG_ERROR("send(result) returned %d: %m", ret);
        return ret;
    }

    return 0;
}
/* Get the open status from server to get back to client*/
int rpc_open_reply(rpc_t *rpc, int fd)
{
    int ret;
    
    LOG("send open reply fd %d", fd);

    ret = send(rpc->sockfd, &fd, sizeof(fd), 0);
    if (ret < 0) {
        LOG_ERROR("send(result) returned %d: %m", ret);
        return ret;
    }

    return 0;
}

/* send the file size to the client */
int rpc_read_size_reply(rpc_t *rpc, size_t size) 
{
    int ret;

    LOG("send read reply size %zu", size);

    ret = send(rpc->sockfd, &size, sizeof(size), 0);
    if(ret < 0) {
        LOG_ERROR("send(size of file) returned %d: %m", ret);
        return ret;
    }

    return 0;
}

/* send the file size to the client */
int rpc_write_size_reply(rpc_t *rpc, size_t size) {

    int ret;

    LOG("write size reply size %zu", size);

    ret = send(rpc->sockfd, &size, sizeof(size), 0);
    if(ret < 0) {
        LOG_ERROR("send(size of file) returned %d: %m", ret);
        return ret;
    }

    return 0;
}

/* Get the create file status from server to get back to client*/
int rpc_create_reply(rpc_t *rpc, int fd)
{
    int ret;

    LOG("create reply fd %d", fd);

    ret = send(rpc->sockfd, &fd, sizeof(fd), 0);
    if (ret < 0) {
        LOG_ERROR("send(result) returned %d: %m", ret);
        return ret;
    }

    return 0;
}

/* Get the chown status from server to get back to client*/
int rpc_chown_reply(rpc_t *rpc, int res)
{
    int ret;

    LOG("chown reply result %d", res);

    ret = send(rpc->sockfd, &res, sizeof(res), 0);
    if (ret < 0) {
        LOG_ERROR("send(result) returned %d: %m", ret);
        return ret;
    }

    return 0;
}

/* Server calls this function to get the rpc request */
int rpc_recv_request(rpc_t *rpc, operation_t *op, mode_t *mode, char *path, uint64_t *fd,
                     size_t *size, off_t *offset, uint32_t *path_length)
{
    rpc_request_header_t header;
    int ret;

    /* Recieve the header */
    ret = recv(rpc->sockfd, &header, sizeof(header), MSG_WAITALL); /* here msg is sent*/

    LOG("received RPC request op=%d mode=%d path_len=%d fd=%ld size=%ld offset=%ld path length=%d",
        header.op, header.mode, header.path_length, header.fd, header.size, header.offset, header.path_length);

    if (ret < 0) {
        LOG_ERROR("recv(header) returned %d: %m", ret);
        return ret;
    }

    *op = header.op;
    *mode = header.mode;
    *fd = header.fd;
    *size = header.size;
    *offset =  header.offset;
    *path_length = header.path_length;

    if (header.path_length > 0) {
        ret = recv(rpc->sockfd, path, header.path_length, MSG_WAITALL);
        if (ret < 0) {
            LOG_ERROR("recv(path, length=%d) returned %d: %m", header.path_length, ret);
            return ret;
        }
    }

    path[header.path_length] = '\0';
    return 0;
}

/* Send result of the operation from server to client. status is 0 in case of success, or
   the value of errno in case of failure */
int rpc_reply_status(rpc_t *rpc, int sys_ret, int sys_errno) {
    rpc_reply_header_t reply;
    int ret;

    LOG("reply status sys_ret %d sys_errno %d", sys_ret, sys_errno);
    
    if (sys_ret < 0) {
        /* System operation failed, set status to the error code
           Expect that errno is a positive value */
        assert(sys_errno > 0);
        reply.status = -sys_errno;
    } else {
        /* Operation was successful */
        reply.status = 0;
    }

    ret = send(rpc->sockfd, &reply, sizeof(reply), 0);
    if (ret < 0) {
        LOG_ERROR("send(reply) returned %d: %m", ret);
        return ret;
    }

    return 0;
}

/* Accept the data packet from client and verification */
int rpc_accept(rpc_t *rpc, int listen_sockfd) {
    int ret;

    LOG("accepting new connection fd %d listen socket fd %d", rpc->sockfd, listen_sockfd);

    ret = accept(listen_sockfd, NULL, 0);
    if (ret < 0) {
        LOG_ERROR("accept(fd=%d) returned %d: %m", listen_sockfd, ret);
        return ret;
    }

    /* Connection accepted */
    rpc->sockfd = ret;
    LOG("accepted");
    return 0;
}