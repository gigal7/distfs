#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <linux/limits.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>

#define PORT		1993
#define SA	struct sockaddr
#define FOURKB 		4096
#define ONE_KB      1024
#define MAX_FD      1000 /* maximum fds a server can listen to */
#define MAX_EVENTS  32 /* the maximum number of events */
#define TIMEOUT     -1 /* infinite time */

enum contentType { FILE_TYPE, FOLDER_TYPE };

/* operations names */
typedef enum {
	READ_DIR,
	GET_ATTR,
	MK_DIR,
	RM_DIR,
	OPEN,
	RELEASE,
	UNLINK,
	READ,
	WRITE,
	CREATE,
	CHMOD,
	UTIMENS,
	CHOWN,
	RENAME,
	TRUNCATE,
	SYMLINK,
	READ_LINK,
	LINK
} operation_t;

/* a request data - a client sends this to the server */
typedef struct {
    operation_t	 op;
	mode_t 		 mode;
    uint32_t     path_length;
	uint64_t  	 fd;
	size_t 		 size;
	off_t 		 offset;
} rpc_request_header_t;

typedef struct {
    int          status; /* value of errno */
} rpc_reply_header_t;

/* rpc_t holds the socket number */
typedef struct {
	int          sockfd;
} rpc_t;

/* the data for chown that the client sends to the server */ 
typedef struct {
  uid_t 		 uid;
  gid_t 		 gid;
} ugid_struct;

/* בommand_type defines a command to perform on a file/folder */
typedef struct {
	uint8_t 	 operation;
} Command_type;

/* function that filles the context in readdir action */
typedef void (*readdir_filler_t)(const char *name, void *arg);

extern const char *operation_names[];

/* common.c function */
int min(off_t size_one, size_t size_two);

/* rpc_client functions */
int rpc_connect(rpc_t *rpc, const char *server_addr) ;
int rpc_readdir_request(rpc_t *rpc, const char *path, readdir_filler_t filler, void *arg);
int rpc_getattr_request(rpc_t *rpc,const char *path, struct stat *stbuf);
int rpc_mkdir_request(rpc_t *rpc, const char *path, mode_t mode);
int rpc_rmdir_request(rpc_t *rpc, const char *path);
int rpc_open_request(rpc_t *rpc, const char *path,int flags);
int rpc_release_request(rpc_t *rpc, uint64_t fd);
int rpc_unlink_request(rpc_t *rpc, const char *path);
ssize_t rpc_read_request(rpc_t *rpc,  char *buf, uint64_t fd, size_t size, off_t offset);
ssize_t rpc_write_request(rpc_t *rpc, const char *buf, uint64_t fd, size_t size, off_t offset);
int rpc_create_request(rpc_t *rpc, const char *path, mode_t mode);
int rpc_chmod_request(rpc_t *rpc, const char *path, mode_t mode);
int rpc_utimens_request(rpc_t *rpc, const char *path, const struct timespec *tv);
int rpc_chown_request(rpc_t *rpc, const char *path, const ugid_struct *ugid);
int rpc_rename_request(rpc_t *rpc, const char *old_name, const char *new_name, unsigned int flags);
int rpc_truncate_request(rpc_t *client_rpc, const char *path, off_t offset);
int rpc_symlink_request(rpc_t *rpc, const char *from, const char *to);
int rpc_link_request(rpc_t *rpc, const char *from, const char *to);
int rpc_read_link_request(rpc_t *rpc, const char *path, char *buf, size_t size);


/* rpc_server functions */
int rpc_recv_request(rpc_t *rpc, operation_t *op, mode_t *mode, char *path, uint64_t *fd,
                     size_t *size, off_t *offset, uint32_t *path_length);
int rpc_reply_status(rpc_t *rpc, int sys_ret, int sys_errno);
int rpc_readdir_reply(rpc_t *rpc, char *name);
int rpc_getattr_reply(rpc_t *rpc, const struct stat *file_stat);
int rpc_accept(rpc_t *rpc, int listen_sockfd);
int rpc_mkdir_reply(rpc_t *rpc, int result);
int rpc_open_reply(rpc_t *rpc, int result);
int rpc_read_size_reply(rpc_t *rpc, size_t size);
int rpc_write_size_reply(rpc_t *rpc, size_t size);
int rpc_create_reply(rpc_t *rpc, int fd);
int rpc_chmod_reply(rpc_t *rpc, int res);
int rpc_utimens_reply(rpc_t *rpc, int res);
int rpc_chown_reply(rpc_t *rpc, int res);