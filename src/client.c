#define FUSE_USE_VERSION 31

#include <arpa/inet.h>
#include <fuse3/fuse.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <bits/types.h>
#include "common.h"
#include "util.h"
#include <string.h>

#define OPTION(t, p) \
    { t, offsetof(struct options, p), 1 }

/* Command line options */
static struct options
{
	const char *server_addr;
	int 		show_help;
	const char *filename;
} options;

/* define options */
static const struct fuse_opt option_spec[] =
{
	OPTION("--server=%s", server_addr),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

/* Holds a buf that has all the context and a function that filles the buf with context */
/* context for the callback of reading file list */
typedef struct
{
	void *buf;
	fuse_fill_dir_t filler;
} filler_context_t;

/* Global rpc for the client */
static rpc_t client_rpc;

/* Get the attributes of the file */
static int client_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{
	/* Get the attributes of all contents in given path into stbuf */
	LOG("path=%s fi=%p", path, fi);
	return rpc_getattr_request(&client_rpc, path, stbuf);
}
/*go throug again */
/* Function that filles the context in readdir action */
static void client_readdir_filler(const char *name, void *arg)
{
	filler_context_t *context = arg;
	context->filler(context->buf, name, NULL, 0, 0);
}
/*go throug again */
/* The function will be called when the user tries to show the files
   and directories that resides in a specific directory. */
static int client_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
						  struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
	filler_context_t context;
	
	LOG("path=%s", path);
	context.buf = buf;
	context.filler = filler;
	return rpc_readdir_request(&client_rpc, path, client_readdir_filler, &context);
}

/* Create a directory */
static int client_mkdir(const char *path, mode_t mode)
{
	LOG("path=%s mode=%u", path,  mode);
	return rpc_mkdir_request(&client_rpc, path, mode|S_IFDIR);;
}

/* Remove a directory */
static int client_rmdir(const char *path)
{
	LOG("path=%s", path);
	return rpc_rmdir_request(&client_rpc, path);
}

/* Open a file*/
static int client_open(const char *path, struct fuse_file_info *fi)
{
	int fd;

	LOG("path=%s fi=%p", path, fi);
	
	fd = rpc_open_request(&client_rpc, path, fi->flags);
	if (fd < 0) {
		return fd;
	}

	/* Save file desc in the fi structure */
	LOG("fi %p: set fd %d", fi, fd);
	fi->fh = fd;
	return 0;
}

/* Release an open file - Release is called when there are no more references to an open
	 file: all file descriptors are closed and all memory mappings are unmapped. */
static int client_release(const char *path, struct fuse_file_info *fi)
{
	LOG("path=%s fi=%p fi->fh=%d", path, fi, (int)fi->fh);
    return rpc_release_request(&client_rpc, fi->fh);
}

/* Remove a file */
static int client_unlink(const char *path) 
{
	LOG("path=%s", path);
	return rpc_unlink_request(&client_rpc, path);
}

/* Read data from an open file */
static int client_read(const char *path, char *buf, size_t size, off_t offset,
                       struct fuse_file_info *fi)
{
	LOG("path=%s buf=%p size=%zu offset=%ld fi=%p fi->fh=%d", path, buf, size, offset,
         fi, (int)fi->fh);
	return rpc_read_request(&client_rpc, buf, fi->fh, size, offset);
}

/* Write data to an open file */
static int client_write(const char *path, const char *buf, size_t size, off_t offset, 
                        struct fuse_file_info *fi)
{
	LOG("path=%s buf=%p size=%zu offset=%ld fi=%p fi->fh=%d", path, buf, size, offset,
         fi, (int)fi->fh);
	return rpc_write_request(&client_rpc, buf, fi->fh, size, offset);
}

/* Create and open a file. If the file does not exist, first create it with the
   specified mode, and then open it.*/
static int client_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd;

	LOG("path=%s mode=%u fi=%p", path, mode, fi);
	
	fd = rpc_create_request(&client_rpc, path, mode);
	if(fd < 0) {
		return fd;
	}

	LOG("fi %p: set fd %d", fi, fd);
	fi->fh = fd;
	return 0;
}

/* Change the permission bits of a file */
static int client_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	LOG("path=%s mode=%u fi=%p", path, mode, fi);
	return rpc_chmod_request(&client_rpc, path, mode);
}

/* Change the owner and group of a file - this method is
	expected to reset the setuid and setgid bits. */
static int client_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
{
	ugid_struct ugid;

	LOG("path=%s uid=%u gid=%u fi=%p", path, uid, gid, fi);
	ugid.uid = uid;
	ugid.gid = gid;
	return rpc_chown_request(&client_rpc, path, &ugid);
}

/* Change the access and modification times of a file with nanosecond resolution */
static int client_utimens(const char *path, const struct timespec tv[2], 
                          struct fuse_file_info *fi)
{
	LOG("path=%s fi=%p", path, fi);
	return rpc_utimens_request(&client_rpc, path, tv);
}

/* Rename a file -
	*flags* may be `RENAME_EXCHANGE` or `RENAME_NOREPLACE`.
	If RENAME_NOREPLACE is specified, the filesystem must not
	overwrite *newname* if it exists and return an error
	instead. If `RENAME_EXCHANGE` is specified, the filesystem
	must atomically exchange the two files, i.e. both must
	exist and neither may be deleted. */
static int client_rename(const char *old_name, const char *new_name, unsigned int flags)
{
	LOG("old_name=%s new_name=%s flags=0x%x", old_name, new_name, flags);
	return rpc_rename_request(&client_rpc, old_name, new_name, flags);
}

/* Change the size of a file - this method is
	 expected to reset the setuid and setgid bits. */
static int client_truncate(const char *path, off_t offset, struct fuse_file_info *fi)
{
	LOG("path=%s offset=%ld fi=%p", path, offset, fi);
	return rpc_truncate_request(&client_rpc, path, offset);
}

/* Create a symbolic link */
static int client_symlink(const char *to, const char *from)
{
	LOG("to=%s from=%s", to, from);
	return rpc_symlink_request(&client_rpc, from, to);
}

/** Read the target of a symbolic link
 * The buffer should be filled with a null terminated string.  The
 * buffer size argument includes the space for the terminating
 * null character.  If the linkname is too long to fit in the
 * buffer, it should be truncated.  The return value should be 0
 * for success.
 */
static int client_read_link(const char * path, char * buf, size_t buf_size)
{
	LOG("path=%s buf=%s buf_size=%zu", path, buf, buf_size);
	return rpc_read_link_request(&client_rpc, path, buf, buf_size);
}

/* Create a hard link to a file */
static int client_link(const char *from, const char *to)
{
	LOG("from=%s to=%s", from, to);
	return rpc_link_request(&client_rpc, from, to);
}

/* File system operation */
static const struct fuse_operations oper =
{
  	.getattr 	= client_getattr,	 	
  	.readdir 	= client_readdir,	 	
	.mkdir 		= client_mkdir, 		
	.rmdir 		= client_rmdir, 		
	.open 		= client_open, 			
	.release 	= client_release,	 	
	.unlink 	= client_unlink, 		
  	.read 		= client_read, 			
	.write 		= client_write,		    
  	.create	  	= client_create,		
	.chmod    	= client_chmod,         
	.chown    	= client_chown,         
	.rename   	= client_rename,        
	.utimens  	= client_utimens,       
	.truncate 	= client_truncate,      
	.symlink  	= client_symlink,       
	.readlink 	= client_read_link,     
	.link     	= client_link           
 };

/* Print help menu */
static void show_help(const char *progname)
{
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("File-system specific options:\n"
	      "    --server=<s>          Server ip address\n"
	      "\n");
}

int main(int argc , char *argv[])
{
	/* Initializer for 'struct fuse_args' */
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct sockaddr_in servaddr;
	struct in_addr addrptr;
	int ret;

	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1) {
		return -1;
  	}

	/* In case of help menu or not given server address as argument */
	if (options.show_help || (options.server_addr == NULL)) {
		show_help(argv[0]);
		assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0][0] = '\0';
	}

	rpc_connect(&client_rpc, options.server_addr);

	ret = fuse_main(args.argc, args.argv, &oper, NULL);
	fuse_opt_free_args(&args);
  	close(client_rpc.sockfd);
  	return ret;
}