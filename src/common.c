#include "common.h"

/* operation names - for handel request function - switch case  */
const char *operation_names[] = {
	[READ_DIR] =	"readdir",
	[GET_ATTR] =	"getattr",
	[MK_DIR]   = 	"mkdir",
	[RM_DIR]   =	"rmdir",
    [OPEN]     = 	"open",
    [RELEASE]  =	"release",
	[UNLINK]   = 	"unlink",
	[READ]     = 	"read",
	[WRITE]    = 	"write",
	[CREATE]   = 	"create",
	[UTIMENS]  =    "utimens",
	[RENAME]   =    "rename",
	[TRUNCATE] =    "truncate",
	[SYMLINK]  =    "symlink",
	[READ_LINK] =   "read_link", 
	[LINK]     =    "link"
};

/* return the minimum  value */
int min(off_t size_one, size_t size_two) {
	if(((int) size_one) <= ((int)size_two)) {
		return (int)size_one;
	} 
	return (int)size_two;
}

