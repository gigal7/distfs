
#include <libgen.h>

// Logging macro
#define LOG(_fmt, ...) \
	printf("[%s:%d] %s() - " _fmt "\n", basename(__FILE__), __LINE__, __FUNCTION__, ## __VA_ARGS__)

// Logging error macro
#define LOG_ERROR(_fmt, ...) \
	LOG("Error: " _fmt, ## __VA_ARGS__)
