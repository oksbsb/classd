#ifndef NAVL_H
#define NAVL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/*******************************************************************************
 * Types and constants
 ******************************************************************************/

typedef enum {
	NAVL_STATE_TERMINATED = 0,  /* Indicates the connection has been terminated */
	NAVL_STATE_INSPECTING = 1,  /* Indicates the connection is under inspection */
	NAVL_STATE_MONITORING = 2,  /* Indicates the connection is under monitoring */
	NAVL_STATE_CLASSIFIED = 3   /* Indicates the connection is fully classified */
} navl_state_t;

typedef enum {
	NAVL_ENCAP_NONE = 0,     /* When no layer 2-4 transport headers are present */
	NAVL_ENCAP_ETH  = 1,     /* Buffer under inspection starts at Ethernet header */
	NAVL_ENCAP_IP   = 2,     /* Buffer under inspection starts at IPv4 header */
	NAVL_ENCAP_IP6  = 3      /* Buffer under inspection starts at IPv6 header */
} navl_encap_t;

#define NAVL_AF_UNSPEC  0
#define NAVL_AF_INET    1
#define NAVL_AF_INET6   2

typedef struct navl_host {
	unsigned char  family;          /* NAVL_AF_INET or NAVL_AF_INET6 */
	unsigned char  padding;
	unsigned short port;            /* Layer 4 port in network order */
	union {
		unsigned int  in4_addr;     /* IPv4 address in network order */
		unsigned char in6_addr[16]; /* IPv6 address in network order */
	};
} navl_host_t;

enum {
	/* Context is available in the most significant 16 bits */
	NAVL_ATTR_F_CTXMASK  = 0xFFFF0000,

	/* Flag bits are available in the least significant 16 bits */
	NAVL_ATTR_F_BITMASK  = 0x0000FFFF,
	NAVL_ATTR_F_FRAGMENT = (1 << 0)
};

enum {
	/* As a policy, controls whether these features are enabled for a given
	 * instance. As a status, indicates the current features applied to the
	 * connection. */
	NAVL_CONN_F_DPI        = (1 << 0),
	NAVL_CONN_F_MUTABLE    = (1 << 1),
	NAVL_CONN_F_FUTUREFLOW = (1 << 2),
	NAVL_CONN_F_ATTRIBUTE  = (1 << 3),
	NAVL_CONN_F_TUNNELING  = (1 << 4)
};

typedef void *navl_iterator_t;
typedef void *navl_result_t;
typedef int navl_handle_t;
typedef void *navl_conn_t;
typedef uint64_t navl_conn_id_t;
typedef uint32_t navl_conn_flags_t;


/*******************************************************************************
 * Library instance and thread initialization
 ******************************************************************************/

/*
 * navl_open()
 *
 * Opens a new navl instance and registers the available classification plugins.
 * On success, a handle for the instance is returned. On error, -1 is returned.
 */
navl_handle_t navl_open(const char *plugins);

/*
 * navl_init()
 *
 * Initializes a thread for the handle.
 * On success, 0 is returned. On error, -1 is returned.
 */
int navl_init(navl_handle_t handle);

/*
 * navl_fini()
 *
 * Finalize a thread for the handle.
 * On success, 0 is returned. On error, -1 is returned.
 */
int navl_fini(navl_handle_t handle);

/*
 * navl_close()
 * 
 * Closes the navl instance referenced by @handle.
 * On success, 0 is returned. On error, -1 is returned. 
 */
int navl_close(navl_handle_t handle);


/*******************************************************************************
 * Classification APIs 
 ******************************************************************************/

/* 
 * navl_classify_simple()
 *
 * Simple classification API.
 * On success, 0 is returned and the best classification result is available in
 * @index. On error, -1 is returned.
 */
int navl_classify_simple(navl_handle_t handle, const void *data, unsigned short len, int *index);

/* 
 * navl_classify()
 *
 * Main classification API
 * On success, the user callback is invoked and 0 is returned. On error, -1 is 
 * returned.
 *
 * Notes:
 *
 * The classify_callback signature includes an error parameter. Errors reported
 * in the callback are not considered critical, but provide an indication when
 * results may have been compromised.
 */

typedef int (*navl_classify_callback_t)(navl_handle_t handle, navl_result_t result, navl_state_t state
	, navl_conn_t conn, void *arg, int error);

int navl_classify(navl_handle_t handle, navl_encap_t encap, const void *data, unsigned short len
	, navl_conn_t conn, int direction, navl_classify_callback_t, void *arg);


/*******************************************************************************
 * Result processing
 ******************************************************************************/

/* 
 * navl_conn_id_get()
 *
 * Returns the connection identifier assigned to this navl_conn_t. 
 *
 * Note: 
 *
 * A connection identifier is unique per instance. This API should never fail;
 * however, a connection identifier with a value of 0 (zero) indicates that navl
 * is not tracking the connection and any result data applies only to the current
 * packet under inspection.
 */
navl_conn_id_t navl_conn_id_get(navl_handle_t handle, navl_conn_t conn);

/*
 * navl_endpoint_get()
 *
 * Provides the endpoint information for the connection. The results always reflect
 * the direction of the packet under inspection.
 *
 * On success, 0 is returned and @src and @dst are filled in accordingly. 
 * On error, -1 is returned.
 */
int navl_endpoint_get(navl_handle_t handle, navl_conn_t conn, navl_host_t *src, navl_host_t *dst);

/*
 * Callback signature for navl_futureflow_callback_set()
 *
 * @src         the initiator host info
 * @dst         the recipient host info
 * @proto       the ip protocol
 * @parent_id   the app id of the flow expecting the futureflow
 * @child_id    the app id of the future flow
 *
 */ 
typedef void (*navl_futureflow_callback_t)(navl_handle_t, navl_host_t *src, navl_host_t *dst, unsigned char proto, int parent_id, int child_id); 

/*
 * navl_futureflow_callback_set()
 * 
 * Bind a futureflow handler for the given instance.
 *
 * On sucess, 0 is returned. On error, -1 is returned.
 */
int navl_futureflow_callback_set(navl_handle_t, navl_futureflow_callback_t);

/*
 * navl_app_get()
 *
 * On success, returns the application protocol index for the result and sets a
 * confidence value in @confidence. On error, -1 is returned.
 */
int navl_app_get(navl_handle_t handle, navl_result_t result, int *confidence);

/*
 * navl_proto_first()
 *
 * Returns the first iterator in the result.
 */
navl_iterator_t navl_proto_first(navl_handle_t handle, navl_result_t result);

/* 
 * navl_proto_valid()
 *
 * Returns 1 if the iterator is valid.
 */
int navl_proto_valid(navl_handle_t handle, navl_iterator_t it);

/*
 * navl_proto_next()
 *
 * Returns the next iterator.
 */
navl_iterator_t navl_proto_next(navl_handle_t handle, navl_iterator_t it);

/*
 * navl_proto_prev()
 *
 * Returns the prev iterator.
 */
navl_iterator_t navl_proto_prev(navl_handle_t handle, navl_iterator_t it);

/*
 * navl_proto_top()
 *
 * Returns an iterator pointing to the top most protocol.
 */
navl_iterator_t navl_proto_top(navl_handle_t handle, navl_result_t result);

/*
 * navl_proto_find()
 *
 * Returns an iterator pointing to the protocol @index.
 */
navl_iterator_t navl_proto_find(navl_handle_t handle, navl_result_t result, int index);

/*
 * navl_proto_get_index()
 *
 * Extracts the protocol from the iterator.
 */
int navl_proto_get_index(navl_handle_t handle, navl_iterator_t it);

/*
 * navl_proto_find_index()
 *
 * Extracts the protocol from the short name.
 */
int navl_proto_find_index(navl_handle_t handle, const char *name);

/*
 * navl_proto_get_name()
 *
 * Returns a pointer to the proto name/
 */
const char *navl_proto_get_name(navl_handle_t handle, int index, char *buf, unsigned int size);


/*******************************************************************************
 * Connection information
 ******************************************************************************/

/*
 * navl_conn_status_flags_get()
 *
 * Fetch the connection flags enabled for @conn.
 *
 * On success, return 0. On error, returns -1.
 */
int navl_conn_status_flags_get(navl_handle_t handle, navl_conn_t conn, navl_conn_flags_t *flags);

/*
 * navl_conn_policy_flags_disable()
 *
 * Clear the specific policy flags for @conn. 
 *
 * On success, return 0, On error, return -1.
 */
int navl_conn_policy_flags_disable(navl_handle_t handle, navl_conn_t conn, navl_conn_flags_t flags);


/*******************************************************************************
 * Connection management (IPv4 and IPv6)
 ******************************************************************************/

/*
 * navl_conn_create()
 *
 * Allocate connection state by 5-tuple.
 *
 * On success, 0 is returned and opaque state is attached to @conn. On error, 
 * -1 is returned.
 *
 * Note:
 *
 * The integrator MUST ensure they pair each successful call to navl_conn_create()
 * with a call to navl_conn_destroy(). This ensure navl can release all associated 
 * resources.
 */
int navl_conn_create(navl_handle_t handle, navl_host_t *shost, navl_host_t *dhost, unsigned char proto, navl_conn_t *conn);

/*
 * navl_conn_destroy()
 *
 * Releases connection state previously allocated by navl_conn_create().
 *
 * On success, 0 is returned. On error, -1 is returned. 
 */
int navl_conn_destroy(navl_handle_t handle, navl_conn_t conn);

/*******************************************************************************
 * Protocol/Index Management
 ******************************************************************************/

/*
 * navl_proto_max_index()
 *
 * Returns the max protocol index.
 */
int navl_proto_max_index(navl_handle_t handle);

/*
 * navl_proto_set_index()
 *
 * Set the GUID protocol string @name to the value @index.
 *
 * On success, returns 0. On error, returns -1.
 */
int navl_proto_set_index(navl_handle_t handle, const char *name, int index);


/*******************************************************************************
 * Attribute Management
 ******************************************************************************/

/* Callback signature for navl attributes */ 
typedef void (*navl_attr_callback_t)(navl_handle_t, navl_conn_t conn, int attr_type, int attr_length, const void *attr_value
	, int attr_flag, void *);

/*
 * navl_attr_callback_set()
 *
 * Returns 0 on success or -1 if the attribute was not found.
 */
int navl_attr_callback_set(navl_handle_t handle, const char *attr, navl_attr_callback_t callback);

/*
 * navl_attr_key_get()
 *
 * Returns the attribute key on success or -1 on if the attribute was not found. 
 */
int navl_attr_key_get(navl_handle_t handle, const char *attr);


/*******************************************************************************
 * Configuration
 ******************************************************************************/

/*
 * navl_config_set()
 *
 * Directly set a configuration variable - use with caution!
 *
 * On success, returns 0. On error, returns -1.
 */
int navl_config_set(navl_handle_t handle, const char *key, const char *val);

/*
 * navl_config_get()
 *
 * Get a configuration variable.
 *
 * On success, returns 0. On error, returns -1.
 */
int navl_config_get(navl_handle_t handle, const char *key, char *val, int size);

/*
 * navl_config_dump()
 *
 * Dumps the entire configuration via navl_diag_printf.
 * On success, returns 0. On error, returns -1.
 *
 * Note in order to use this you must bind navl_diag_printf to a valid callback
 * function.
 */
int navl_config_dump(navl_handle_t handle);


/*******************************************************************************
 * Clock Manipulation
 ******************************************************************************/

/*
 * navl_clock_set_mode()
 *
 * Set and unset the clock mode:
 * 
 * 0 = auto, navl will use the system clock via the external function
 * navl_gettimeofday(). This is the default setting.
 *
 * 1 = manual, navl will use the time from the value set by navl_clock_set().
 */
void navl_clock_set_mode(navl_handle_t handle, int value);

/*
 * navl_clock_set()
 *
 * Manually set the wallclock time.
 */
void navl_clock_set(navl_handle_t handle, int64_t msecs);


/*******************************************************************************
 * Custom Protocols and Rules
 ******************************************************************************/

/*
 * navl_proto_add()
 *
 * Create and register a custom protocol with the given string name @protoname 
 * and a requested protocol @index (or zero for auto-assign). 
 *
 * On success, returns protocol index. On error, returns -1.
 *
 * Note: 
 * If the requested @index is already in use, this will return an error.
 */
int navl_proto_add(navl_handle_t handle, const char *protoname, int index);

/*
 * navl_proto_remove()
 *
 * Removes a custom protocol with the given @protoname.
 *
 * On success, 0 is returned. On error, returns -1.
 */
int navl_proto_remove(navl_handle_t handle, const char *protoname);

/*
 * navl_rule_add()
 *
 * Bind a protocol to a rule. See navl api guide for details.
 *
 * On success, 0 is returned. On error, returns -1.
 */
int navl_rule_add(navl_handle_t handle, int index, const char *module, const char *rule);

/*
 * navl_rule_remove()
 *
 * Unbind a protocol from a rule.
 *
 * On success, 0 is returned. On error, returns -1.
 */
int navl_rule_remove(navl_handle_t handle, int index, const char *module, const char *rule);


/*******************************************************************************
 * Runtime Utility Functions
 ******************************************************************************/

/*
 * navl_error_get()
 *
 * Returns the current value of the thread/instance-specific error.
 */
int navl_error_get(navl_handle_t handle);

/*
 * navl_idle()
 *
 * Perform necessary maintenance on idle thread. This should be called at
 * least once per second if thread is not calling navl_classify().
 *
 */
void navl_idle(navl_handle_t handle);

/*
 * navl_handle_get()
 *
 * Returns the navl instance handle active on the current thread. This may
 * may be used inside external functions to determine the active instance.
 *
 * Returns 0 on a thread for which navl_init has not been called.
 */
navl_handle_t navl_handle_get(void);

/*
 * navl_diag()
 *
 * Write diagnostic information for a module via navl_diag_printf.
 *
 * On success, 0 is returned. On error, returns -1.
 */
int navl_diag(navl_handle_t handle, const char *module, const char *args);

/*
 * navl_memory_tag_get()
 *
 * Returns the current memory tags associated with this thread. The lower 16
 * bits contains a context (ctx) index/tag and the upper 16 bit contain an
 * object (obj) index/tag.
 */ 
int navl_memory_tag_get(navl_handle_t);

/*
 * navl_memory_ctx_num()
 *
 * Returns the number of memory context identifiers.
 */
int navl_memory_ctx_num(navl_handle_t);

/*
 * navl_memory_ctx_name()
 *
 * Converts a context index retrived by navl_memory_tag_get() into a readable
 * string.
 *
 * On success, 0 is returned. On error, returns -1.
 */
int navl_memory_ctx_name(navl_handle_t, int, char *, int);

/*
 * navl_memory_obj_num()
 *
 * Returns the number of memory object identifiers.
 */
int navl_memory_obj_num(navl_handle_t);

/*
 * navl_memory_obj_name()
 *
 * Converts an object index retrived by navl_memory_tag_get() into a readablei
 * string.
 *
 * On success, 0 is returned. On error, returns -1.
 */
int navl_memory_obj_name(navl_handle_t, int, char *, int);


/*******************************************************************************
 * End of API declarations
 *******************************************************************************/


/* 
 * The following section contains declarations of NAVL external functions. These
 * functions are required by NAVL but are not bound initially. You must bind these
 * function pointers to real functions either by using the included 
 * "bind_navl_externals" code fragment for your platform, or by specifying your own
 * function bindings.
 *
 * IMPORTANT: navl_open will fail if any of these functions are not set.
 */

#ifndef NAVL_LIBRARY

#include <stddef.h>

/* structure definitions */
typedef int64_t navl_time_t;

struct navl_timeval
{
	long int tv_sec;
	long int tv_usec;
};

struct navl_tm
{ 
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
	char *tm_zone;
	int tm_gmtoff;
};

/* memory allocation */
extern void *(*navl_malloc_local)(size_t size);
extern void (*navl_free_local)(void *ptr);
extern void *(*navl_malloc_shared)(size_t size);
extern void (*navl_free_shared)(void *ptr);

/* ctype */
extern int (*navl_islower)(int c);
extern int (*navl_isupper)(int c);
extern int (*navl_tolower)(int c);
extern int (*navl_toupper)(int c);
extern int (*navl_isalnum)(int c);
extern int (*navl_isspace)(int c);
extern int (*navl_isdigit)(int c);

/* string functions */
extern int (*navl_atoi)(const char *nptr);
extern void *(*navl_memcpy)(void *dest, const void *src, size_t n);
extern int (*navl_memcmp)(const void *s1, const void *s2, size_t n);
extern void *(*navl_memset)(void *s, int c, size_t n);
extern int (*navl_strcasecmp)(const char *s1, const char *s2);
extern const char *(*navl_strchr)(const char *s, int c);
extern const char *(*navl_strrchr)(const char *s, int c);
extern int (*navl_strcmp)(const char *s1, const char *s2);
extern int (*navl_strncmp)(const char *s1, const char *s2, size_t n);
extern char *(*navl_strcpy)(char *dest, const char *src);
extern char *(*navl_strncpy)(char *dest, const char *src, size_t n);
extern char *(*navl_strerror)(int errnum);
extern size_t (*navl_strftime)(char *s, size_t max, const char *format, const struct navl_tm *tm);
extern size_t (*navl_strlen)(const char *s);
extern const char *(*navl_strpbrk)(const char *s, const char *accept);
extern const char *(*navl_strstr)(const char *haystack, const char *needle);
extern long int (*navl_strtol)(const char *nptr, char **endptr, int base);

/* input/output */
extern int (*navl_printf)(const char *format, ...);
extern int (*navl_sprintf)(char *str, const char *format, ...);
extern int (*navl_snprintf)(char *str, size_t size, const char *format, ...);
extern int (*navl_sscanf)(const char *str, const char *format, ...);
extern int (*navl_putchar)(int c);
extern int (*navl_puts)(const char *s);
extern int (*navl_diag_printf)(const char *format, ...);

/* time */
extern int (*navl_gettimeofday)(struct navl_timeval *tv, void *tz);
extern navl_time_t (*navl_mktime)(struct navl_tm *tm);

/* math */
extern double (*navl_log)(double x);
extern double (*navl_fabs)(double x);

/* system */
extern void (*navl_abort)(void);
extern unsigned long (*navl_get_thread_id)(void);

/* navl specific */
extern int (*navl_log_message)(const char *level, const char *func, const char *format, ... );

#endif /* NAVL_LIBRARY */

#ifdef __cplusplus
}
#endif

#endif /* NAVL_H */
