#ifndef NAVL_H
#define NAVL_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	NAVL_STATE_INSPECTING = 0,	/* Indicates the connection is under inspection */
	NAVL_STATE_CLASSIFIED = 1,	/* Indicates the connection is fully classified */
	NAVL_STATE_TERMINATED = 2	/* Indicates the connection has been terminated */
} navl_state_t;




typedef void *navl_iterator_t;
typedef void *navl_result_t;

/* Returns the application id for the result */
int navl_app_get(navl_result_t result, int *confidence);

/* Returns the first iterator in the result */
navl_iterator_t navl_proto_first(navl_result_t);

/* Returns 1 if the iterator is valid */
int navl_proto_valid(navl_iterator_t);

/* Returns the next iterator */
navl_iterator_t navl_proto_next(navl_iterator_t);

/* Returns the prev iterator */
navl_iterator_t navl_proto_prev(navl_iterator_t);

/* Returns an iterator pointing to the top most protocol */
navl_iterator_t navl_proto_top(navl_result_t);

/* Returns an iterator pointing to the protocol @id */
navl_iterator_t navl_proto_find(navl_result_t result, int id);

/* Extracts the protocol from the iterator */
int navl_proto_get_id(navl_iterator_t);

/* Extracts the protocol from the short name */
int navl_proto_find_id(const char *name);

/* Returns a pointer to the proto name */
const char *navl_proto_get_name(int id, char *buf, unsigned int size);

/* 
 * Enable (non-zero) or disable (zero) tracking of the attribute @attr.
 * Returns the attribute key on success or -1 on if the attribute was not found.
 */ 
int navl_attr(const char *attr, int enable);

/* Returns 0 and stores the attribute requested by @attr in @value or -1 on error */
int navl_attr_get(navl_iterator_t it, int attr, void *value, unsigned int value_size);

/* Callback signature for navl_classify */
typedef int (*navl_callback_t)(navl_result_t, navl_state_t state, void *arg, int error);

/* Open the library with @num_conns referencing the plugin directory @plugins */
int navl_open(unsigned int num_conns, unsigned int num_threads, const char *plugins);

/* Close the library */
void navl_close(void);

/* Refresh the plugin directory. Newly added plugins will be loaded */
int navl_refresh(void);

/* Returns the max protocol id */
int navl_proto_max_id(void);

/* Set the GUID protocol string @name to the value @id. Returns 0 on success, -1 on error. */
int navl_proto_set_id(const char *name, unsigned int id);

/* Simple classification API. */
int navl_classify_simple(const void *data, unsigned short len, unsigned int *id);

/* Normal packet based classification API */
int navl_classify(const void *data, unsigned short len, navl_callback_t, void *arg);

/* Stream API */
int	navl_conn_classify(unsigned int src_addr, unsigned short src_port, unsigned int dst_addr
	, unsigned short dst_port, unsigned char ip_proto, void *conn, const void *data, unsigned short len
	, navl_callback_t callback, void *arg);

/* 
 * Create a connection for the 5 tuple
 *
 * Returns 0 on success or -1 if resources cannot be allocated. 
 *
 * NOTE:
 *
 * This API supports an optional @conn param which can be supplied to navl_conn_classify()
 * as an optimization.
 *
 * Before using this API the caller must disable connection management. It is also expected
 * that each call to navl_conn_init() be paired with navl_conn_fini() on completion.
 *
 */
int navl_conn_init(unsigned int src_addr, unsigned short src_port, unsigned int dst_addr
	, unsigned short dst_port, unsigned char ip_proto, void **conn);

/* Releases the connection associated with the 5 tuple. Returns 0 on success, -1 on error. */
int navl_conn_fini(unsigned int src_addr, unsigned short src_port, unsigned int dst_addr
	, unsigned short dst_port, unsigned char ip_proto);

/*
 * Initialize a connection (previously created with navl_classify_init()) with the initial 
 * tcp sequence numbers. This is a necessary step when callers want to send only select tcp
 * packets (typically those with payload) through navl.
 *
 * Returns 0 on success and -1 on error. 
 *
 * NOTE: This can only fail in 2 cases both of which point to invalid use of the API.
 *
 * 	1.) The tcp connection hasn't been created.
 * 	2.) Data has already been seen on this connection.
 */
int navl_conn_tcp_seq_init(unsigned int src_addr, unsigned short src_port, unsigned int dst_addr
	, unsigned short dst_port, unsigned char ip_proto
	, unsigned int initiator_isn, unsigned int recipient_isn);

/* API to execute an arbitrary command within the NAVL system */
int navl_command(const char *cmd, const char *params, char *buffer, int buf_size);

/* Enable (non-zero) or disable (zero) future flow detection */
int navl_future_flow(int enable);

/* Configure the default idle connection @timeout for the @ip_proto. Applies to tcp & udp. A @timeout
 * of 0 (zero) disables connection lifetime management.
 *
 * NOTE: This does not prevent connections for being torn down for legitimate reasons. For example
 * processing a reset flag will still cause the release of the connection.
 */
int navl_conn_idle_timeout(unsigned char ip_proto, unsigned int timeout);

/* Enable (non-zero) or disable (zero) ip defrag support */
int navl_ip_defrag(int enable);

/* Diagnostics */
int navl_diag(int fd);
void navl_backtrace(int fd);

/* Create and register a custom protocol with the given string name */
/* returns protocol index if successful or zero if error occurred */
int navl_create_protocol(const char *protoname);

/* Remove a custom protocol with the given string name */
/* returns 0 for success, or error code if error occurred */
int navl_delete_protocol(const char *protoname);

/* Bind a protocol to a rule - either ip info or module/key/value or both may be specified */
/* returns 0 for success, or error code if error occurred */
int navl_add_protocol_rule(int proto_id, const char *module, const char *rule);

/* Unbind a protocol from a rule */
/* returns 0 for success, or error code if error occurred */
int navl_remove_protocol_rule(int proto_id, const char *module, const char *rule);

/* set/unset manual clock mode - 0=auto, 1=manual */
void navl_set_clock_mode(int value);

/* manually set the wallclock time */
void navl_set_clock(unsigned long msecs);

#ifdef __cplusplus
}
#endif

#endif
