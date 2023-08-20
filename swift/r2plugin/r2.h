extern int r2swift_cmd(void *core, const char *cmd);
typedef struct r_lib_struct_t {
	int type;
	void *data; /* pointer to data handled by plugin handler */
	const char *version; /* r2 version */
	void (*free)(void *data);
	const char *pkgname; /* pkgname associated to this plugin */
} RLibStruct;
typedef enum r_plugin_status_t {
	R_PLUGIN_STATUS_BROKEN = 0,
	R_PLUGIN_STATUS_INCOMPLETE = 1,
	R_PLUGIN_STATUS_BASIC = 2,
	R_PLUGIN_STATUS_OK = 3,
	R_PLUGIN_STATUS_GOOD= 4,
	R_PLUGIN_STATUS_COMPLETE = 5,
} RPluginStatus;
typedef struct r_plugin_meta_t {
	char *name;
	char *desc;
	char *author;
	char *version;
	char *license;
	RPluginStatus status;
} RPluginMeta;

typedef int (*RCmdCb) (void *user, const char *input);
typedef struct r_core_plugin_t {
	RPluginMeta meta;
	RCmdCb call; // returns true if command was handled, false otherwise.
	RCmdCb init;
	RCmdCb fini;
} RCorePlugin;

// PLUGIN Definition Info
RCorePlugin swift_plugin = {
	.meta = {
		.name = "a2f",
		.desc = "The reworked analysis from scratch thing",
		.license = "LGPL3",
	},
	.call = r2swift_cmd,
};

#define R2_VERSION "5.8.9"
#define R_LIB_TYPE_CORE 13
#define R_API __attribute__((__visibility__("default")))

