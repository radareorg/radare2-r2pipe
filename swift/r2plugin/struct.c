// #import <r_core.h>
#include "r2.h" // to be replaced with r_core.h when -Xcc -I works

R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &swift_plugin,
	.version = R2_VERSION
};
