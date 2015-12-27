import r_core

let r = r_core.r_core_new()
r_core.r_core_cmd_str(r, "o /bin/ls");
if let str = String.fromCString(r_core.r_core_cmd_str(r, "pd 10")) {
	print (str);
}
