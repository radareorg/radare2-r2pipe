<?php
/* r2pipe.php PoC by pancake @ 2016 */

$cwd = '.';
$descs = array(
	0 => array("pipe", "r"),  // stdin
	1 => array("pipe", "w"),  // stdout
	2 => array("pipe", "w")   // stderr
);
$proc = proc_open("radare2 -q0 /bin/ls", $descs, $pipes);
if (is_resource($proc)) {
	 $msg = fread($pipes[1], 1);
}

function r2cmd($cmd) {
	global $pipes;
	$rc = fwrite($pipes[0], "$cmd\n");
	return trim(fread($pipes[1], 4096));
}

function r2cmdj($cmd) {
	return json_decode (r2cmd ($cmd), true);
}

print_r(r2cmdj("ij"));
print(r2cmd("?V"));
print(r2cmd("pd 10"));

$return_value = proc_close($proc);

?>
