library r2pipe.js;

import 'dart:convert';
import 'dart:js' as js;

String r2cmd(String cmd) {
	return js.context.callMethod ("r2cmd", [cmd]);
}
dynamic r2cmdj(String cmd) {
	return jsonDecode(r2cmd(cmd));
}
void main() {
	print("Hello Radare2" + r2cmd("pd 10"));
	print("FileName: " + r2cmdj("ij")["core"]["file"]);
}

/*
import 'package:js/js.dart';
// import 'dart:js' as js;

// external JsAny r2; // 
@JS('r2cmd')
external String r2cmd(String input);

@JS('r2')
abstract class r2 {
	external static String cmd(String);
	external static Object cmdj(String);
}

void main() {
	// final js.JsFunction r2cmd = js.context['r2cmd'];
	print("Hello Radare2" + r2.cmd("x"));
	// print("Hello Radare2" + r2cmd("x"));
	// print("Hello Radare2" + js.context.callMethod("r2cmd", ["x"]));
	// print("Hello Radare2" + js.context.callMethod(r2cmd, ["x"])); // r2cmd("x")); // js.context.callMethod('r2.cmd', ["x"]));
}
*/
