import 'dart:ffi' as ffi;
import 'dart:convert' show utf8;
/* doesnt exist

import "package:ffi/ffi.dart";

typedef RCoreCmdStrFunc = ffi.Pointer<Utf8> Function(ffi.Pointer, ffi.Pointer<Utf8>);
typedef RCoreCmdStr = String Function(ffi.Pointer, String);
*/

typedef RCoreNewFunc = ffi.Pointer Function();
typedef RCoreNew = ffi.Pointer Function();

typedef RCoreFreeFunc = ffi.Void Function(ffi.Pointer);
typedef RCoreFree = void Function(ffi.Pointer);


void main() {
   print('Hello Radare2 from Dart!');

   var libraryPath = '/usr/local/lib/libr_core.dylib';

   final dylib = ffi.DynamicLibrary.open(libraryPath);
   final RCoreNew r_core_new = dylib
	   .lookup<ffi.NativeFunction<RCoreNewFunc>>('r_core_new')
	   .asFunction();
   final RCoreFree r_core_free = dylib
	   .lookup<ffi.NativeFunction<RCoreFreeFunc>>('r_core_free')
	   .asFunction();
   // Call the function
   var a = r_core_new();
   /*
       final pathC = Utf8.toUtf8(path);
   final RCoreCmdStr r_core_cmd_str = dylib
	   .lookup<ffi.NativeFunction<RCoreCmdStrFunc>>('r_core_cmd_str')
	   .asFunction();

//    var cmd = utf8.encode("?E Hello");
 //  var r = r_core_cmd_str (a, cmd);
 */
   print(a);
   r_core_free (a);
   // r_core_cmd();
}
