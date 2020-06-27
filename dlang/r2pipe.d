module r2pipe;

import std.conv;
import std.json;
import std.stdio;
import std.string;
import std.process;
import core.sys.posix.unistd;

class R2Pipe {
       private alias sysread = core.sys.posix.unistd.read;
       private alias syswrite = core.sys.posix.unistd.write;

       private int fdIn;
       private int fdOut;

       this() {
               fdIn = to!int(environment["R2PIPE_IN"]);
               fdOut = to!int(environment["R2PIPE_OUT"]);
       }

       public string cmd(string c) {
               char[] cbuf = (c~"\n").dup;
               syswrite(fdOut, cast(void*)cbuf, cbuf.length);
               string res = "";
               while (true) {
                       byte[1] buf;
                       auto n = sysread(fdIn, &buf, 1);
                       if (buf[0] == '\0') {
                               break;
                       }
                       res ~= buf[0];
               }
               return res.chomp();
       }
       public JSONValue cmdj(string s) {
               return parseJSON(cmd(s));
       }
}

public static R2Pipe open() {
       return new R2Pipe();
}
