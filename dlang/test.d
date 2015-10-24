import std.stdio;
import r2pipe;

void main() {
       auto r2 = r2pipe.open ();
       writeln ("Hello "~ r2.cmd("?e World"));
       writeln ("Hello "~ r2.cmd("?e Works"));
       string file = r2.cmdj("ij")["core"]["file"].str;
       writeln ("File: ", file);
}
