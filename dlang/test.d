import std.stdio;
import r2pipe;

void main() {
	auto r2 = r2pipe.open ();
	writeln ("Hello "~ r2.cmd("?e World"));
	writeln ("Hello "~ r2.cmd("?e Works"));

	string uri = r2.cmdj("ij")["core"]["uri"].str;
	writeln ("Uri: ",uri);
}
