#include "r2pipe.h"

static QTextStream& cout() {
    static QTextStream ts(stdout);
    return ts;
}

int main() {
	R2Pipe *r2;
	try {
		r2 = new R2Pipe();
	} catch (QString err) {
		cout() << err << "\n";
		r2 = new R2Pipe("/bin/ls");
	}
	cout() << r2->cmd ("?e hello world");
	cout() << r2->cmd ("x");
	cout() << r2->cmd ("pd 3");
	r2->close();
	return 0;
}
