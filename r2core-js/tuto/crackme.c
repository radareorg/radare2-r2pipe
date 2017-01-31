#include <stdio.h>

main() {
char buf[32];
	printf ("Password: ");
	fflush (stdout);
	buf[0] = 0;
	fgets (buf, 32, stdin);
	if (!strcmp (buf, "th3p4ss") ) {
		printf ("Password Correct!\n");
		return 0;
	} else {
		printf ("Invalid Password\n");
		return 1;
	}
}
