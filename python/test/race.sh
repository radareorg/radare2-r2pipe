#!/bin/sh

fail() {
	echo "ERROR"
	exit 1
}

C=0
while : ; do
	PYTHONPATH=${PWD}/.. python race.py /bin/ls | grep FAIL
	[ $? = 0 ] && fail
	printf "... $C\r"
	C=$(($C+1))
	[ "$C" = 32 ] && break
done
echo "PASS"
exit 0
