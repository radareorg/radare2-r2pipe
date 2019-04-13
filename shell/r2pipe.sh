#!/bin/sh

if [ -z "${R2PIPE_IN}" ]; then
	echo 'r2 -i test.sh -qcq /bin/ls'
	exit 1
fi

r2cmd() {
        if [ -z "${R2PIPE_IN}" ]; then
                echo "No r2pipe environment found" >&2
                exit 1
        fi
        printf "$1\x00" >&${R2PIPE_OUT}
        while : ; do
                A=""
                read -t 1 A <&${R2PIPE_IN}
                [ -z "$A" ] && break
                echo "$A"
        done
}
