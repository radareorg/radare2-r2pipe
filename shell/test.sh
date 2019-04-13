#!/bin/sh
. r2pipe.sh
echo "Running analysis..."
r2cmd aaa
echo "Disassembling code..."
pd3=`r2cmd "pd 3"`
pxs=`r2cmd "px 64"`

echo "$pd3"
echo "$pxs"

exit 0
