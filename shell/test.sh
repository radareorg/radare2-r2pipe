#!/bin/sh

#r=r2cmd
#. r2pipe.sh
R=./r2cmd

echo "Running analysis..."
$R aaa
echo "Disassembling code..."

$R "pd 3"
$R "px 32"
$R "pd 3"
$R "px 32"
pd3=`$R "pd 3"`
pxs=`$R "px 64"`

echo "$pd3"
echo "$pxs"

exit 0
