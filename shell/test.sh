#!/bin/sh

#. r2pipe.sh
#R=./r2cmd
R=r2p

echo "Running analysis..."
$R aaa
echo "Disassembling code..."

$R pdj | jq .

exit 0

$R "pd 3"
$R "px 32"
$R "pd 3"
$R "px 32"
pd3=`$R "pd 3"`
pxs=`$R "px 64"`

echo "$pd3"
echo "$pxs"

exit 0
