e asm.arch=x86
e asm.bits=32
wx 43 b940000000 ba0c000000 31c040404040cd80cc
w Hello World @ 0x40
"e cmd.esil.intr=#!pipe node int.js"
aei
pd 10
10aes
ae*
