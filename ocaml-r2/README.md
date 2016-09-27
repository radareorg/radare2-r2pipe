# r2pipe for OCaml 

## usage

Open binary with r2

``` ocaml
utop # let ctx = unwrap (R2pipe.ropen "/bin/ls") ;;
val ctx : R2pipe.ctx = R2pipe.Local (<abstr>, <abstr>, <abstr>) 
```

Execute r2 command 

``` ocaml
utop # R2pipe.cmd ctx "pd 1";;
- : bytes =                                                                                                          "            ;-- entry0:\n            0x004049a0      31ed           xor ebp, ebp\n"   
```

Get JSON object 

``` ocaml
utop # R2pipe.cmdj ctx "pdj 5";;
- : Yojson.Safe.json =                                                                                               `List                                                                                                                  [`Assoc                                                                                                            
     [("offset", `Int 4213152); ("fcn_addr", `Int 0); ("fcn_last", `Int 0);
      ("size", `Int 2); ("opcode", `String "xor ebp, ebp");
      ("bytes", `String "31ed"); ("family", `String "cpu");
      ("type", `String "xor"); ("type_num", `Int 28); ("type2_num", `Int 0);
      ("flags", `List [`String "entry0"])];
   `Assoc
     [("offset", `Int 4213154); ("fcn_addr", `Int 0); ("fcn_last", `Int 0);
      ("size", `Int 3); ("opcode", `String "mov r9, rdx");
      ("bytes", `String "4989d1"); ("family", `String "cpu");
      ("type", `String "mov"); ("type_num", `Int 9); ("type2_num", `Int 0)];
   `Assoc
     [("offset", `Int 4213157); ("fcn_addr", `Int 0); ("fcn_last", `Int 0);
      ("size", `Int 1); ("opcode", `String "pop rsi"); ("bytes", `String "5e");
      ("family", `String "cpu"); ("type", `String "pop");
      ("type_num", `Int 14); ("type2_num", `Int 0)];
   `Assoc
     [("offset", `Int 4213158); ("fcn_addr", `Int 0); ("fcn_last", `Int 0);
      ("size", `Int 3); ("opcode", `String "mov rdx, rsp");
      ("bytes", `String "4889e2"); ("family", `String "cpu");
      ("type", `String "mov"); ("type_num", `Int 9); ("type2_num", `Int 0)];
   `Assoc
     [("offset", `Int 4213161); ("fcn_addr", `Int 0); ("fcn_last", `Int 0);
      ("size", `Int 4); ("opcode", `String "and rsp, 0xfffffffffffffff0");
      ("bytes", `String "4883e4f0"); ("family", `String "cpu");
      ("type", `String "and"); ("type_num", `Int 27); ("type2_num", `Int 0)]]


```
