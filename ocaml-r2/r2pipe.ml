(* 
 * R2PIPE 
 *
 * This module provides an API to interact with the radare2
 * commandline interface from OCaml using a pipe.
 *
 *)

type ctx =
  | Local of in_channel * out_channel * in_channel
  | Remote of string (* For Future *)

let bytes_startswith s sub =
  let slen, sublen = (String.length s, String.length sub) in
  if sublen>slen then false
  else if String.sub s 0 sublen = sub then true
  else false
                                  
let ropen f =
  if bytes_startswith f "http://" = false
  then let cmd_str = Printf.sprintf "r2 -q0 %s" f in (* -q0 : be quite and print zero *)
       let (cout, cin, cerr) = Unix.open_process_full cmd_str [| |] in
       let _ = input_byte cout in (* Read first 0x00 byte after the radare2 init *)
       Some(Local(cout, cin, cerr))
  else None (* Currently, we only support Local PIPE *)

let takeUntil cha ch =
  let flag = ref true in
  let idx = ref 0 in
  let output = Buffer.create 1 in
  let () = while !flag <> false do
             let b = input_char cha in
             if b = ch then flag := false
             else Buffer.add_char output b ; idx := !idx+1
           done
  in
  Buffer.sub output 0 (!idx-1)

let cmd ctx c =
  match ctx with
  | Local (cout, cin, cerr) -> 
     let cmd_str = Printf.sprintf "%s\n" c in
     let () = output_string cin cmd_str in
     let () = flush_all () in
     takeUntil cout '\x00'
  | _ -> ""

let cmdj ctx c = 
  Yojson.Safe.from_string (cmd ctx c)

(* ------------ UNIT TEST -------------- *)
(*
let opt_get = function
  | Some x -> x
  | None -> raise (Invalid_argument "Opt_get")
                  
let () =
  let ctx = opt_get (ropen "/bin/ls") in
  let output = cmd ctx "pd 2" in
  let () = print_endline output in
  let output = cmdj ctx "pdj 2" in
  print_endline (Yojson.Safe.pretty_to_string output)
 *)
