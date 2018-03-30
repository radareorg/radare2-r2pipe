type r2 =
  {pid : int; read_from : Unix.file_descr; write_to : Unix.file_descr}

exception Stop_read

let read_result read_from =
  let b = Buffer.create 1 in
  let buf = Bytes.create 1 in
  begin
    try
      while true do
        Unix.read read_from buf 0 1 |> ignore;
        if buf = "\x00" then raise Stop_read
        else Buffer.add_bytes b buf
      done
    with Stop_read -> ()
  end;
  Buffer.to_bytes b

let send_command {write_to; read_from; _} cmd =
  let c = Printf.sprintf "%s\n" cmd in
  ignore (Unix.write_substring write_to c 0 (String.length c));
  read_result read_from |> String.trim

let command ~r2 cmd = send_command r2 cmd

let command_json ~r2 cmd =
  try
    send_command r2 cmd |> Yojson.Basic.from_string
  with
    Yojson.Json_error _ ->
    raise (Invalid_argument "Output wasn't JSON parsable, \
                             make sure you used /j")

let open_file f_name =
  if not (Sys.file_exists f_name) then
    raise (Invalid_argument "Non-existent file")
  else
    let (ins_r, ins_w),
        (out_r, out_w),
        (_, err_w) = Unix.(pipe (), pipe (), pipe ())
    in
    let args = [|"r2"; "-2"; "-q0"; f_name|] in
    let pid = Unix.create_process "r2" args ins_r out_w err_w in
    (* Get rid of the beginning \x00 *)
    ignore (Unix.read out_r (Bytes.create 1) 0 1);
    {pid; read_from = out_r; write_to = ins_w}

(* Heavy handed but we ensure that r2 is killed *)
let close {pid; _} =
  Unix.kill pid Sys.sigkill;
  Unix.waitpid [] pid |> ignore;
  ()

let with_command ~cmd f_name =
  let r2 = open_file f_name in
  let output = command ~r2 cmd in
  close r2;
  output

let with_command_j ~cmd f_name =
  let r2 = open_file f_name in
  let output = command ~r2 cmd in
  close r2;
  output |> Yojson.Basic.from_string
