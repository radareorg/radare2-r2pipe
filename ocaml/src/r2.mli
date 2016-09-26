(** Interact with radare2, ideal for utop interaction *)

(** A running instance of r2 *)
type r2

(** Send a command to r2, get back plain string output *)
val command : r2:r2 -> string -> string

(** Send a command to r2, get back Yojson. If output isn't JSON
    parsable then raises {Invalid_argument} so make sure command starts
    with /j *)
val command_json : r2:r2 -> string -> Yojson.Basic.json

(** Create a r2 instance with a given file, raises {Invalid_argument}
    if file doesn't exists *)
val open_file : string -> r2

(** close a r2 instance *)
val close : r2 -> unit

(** Convenience function for opening a r2 instance, sending a command,
    getting the result as plain string and closing the r2 instance *)
val with_command : cmd:string -> string -> string

(** Convenience function for opening a r2 instance, sending a command,
    getting the result as Yojson and closing the r2 instance *)
val with_command_j : cmd:string -> string -> Yojson.Basic.json
