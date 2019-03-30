% -*- Mode: Prolog -*-
:- module(r2pipe, []).
:- use_module(library(unix)).
:- use_module(library(process)).
:- use_module(library(http/json)).

read_result(Out, Json) :-
	read_string(Out, "", "", _, String),
	atom_json_dict(String, Json, []).

send_command(R, Command, Json) :-
	write(R.in, Command),
	nl(R.in),
	flush_output(R.in),
	read_result(R.out, Json).

% create structure with pid and in/out pipes
open_file(File, R) :-
	process_create(path(radare2),
		% r2 -2 -q0 file
		["-2", "-q0", file(File)],
		[stdin(pipe(In)),
		stdout(pipe(Out)),
		process(Pid)]),
	dict_create(R, r2instance, [pid:Pid,in:In,out:Out]).

% TODO: Make more graceful exit
close_instance(R) :-
	close(R.in),
	close(R.out),
	process_kill(R.pid).

with_command(File, Command, O) :-
	open_file(File, R),
	send_command(R, Command, O),
	close_instance(R).

