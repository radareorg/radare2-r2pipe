-module(r2pipe_handler).

%% standard port handler interface

-export([start/1, stop/0, init/1, call/1]).

start(R2Path) ->
    spawn(?MODULE, init, [R2Path]).
stop() ->
    r2pipe_handler ! stop.

init_port(lpipe) ->	
	open_port({fd, list_to_integer(os:getenv("R2PIPE_IN")), list_to_integer(os:getenv("R2PIPE_OUT"))}, [stream, binary]);
init_port(R2Path) ->
	open_port({spawn, R2Path}, [stream, binary]).

init(Mode) ->
    register(r2pipe_handler, self()),
    process_flag(trap_exit, true),
    Port = init_port(Mode),
    loop(Port).

call(Msg) ->
    r2pipe_handler ! {call, self(), Msg},
    receive
		{r2pipe_handler, Result} ->
	    	Result
    end.

%% TODO: Dirty code: timeout should be externally configurable
get_timeout() -> 
	10000.

loop(Port) ->
    receive
   	{Port, {data, _Data}} ->
   		%% data without query, do nothing
   		loop(Port);
	{call, Caller, Msg} ->
		Port ! {self(), {command, Msg}},
	    receive
		{Port, {data, Data}} ->
		    Caller ! {r2pipe_handler, {ok, Data}}
		after get_timeout() ->
			Caller ! {r2pipe_handler, {fail, expired}}
	    end,
	    loop(Port);
	stop ->
	    Port ! {self(), close},
	    receive
		{Port, closed} ->
		    exit(normal)
	    end;
	{'EXIT', Port, _Reason} ->
	    exit(port_terminated)
    end.

