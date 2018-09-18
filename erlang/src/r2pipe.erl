-module(r2pipe).

-author(dark_k3y).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([init/1, init/2, init/3, cmd/2, cmdj/2, quit/0]).

init(pipe, File) ->
	init(pipe, File, "radare2").

init(pipe, File, R2Bin) ->
	Path =  R2Bin ++ " -q0 " ++ File,
	r2pipe_handler:start(Path),
	{pipe, r2pipe_handler}.

init(lpipe) ->
	r2pipe_handler:start(lpipe),
	timer:sleep(50), %% ugly sleep to let i/o initialize
	{pipe, r2pipe_handler}.

cmd({pipe, _}, Cmd) ->
	{ok, Data} = r2pipe_handler:call(prepare_cmd(Cmd)),
	binary_to_list(Data).

cmdj({pipe, _}, Cmd) ->
	{ok, Data} = r2pipe_handler:call(prepare_cmd(Cmd)),
	parse_json(Data).

quit() ->
	r2pipe_handler:stop().

prepare_cmd(Cmd) ->
	Cmd ++ [10].

parse_json(Res) when is_binary(Res) ->
	Size = (byte_size(Res) - 2 ) * 8,
	<<Bin:Size, _Temp/binary>> = Res,
	jsx:decode(<<Bin:Size>>).
