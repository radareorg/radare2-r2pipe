#!/usr/bin/env escript
%% -*- erlang -*-
%%! -smp enable

%% -sname hr
-mode(compile).

-export([main/1]).    

main(_Args) ->
    %% adding r2pipe to modulepath, set it to your r2pipe_erl location
    R2pipePATH = filename:dirname(escript:script_name()) ++ "/ebin",
    true = code:add_pathz(R2pipePATH), 

    %% initializing the link with r2
    H = r2pipe:init(lpipe),    

    %% all work goes here
    io:format("~s", [r2pipe:cmd(H, "i")]).
    