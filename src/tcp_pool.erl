%%%-------------------------------------------------------------------
%%% File    : tcp_pool.erl
%%% Author  : Javier Paris <javier.paris@udc.es>
%%% Description : Tcp Connection Pool
%%%
%%% Created : 13 Aug 2004 by Javier Paris <javier.paris@udc.es>
%%%
%%%
%%% erlang-tcpip, Copyright (C) 2004 Javier Paris
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%-------------------------------------------------------------------

-module(tcp_pool).

-export([start_link/1,init/1,get/1,add/2,remove/1, new_ip/1]).
-behavior(gen_server).
-export([handle_call/3]).

%%%%%%%%%%%%%%%%%%%%%%%%% API %%%%%%%%%%%%%%%%%%%%%

start_link(Ip) -> gen_server:start_link({local, ?MODULE}, ?MODULE, [Ip], []).

get(Socket) -> gen_server:call(?MODULE, {get, Socket}, infinity).

add({Type, Socket}, Conn) -> gen_server:call(?MODULE, {add, Type, Socket, Conn}, infinity).

remove(Socket) -> gen_server:call(?MODULE, {remove, Socket}).


%%%%%%%%%%%%%%%%%%%%% Server Loop %%%%%%%%%%%%%%%%%%

init(Ip) ->
    Table = ets:new(tcp_pool, [set, public, named_table]),
    {ok, {Table, Ip}}.

new_ip(Ip) -> gen_server:call(?MODULE, {new_ip, Ip}, infinity).

lookup(_Table, []) -> [];
lookup(Table, [Socket | T]) ->
    case catch (ets:lookup(Table, Socket)) of
        [] -> lookup(Table, T);
        Other -> Other
    end;
lookup(Table, Socket) -> lookup(Table, [Socket]).

handle_call({new_ip, NewIp}, _From, {Table, _Ip}) -> {reply, ok, {Table, NewIp}};

handle_call({get, Socket}, _From, {Table, _} = S) ->
    case lookup(Table, Socket) of
	[] -> {reply, {error, no_connection}, S};
	[{_, Conn}] -> {reply, {ok, Conn}, S}
    end;

handle_call({add, remote, R_Socket, Conn}, _From, {Table, Ip} = S) ->
    {Rt_Ip, Rt_Port} = R_Socket,
    Lc_Port = find_free_port(Table, Ip, Rt_Ip, Rt_Port),
    ets:insert(Table, {{Ip, Lc_Port, Rt_Ip, Rt_Port}, Conn}),
    {reply, {ok, Ip, Lc_Port}, S};

handle_call({add, local, {Lc_Addr, Lc_Port}, Conn}, _From, {Table, _} = S) ->
    case ets:insert_new(Table, {{Lc_Addr, Lc_Port}, Conn}) of
	true -> {reply, {ok, Lc_Addr, Lc_Port}, S};
	false -> {reply, {error, eaddrinuse}, S}
    end;

handle_call({add, connect, {Ip, Lc_Port, Rt_Ip, Rt_Port}, Conn}, _From, {Table, _} = S) ->
    ets:insert(Table, {{Ip, Lc_Port, Rt_Ip, Rt_Port}, Conn}),
    {reply, {ok, Ip, Lc_Port}, S};

handle_call({remove, Socket}, _From, {Table, _} = S) ->
    ets:delete(Table, Socket),
    {reply, ok, S}.

find_free_port(Table, Lc_Ip, Rt_Ip, Rt_Port) ->
    find_free_port_1(Table, Lc_Ip, Rt_Ip, Rt_Port, 1000).

find_free_port_1(Table, Lc_Ip, Rt_Ip, Rt_Port, N) ->
    case ets:member(Table, {Lc_Ip, N, Rt_Ip, Rt_Port}) of
	true ->
	    find_free_port_1(Table, Lc_Ip, Rt_Ip, Rt_Port, N+1);
	false ->
	    N
    end.
