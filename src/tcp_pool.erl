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

handle_call({add, local, {Lc_Addr, 0}, Conn}, From, S) -> handle_call({add, local, {Lc_Addr, 0, 65535}, Conn}, From, S);
handle_call({add, local, {Lc_Addr, Lc_Port}, Conn}, From, S) -> handle_call({add, local, {Lc_Addr, Lc_Port, 1}, Conn}, From, S);
handle_call({add, local, {Lc_Addr, 0, Tries}, Conn}, From, S) -> handle_call({add, local, {Lc_Addr, 1, Tries}, Conn}, From, S);
handle_call({add, local, {_Lc_Addr, _Lc_Port, 0}, _Conn}, _From, S) -> {reply, {error, eaddrinuse}, S};

handle_call({add, local, {Lc_Addr, Lc_Port, Tries}, Conn}, From, {Table, _} = S) ->
    case ets:insert_new(Table, {{Lc_Addr, Lc_Port}, Conn}) of
        true -> {reply, {ok, Lc_Addr, Lc_Port}, S};
        false -> handle_call({add, local, {Lc_Addr, (Lc_Port + 1) band 16#FFFF, Tries - 1}, Conn}, From, S)
    end;

handle_call({add, connect, {0, Lc_Port, Rt_Ip, Rt_Port}, Conn}, From, {_Table, Ip} = S) -> handle_call({add, connect, {Ip, Lc_Port, Rt_Ip, Rt_Port}, Conn}, From, S);
handle_call({add, connect, {Lc_Ip, 0, Rt_Ip, Rt_Port}, Conn}, From, S) -> handle_call({add, connect, {Lc_Ip, 0, Rt_Ip, Rt_Port, 65535}, Conn}, From, S);
handle_call({add, connect, {Lc_Ip, Lc_Port, Rt_Ip, Rt_Port}, Conn}, From, S) -> handle_call({add, connect, {Lc_Ip, Lc_Port, Rt_Ip, Rt_Port, 1}, Conn}, From, S);
handle_call({add, connect, {Lc_Ip, 0, Rt_Ip, Rt_Port, Tries}, Conn}, From, S) -> handle_call({add, connect, {Lc_Ip, 1, Rt_Ip, Rt_Port, Tries}, Conn}, From, S);
handle_call({add, connect, {_Lc_Ip, _Lc_Port, _Rt_Ip, _Rt_Port, 0}, _Conn}, _From, S) -> {reply, {error, eaddrinuse}, S};

handle_call({add, connect, {Lc_Ip, Lc_Port, Rt_Ip, Rt_Port, Tries}, Conn}, From, {Table, _} = S) ->
    case ets:insert_new(Table, {{Lc_Ip, Lc_Port, Rt_Ip, Rt_Port}, Conn}) of
        true -> {reply, {ok, Lc_Ip, Lc_Port}, S};
        false -> handle_call({add, connect, {Lc_Ip, (Lc_Port + 1) band 16#FFFF, Rt_Ip, Rt_Port, Tries - 1}, Conn}, From, S)
    end;

handle_call({remove, Socket}, _From, {Table, _} = S) ->
    ets:delete(Table, Socket),
    {reply, ok, S}.
