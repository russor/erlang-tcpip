%%%-------------------------------------------------------------------
%%% File    : udp.erl
%%% Author  : Javier Paris Fernandez <javier.paris@udc.es>
%%% Description : Udp Protocol Support
%%%
%%% Created :  6 Aug 2004 by Javier Paris Fernandez <javier.paris@udc.es>
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

-module(udp).

-import(checksum,[checksum/1]).
-import(packet_check,[check_packet/4, compute_checksum/5]).
-export([start_link/0, init/1, recv/3, send/5, open/1, open/2, open/3]).
-export([handle_call/3, handle_cast/2, handle_info/2, new_ip/1]).
-behavior(gen_server).
-include("ip.hrl").
%%%%%%%%%%%%%%%%%%%% API %%%%%%%%%%%%%%%%%%%%%%%%%%%%

start_link() -> gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

recv(Src_Ip, Dst_Ip, Data) ->
    gen_server:cast(?MODULE, {recv, Src_Ip, Dst_Ip, Data}).

open(Lc_Port) -> gen_server:call(?MODULE, {open, Lc_Port, self()}, infinity).
open(Lc_Addr, Lc_Port) -> gen_server:call(?MODULE, {add, local, {Lc_Addr, Lc_Port}, self()}, infinity).
open(Lc_Port, Dst_Ip, Dst_Port) -> %% This will send incoming packets to Lc_Port from Dst_Ip, Dst_Port to the calling process as {udp, {Lc_Ip, Lc_Port, Dst_Ip, Dst_Port}, Data}
    gen_server:call(?MODULE, {open, Lc_Port, Dst_Ip, Dst_Port, self()}, infinity).



send(Src_Ip, SPort, Dst_Ip, DPort, Data) ->
    Len = size(Data) + 8,
    Pre_Checksum = <<SPort:16/big-integer,
		    DPort:16/big-integer,
		    Len:16/big-integer>>,
    Packet = <<Pre_Checksum/binary,
	      0:16/big-integer,
	      Data/binary>>,
    Checksum = compute_checksum(Src_Ip, Dst_Ip, ?IP_PROTO_UDP, Packet, size(Packet)),
    Checksum_Packet = <<Pre_Checksum/binary,
		      Checksum:16/big-integer,
		      Data/binary>>,
    ip:send(Checksum_Packet, size(Checksum_Packet), udp, Src_Ip, Dst_Ip).

new_ip(Ip) -> gen_server:call(?MODULE, {new_ip, Ip}, infinity).


%%%%%%%%%%%%%% Reader Loop %%%%%%%%%%%%%%

init([]) ->
    Table = ets:new(?MODULE, []),
    {ok, {Table, 0}}.

handle_call({new_ip, NewIp}, _From, {Table, _Ip}) -> {reply, ok, {Table, NewIp}};
handle_call({open, Lc_Port, Pid}, From, S) -> handle_call({add, local, {0, Lc_Port}, Pid}, From, S);

handle_call({add, local, {0, Lc_Port}, Conn}, From, {_, Lc_Addr} = S) when Lc_Addr /= 0 -> handle_call({add, local, {Lc_Addr, Lc_Port}, Conn}, From, S);
handle_call({add, local, {Lc_Addr, 0}, Conn}, From, S) -> handle_call({add, local, {Lc_Addr, 0, 65535}, Conn}, From, S);
handle_call({add, local, {Lc_Addr, Lc_Port}, Conn}, From, S) -> handle_call({add, local, {Lc_Addr, Lc_Port, 1}, Conn}, From, S);
handle_call({add, local, {Lc_Addr, 0, Tries}, Conn}, From, S) -> handle_call({add, local, {Lc_Addr, 1, Tries}, Conn}, From, S);
handle_call({add, local, {_Lc_Addr, _Lc_Port, 0}, _Conn}, _From, S) -> {reply, {error, eaddrinuse}, S};

handle_call({add, local, {Lc_Addr, Lc_Port, Tries}, Conn}, From, {Table, _} = S) ->
    Key = {Lc_Addr, Lc_Port},
    case ets:insert_new(Table, {Key, Conn}) of
	true ->
	    Ref = monitor(process, Conn),
	    true = ets:insert_new(Table, {Ref, Key}),
	    {reply, {ok, Lc_Addr, Lc_Port}, S};
	false -> handle_call({add, local, {Lc_Addr, Lc_Port + 1, Tries - 1}, Conn}, From, S)
    end;

handle_call({open, Lc_Port, Dst_Ip, Dst_Port, Pid}, _From, {Table, _} = S) ->
    {reply, open_impl(Table, {Lc_Port, Dst_Ip, Dst_Port}, Pid), S}.

open_impl(Table, Key, Pid) ->
    Ref = monitor(process, Pid),
    case ets:insert_new(Table, {Key, Pid}) of
        true ->
            true = ets:insert_new(Table, {Ref, Key}),
            ok;
        false ->
            demonitor(Ref),
            {error, addrinuse}
    end.

handle_cast({recv, Src_Ip, Loc_Ip, Packet}, {Table, _} = S) ->
    case catch decode(Src_Ip, Loc_Ip, Packet) of
	{ok, Src_Ip, Loc_Ip, Src_Port, Loc_Port, Data} ->
	    case ets:lookup(Table, {Loc_Port, Src_Ip, Src_Port}) of
	        [{_Key, Pid}] -> Pid ! {udp, {Loc_Ip, Loc_Port, Src_Ip, Src_Port}, Data};
	        [] -> case ets:lookup(Table, {Loc_Ip, Loc_Port}) of
	            [{_Key, Pid}] -> Pid ! {udp, {Loc_Ip, Loc_Port, Src_Ip, Src_Port}, Data};
	            [] -> case ets:lookup(Table, {0, Loc_Port}) of
	                [{_Key, Pid}] -> Pid ! {udp, {Loc_Ip, Loc_Port, Src_Ip, Src_Port}, Data};
	                [] -> ok
	            end
	        end
	    end;
	{error, _Error} -> ok
     end,
     {noreply, S}.

handle_info({'DOWN', Ref, _Type, _Pid, _Info}, {Table, _} = S) ->
    case ets:lookup(Table, Ref) of
        [{Ref, Key}] ->
            true = ets:delete(Table, Ref),
            true = ets:delete(Table, Key);
        [] -> ok
    end,
    {noreply, S}.

%%%%%%%%%%%%%% Reader Help Functions %%%%%%%%%%%%%%%%%%

decode(Src_Ip, Dst_Ip, Packet) when is_binary(Packet) ->
    case check_packet(Src_Ip, Dst_Ip, ?IP_PROTO_UDP, Packet) of
	ok ->
	    <<Src_Port:16/big-integer,
	     Dst_Port:16/big-integer,
	     _Len:16/big-integer,
	     _:16/big-integer,
	     Data/binary>> = Packet,
	    {ok, Src_Ip, Dst_Ip, Src_Port, Dst_Port, Data}; % Should check length?
	{error, Error} ->
	    {error, Error}
    end.

