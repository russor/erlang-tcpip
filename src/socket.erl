%%%-------------------------------------------------------------------
%%% File    : socket.erl
%%% Author  : Javier Paris Fernandez <javier.paris@udc.es>
%%% Description : Socket interface for Tcp/Ip
%%%
%%% Created : 14 Sep 2004 by Javier Paris Fernandez <javier.paris@udc.es>
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

-module(socket).

-export([start/0, start/2, start_ip/1, open/3, open/4, listen/1, accept/1, recv/2, send/2,
	 send/4, close/1, string_to_ip/1,
         set_sockopt/3]).

%%%%%%%%%%%%%%%%%%%%%%%%%% USER API %%%%%%%%%%%%%%%%%%%%%%%%%%

start() ->
    {ok, Iface} = application:get_env(etcpip, iface),
    % eth_port:start(Iface),
    init(true, eth_port, arp).

start(PhyModule, L2Module) ->
    init(true, PhyModule, L2Module).

start_ip(L2Module) ->
    init(false, unknown, L2Module).

open(tcp, Dst_Ip, Dst_Port) ->
    tcp_con:usr_open(Dst_Ip, Dst_Port).

open(udp, Lc_Port, Dst_Ip, Dst_Port) -> %% Udp
    udp:usr_open(Lc_Port, Dst_Ip, Dst_Port).

listen(Src_Port) ->
    tcp_con:usr_listen(Src_Port).

accept(ListenConn) ->
    tcp_con:usr_accept(ListenConn).

recv(Conn, Bytes) ->
    tcp_con:usr_recv(Conn, Bytes).

send(Conn, Data) ->
    tcp_con:usr_send(Conn, Data).

send(Src_Port, Dst_Ip, Dst_Port, Data) -> %% Udp
    udp:send(Dst_Ip, Dst_Port, Src_Port, Data).

close(Conn) ->
    tcp_con:usr_close(Conn).

string_to_ip(Ip) ->
    T = string:tokens(Ip, "."),
    lists:foldl(fun (N, Acc) -> {N2, _} = string:to_integer(N), Acc*256+N2 end, 0, T).

set_sockopt(Con, Option, Parameter) ->
    tcp_con:usr_sockopt(Con, Option, Parameter).
    
%%%%%%%%%%%%%%%%%%%%%%% INTERNAL FUNCTIONS %%%%%%%%%%%%%%%%%%

init(Full, PhyModule, L2Module) ->
    Terms = application:get_all_env(etcpip),
    {value, {ip, EIp}} = lists:keysearch(ip, 1, Terms),
    {value, {netmask, ENetMask}} = lists:keysearch(netmask, 1, Terms),
    {value, {gateway, EGateWay}} = lists:keysearch(gateway, 1, Terms),
    {value, {mac, EMac}} = lists:keysearch(mac, 1, Terms),
    
    Ip = map_ip(EIp),
    NetMask = map_ip(ENetMask),
    GateWay = map_ip(EGateWay),
    Mac = map_mac(EMac),

    case Full of
        true->
            eth:start(Mac, PhyModule),
            arp:start(Ip, Mac);
        _ -> ok
    end,
    checksum:start(),
    ip:start(Ip, NetMask, GateWay, L2Module),
    icmp:start(),
    udp:start(Ip),
    tcp_pool:start(Ip),
    iss:start(),
    tcp:start().

%% Stack is IPv4 only...
map_ip({A, B, C, D}) ->
    <<R:32>> = <<A, B, C, D>>,
    R.

map_mac(<<E:48>>) -> E.
