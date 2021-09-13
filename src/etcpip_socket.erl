%%%-------------------------------------------------------------------
%%% File    : etcpip_socket.erl
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

-module(etcpip_socket).

-export([start/0, start/2, start_ip/1, open/2, open/3, open/4, listen/1, accept/1, accept/2, recv/2, send/2,
	 send/4, close/1, bind/2, string_to_ip/1, new_ip/3, setopt/3, map_ip/1, listen/2]).

%%%%%%%%%%%%%%%%%%%%%%%%%% USER API %%%%%%%%%%%%%%%%%%%%%%%%%%

start() -> init(true, eth_port, arp).

start(PhyModule, L2Module) ->
    init(true, PhyModule, L2Module).

start_ip(L2Module) ->
    init(false, unknown, L2Module).

open(tcp, Options) -> tcb:start(new, Options).

open(tcp, Dst_Ip, Dst_Port) ->
    tcp_con:usr_open(Dst_Ip, Dst_Port).

open(udp, Lc_Port, Dst_Ip, Dst_Port) -> %% Udp
    udp:usr_open(Lc_Port, Dst_Ip, Dst_Port).

listen(Src_Port) -> tcb:start(listen, Src_Port).

accept(ListenConn) -> accept(ListenConn, infinity).
accept(ListenConn, Timeout) -> gen_server:call(ListenConn, {accept, Timeout}, infinity).

recv(Conn, Bytes) -> gen_server:call(Conn, {read, Bytes}, infinity).

send(Conn, Data) -> gen_server:call(Conn, {queue, Data}, infinity).

send(Src_Port, Dst_Ip, Dst_Port, Data) -> %% Udp
    udp:send(Dst_Ip, Dst_Port, Src_Port, Data).

close(Conn) -> gen_server:call(Conn, close, infinity).

bind(Conn, Addr) -> gen_server:call(Conn, {bind, Addr}, infinity).

listen(Conn, Backlog) -> gen_server:call(Conn, {listen, Backlog}, infinity).

string_to_ip(Ip) ->
    T = string:tokens(Ip, "."),
    lists:foldl(fun (N, Acc) -> {N2, _} = string:to_integer(N), Acc*256+N2 end, 0, T).

setopt(Con, Option, Parameter) -> gen_server:call(Con, {setopt, Option, Parameter}, infinity).
    
%%%%%%%%%%%%%%%%%%%%%%% INTERNAL FUNCTIONS %%%%%%%%%%%%%%%%%%

init(Full, _PhyModule, L2Module) ->
    Terms = application:get_all_env(etcpip),
    {value, {iface, Iface}} = lists:keysearch(iface, 1, Terms),
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
            eth_port:start_reader(Iface),
            eth_port:start_writer(),
            eth:start_reader(Mac),
            eth:start_writer(Mac),
            arp:start(Ip, Mac);
        _ -> ok
    end,
    checksum:start(),
    ip:start(Ip, NetMask, GateWay, L2Module),
    icmp:start(),
    udp:start_link(),
    tcp_pool:start(Ip),
    tcp:start().

new_ip(Ip, NetMask, GateWay) ->
    arp:new_ip(Ip),
    ip:new_ip(Ip, NetMask, GateWay),
    tcp_pool:new_ip(Ip).

%% Stack is IPv4 only...
map_ip({A, B, C, D}) ->
    <<R:32>> = <<A, B, C, D>>,
    R.

map_mac(<<E:48>>) -> E.
