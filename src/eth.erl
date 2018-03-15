%%%-------------------------------------------------------------------
%%% File    : eth.erl
%%% Author  : Javier Paris Fernandez <javier.paris@udc.es>
%%% Description : Ethernet Link Layer
%%%
%%% Created :  2 Aug 2004 by Javier Paris Fernandez <javier.paris@udc.es>
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
-module(eth).

% API
-export([start_reader/1, start_writer/1, send/3, recv/1, get_mtu/0]).

% Includes
-include("eth.hrl").

%--- API -----------------------------------------------------------------------

start_reader(Mac) ->
    etcpip_proc:start_link(eth_reader, #{
        init        => fun() -> Mac end,
        handle_cast => fun reader_handle_cast/2
    }).

start_writer(Mac) ->
    etcpip_proc:start_link(eth_writer, #{
        init        => fun() -> Mac end,
        handle_cast => fun writer_handle_cast/2
    }).

send(Payload, Protocol, DstMac) ->
    etcpip_proc:cast(eth_writer, {send, Payload, Protocol, DstMac}).

recv(Packet) ->
    etcpip_proc:cast(eth_reader, {recv, Packet}).

get_mtu() -> eth_port:get_mtu().

%--- Reader --------------------------------------------------------------------

reader_handle_cast({recv, Packet}, Mac) ->
    case decode(Packet, Mac) of
        {ok, Protocol, Data} -> Protocol:recv(Data);
        ignore               -> ok
    end,
    {noreply, Mac}.

%--- Writer --------------------------------------------------------------------

writer_handle_cast({send, Payload, Protocol, DstMac}, Mac) ->
    eth_port:send(encode(DstMac, Mac, Protocol, Payload)),
    {noreply, Mac}.

%--- Internal ------------------------------------------------------------------

encode(DstMac, SrcMac, Protocol, Payload) ->
    EthProtocol = encode_protocol(Protocol),
    [<<DstMac:48/big, SrcMac:48/big, EthProtocol:16/big>>, Payload].

decode(<<_Mac:48/big, _Src:48/big, ?ETH_IPV6:16/big, Data/binary>>, _) ->
    {ok, decode_protocol(?ETH_IPV6), Data};
decode(<<Mac:48/big, _Src:48/big, Protocol:16/big, Data/binary>>, Mac)  ->
    {ok, decode_protocol(Protocol), Data};
decode(<<?ETH_BROAD:48/big, _Src:48/big, Protocol:16/big, Data/binary>>, _Mac) ->
    {ok, decode_protocol(Protocol), Data};
decode(_Packet, _Mac) ->
    ignore.

encode_protocol(ip) -> ?ETH_IP;
encode_protocol(ipv6) -> ?ETH_IPV6;
encode_protocol(arp) -> ?ETH_ARP.

decode_protocol(?ETH_IP) -> ip;
decode_protocol(?ETH_IPV6) -> ipv6;
decode_protocol(?ETH_ARP) -> arp.
