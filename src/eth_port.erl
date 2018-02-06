%%%-------------------------------------------------------------------
%%% File    : eth_port.erl
%%% Author  : Javier Paris Fernandez <javier.paris@udc.es>
%%% Description : Ethernet Port driver
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
-module(eth_port).

% API
-export([start_reader/1, start_writer/0, send/1, get_instance/0, get_stats/0, get_mtu/0]).

%--- API -----------------------------------------------------------------------

start_reader(Iface) ->
    etcpip_proc:start_link(eth_port_reader, #{
        init        => fun() -> reader_init(Iface) end,
        handle_call => fun reader_call/3,
        handle_info => fun reader_info/2
    }).

start_writer() ->
    etcpip_proc:start_link(eth_port_writer, #{
        init        => fun writer_init/0,
        handle_cast => fun writer_cast/2
    }).

send(Packet) -> etcpip_proc:cast(eth_port_writer, {send, Packet}).

get_instance() -> etcpip_proc:call(eth_port_reader, get_instance).

get_mtu() -> {mtu, etcpip_proc:call(eth_port_reader, get_mtu)}.

get_stats() -> {ok, etcpip_proc:call(eth_port_reader, get_stats)}.

%--- Reader --------------------------------------------------------------------

reader_init(Iface) ->
    erl_ddll:load_driver(code:priv_dir(etcpip), "eth_driver"),
    Port = open_port({spawn_driver, eth_driver},[binary]),
    port_control(Port, 0, Iface),
    Port.

reader_call(get_instance, _From, Port) ->
    {reply, {self(), Port}, Port};
reader_call(get_stats, _From, Port) ->
    Stats = port_control(Port, 1, []),
    {reply, {ok, Stats}, Port};
reader_call(get_mtu, _From, Port) ->
    <<MTU:32/native-integer>> = list_to_binary(port_control(Port, 2, [])),
    {reply, MTU, Port}.

reader_info({Port, {data, Data}}, Port) ->
    eth:recv(Data),
    {noreply, Port}.

%--- Writer --------------------------------------------------------------------

writer_init() -> eth_port:get_instance().

writer_cast({send, Packet}, {Reader, Port} = State) ->
    Port ! {Reader, {command, Packet}},
    {noreply, State}.
