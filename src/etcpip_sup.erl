%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @doc
%%%
%%% License:
%%% This code is licensed to you under the Apache License, Version 2.0
%%% (the "License"); you may not use this file except in compliance with
%%% the License. You may obtain a copy of the License at
%%% 
%%%   http://www.apache.org/licenses/LICENSE-2.0
%%% 
%%% Unless required by applicable law or agreed to in writing,
%%% software distributed under the License is distributed on an
%%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%%% KIND, either express or implied.  See the License for the
%%% specific language governing permissions and limitations
%%% under the License.
%%%
%%% @end
%%% Created : 12 Aug 2016 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(etcpip_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart intensity, and child
%% specifications.
%%
%% @spec init(Args) -> {ok, {SupFlags, [ChildSpec]}} |
%%                     ignore |
%%                     {error, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    SupFlags = #{
        strategy  => rest_for_one,
        intensity => 1,
        period    => 5
    },

    Iface   = get_env(iface),
    Ip      = ip_to_integer(get_env(ip)),
    IP6     = parse_ip6(get_env([ip6, addr])),
    Netmask = ip_to_integer(get_env(netmask)),
    Gateway = ip_to_integer(get_env(gateway)),
    Mac     = mac_to_integer(get_env(mac)),

    L2Module = arp,
    L2Sup = list_to_atom(atom_to_list(L2Module) ++ "_sup"),

    % TODO: Reverse processes later in the chain are already started
    {ok, {SupFlags, [
        #{id => eth_port_reader, start => {eth_port, start_reader, [Iface]}},
        #{id => eth_port_writer, start => {eth_port, start_writer, []}},
        #{id => eth_reader,      start => {eth, start_reader, [Mac]}},
        #{id => eth_writer,      start => {eth, start_writer, [Mac]}},

        #{id => L2Sup,        start => {L2Sup, start_link, [Ip, Mac]}, type => supervisor},
        #{id => checksum,     start => {checksum, start_link, []}},
        #{id => ip_sup,       start => {ip_sup, start_link, [Ip, Netmask, Gateway, L2Module]}},
        #{id => icmp_sup,     start => {icmp_sup, start_link, []}},
        #{id => udp_sup,      start => {udp_sup, start_link, [Ip]}},
        #{id => tcp_pool,     start => {tcp_pool, start_link, [Ip]}},
        #{id => iss,          start => {iss, start_link, []}},
        #{id => tcp,          start => {tcp, start_link, []}},
        #{id => tcp_sup,      start => {tcp_sup, start_link, []}},

        % IPv6
        #{id => ipv6_reader,   start => {ipv6, start_reader, []}},
        #{id => ipv6_writer,   start => {ipv6, start_writer, []}},
        #{id => icmpv6_reader, start => {icmpv6, start_reader, [IP6, Mac]}},
        #{id => icmpv6_writer, start => {icmpv6, start_writer, []}}
    ]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

get_env(Path) when is_list(Path) ->
    Envs = application:get_all_env(),
    try get_env(Path, Envs)
    catch key_not_found -> error({key_not_found, Path, Envs})
    end;
get_env(Env) ->
    {ok, Value} = application:get_env(Env),
    Value.

get_env([], Value) ->
    Value;
get_env([Key|Path], Envs) ->
    case proplists:lookup(Key, Envs) of
        none         -> throw(key_not_found);
        {Key, Value} -> get_env(Path, Value)
    end.

ip_to_integer({A, B, C, D}) ->
    <<R:32>> = <<A, B, C, D>>,
    R.

mac_to_integer(<<E:48>>) -> E.

parse_ip6(String) ->
    case inet:parse_ipv6_address(String) of
        {error, einval} -> error({invalid_ipv6_address, String});
        {ok, {A, B, C, D, E, F, G, H}} ->
            <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>
    end.
