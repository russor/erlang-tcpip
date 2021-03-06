%%%-------------------------------------------------------------------
%%% @doc TCP pool supervisor.
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
%%%-------------------------------------------------------------------
-module(arp_sup).

-behaviour(supervisor).

%% API
-export([start_link/2]).

%% Supervisor callbacks
-export([init/1]).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link(Ip, Mac) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Ip, Mac]).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

init([Ip, Mac]) ->
    SupFlags = #{
        strategy  => one_for_one,
        intensity => 1,
        period    => 5
    },
    % FIXME: Proper owner of ETS table (not the supervisor!)
    ets:new(arp_cache, [set, public, named_table]),
    {ok, {SupFlags, [
        #{id => reader,   start => {arp, start_reader, [Ip, Mac]}},
        #{id => writer,   start => {arp, start_writer, [Ip, Mac]}},
        #{id => ip_queue, start => {arp, start_ip_queue, [Ip, Mac]}}
    ]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
