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
-module(ip_sup).

-behaviour(supervisor).

%% API
-export([start_link/4]).

%% Supervisor callbacks
-export([init/1]).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link(Ip, Netmask, Gateway, L2Module) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Ip, Netmask, Gateway, L2Module]).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

init([Ip, Netmask, Gateway, L2Module]) ->
    SupFlags = #{
        strategy  => one_for_one,
        intensity => 1,
        period    => 5
    },
    {ok, {SupFlags, [
        #{id => writer,   start => {ip, start_writer, [Ip, Netmask, Gateway, L2Module]}},
        #{id => reader,   start => {ip, start_reader, [Ip, Netmask]}}
    ]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
