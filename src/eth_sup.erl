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
-module(eth_sup).

-behaviour(supervisor).

%% API
-export([start_link/2]).

%% Supervisor callbacks
-export([init/1]).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link(Mac, PhyModule) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Mac, PhyModule]).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

init([Mac, PhyModule]) ->
    SupFlags = #{
        strategy  => one_for_one,
        intensity => 1,
        period    => 5
    },
    {ok, {SupFlags, [
        #{id => eth_reader,   start => {eth, start_reader, [Mac]}},
        #{id => eth_writer,   start => {eth, start_writer, [Mac, PhyModule]}}
    ]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
