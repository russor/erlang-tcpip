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
-module(tcp_con_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_con/2]).

%% Supervisor callbacks
-export([init/1]).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_con(Sup, Tcb) ->
    {ok, Writer} = supervisor:start_child(Sup,
        #{id => reader, start => {tcp_con, start_writer, [Tcb]}}
    ),
    {ok, Reader} = supervisor:start_child(Sup,
        #{id => reader, start => {tcp_con, start_reader, [Tcb, Writer]}}
    ),
    {ok, Reader, Writer}.

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

init([]) ->
    SupFlags = #{
        strategy  => rest_for_one,
        intensity => 1,
        period    => 5
    },
    {ok, {SupFlags, []}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
