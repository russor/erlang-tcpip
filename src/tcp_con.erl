%%%-------------------------------------------------------------------
%%% File    : tcp_con.erl
%%% Author  : Javier Paris Fernandez <javier.paris@udc.es>
%%% Description : Tcp Connection Management
%%%
%%% Created : 11 Aug 2004 by Javier Paris Fernandez <javier.paris@udc.es>
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

-module(tcp_con).

-export([new_mtu/2]).

-include("tcb.hrl").
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% API FOR APPLICATION LEVEL PROTOCOLS %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%usr_open(Rt_Ip, Rt_Port) ->  % Active Open
%    init(Rt_Ip, Rt_Port).

%%%%%%%%%%%%%%%%%% API FOR OTHER TCP AND IP MODULES %%%%%%%%%%%%%

new_mtu({Tcb, _, _}, MTU) -> % For PMTU discovery.
    tcb:set_tcbdata(Tcb, smss, MTU-40).

%%%%%%%%%%%%%%% Reader and Writer loop %%%%%%%%%%%%%%%

%% Every other protocol has a process for sending and a second one for receiving. 
%% In tcp the processes are per connection

%init(Rt_Ip, Rt_Port) ->
%    Tcb = tcb:start(closed, Rt_Ip, Rt_Port),
%    Writer = proc_lib:spawn_link(tcp_con, init_writer, [Tcb]),
%    Reader = proc_lib:spawn_link(tcp_con, init_reader, [Tcb, Writer]),
%    {ok, Lc_Ip, Lc_Port} = tcp_pool:add({remote, {Rt_Ip, Rt_Port}},
%					{Tcb, Reader, Writer}),
%    tcb:set_tcbdata(Tcb, lsocket, {Lc_Ip, Lc_Port}),
%    %TODO: send_packet(Writer, syn),
%    wait_state(Tcb, [established]),
%    {Tcb, Reader, Writer}.

%handle_info(timeout, {writer, Tcb, State, Data_Avail}) ->
%    {_Timeout, Def_Msg} = check_send(Tcb, State, Data_Avail),
%    New_Data_Avail = procces_msg(Tcb, State, {send, Def_Msg}),
%    {Timeout, _Def_Msg} = check_send(Tcb, State, New_Data_Avail),
%    {noreply, {writer, Tcb, State, New_Data_Avail}, Timeout}.
