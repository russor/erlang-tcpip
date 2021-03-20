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

-export([usr_listen/1, usr_accept/1, usr_send/2,
	 close_connection/1, abort_connection/1, usr_recv/2, new_mtu/2,
	 dst_unr/1, usr_sockopt/3]).

-include("tcb.hrl").
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% API FOR APPLICATION LEVEL PROTOCOLS %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%usr_open(Rt_Ip, Rt_Port) ->  % Active Open
%    init(Rt_Ip, Rt_Port).

usr_listen(Lc_Port) ->  % Pasive Open
    init(Lc_Port).

usr_accept(Tcb) -> accept(Tcb).

usr_send(Tcb, Data) -> gen_server:call(Tcb, {queue, Data}).

usr_recv(Tcb, Bytes) -> gen_server:call(Tcb, {read, Bytes}).

usr_sockopt({Tcb, _Reader, _Writer}, Param, Value) ->
    tcb:set_tcbdata(Tcb, Param, Value).

%%%%%%%%%%%%%%%%%% API FOR OTHER TCP AND IP MODULES %%%%%%%%%%%%%

close_connection(Tcb) ->
    tcp_pool:remove(Tcb),
    tcb:set_state(Tcb, closed).

% maybe this should do something slightly different?
abort_connection(Tcb) ->
    close_connection(Tcb).

new_mtu({Tcb, _, _}, MTU) -> % For PMTU discovery.
    tcb:set_tcbdata(Tcb, smss, MTU-40).

dst_unr({_Tcb, _, _}) -> % Should send the user an error. Unimplemented
    ok.

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

init(Lc_Port) -> tcb:start(listen, Lc_Port).

%handle_info(timeout, {writer, Tcb, State, Data_Avail}) ->
%    {_Timeout, Def_Msg} = check_send(Tcb, State, Data_Avail),
%    New_Data_Avail = procces_msg(Tcb, State, {send, Def_Msg}),
%    {Timeout, _Def_Msg} = check_send(Tcb, State, New_Data_Avail),
%    {noreply, {writer, Tcb, State, New_Data_Avail}, Timeout}.

%%%%%%%%%%%%%%%%%%%%% User Commands %%%%%%%%%%%%%%%%%%%%

wait_state(Tcb, State_List) ->
    tcb:subscribe(Tcb, state),
    case wait_state_1(State_List) of
        {ok, closed} ->
            receive
                {state, closed, _} ->
                    ok
            after 2000 ->
                    throw(timeout)
            end,
            ok;
        _ ->
            tcb:unsubscribe(Tcb, state),
            ok
    end.

wait_state_1(State_List) ->
    receive
	{state, State, _Who} ->
	    case lists:member(State, State_List) of
		true ->
                    {ok, State};
		false ->
		    wait_state_1(State_List)
	    end
    end.

close(Tcb, Writer) ->
    tcp_con:send_packet(Writer, fin),
    wait_state(Tcb, [time_wait, closed]).

accept(Tcb) ->
    tcb:subscribe(Tcb, listener_queue),
    receive
        {open_con, closed} ->
            %% Listen socket was closed...
            closed;
        {open_con, Socket} ->
            link(Socket),
            Socket
    end.


state_close(close_wait) -> ok;
state_close(closing) -> {error, connection_closing};
state_close(established) -> ok;
state_close(fin_wait_1) -> {error, connection_closing};
state_close(fin_wait_2) -> {error, connection_closing};
state_close(last_ack) -> {error, connection_closing};
state_close(listen) -> ok;
state_close(syn_rcvd) -> ok;
state_close(syn_sent) -> ok;
state_close(time_wait) -> {error, connection_closing}.
