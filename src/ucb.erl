%%%-------------------------------------------------------------------
%%% File    : ucb.erl
%%% Author  : Richard Russo <toast@ruka.org>
%%% Description : Ucb process (UDP Control Block)
%%%
%%% Created : 10 Nov 2021 by Richard Russo <toast@ruka.org>
%%% patterned after tcb.erl
%%%
%%%
%%% erlang-tcpip, Copyright (C) 2004 Javier Paris, 2021 Richard Russo
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

-module(ucb).

-export([start/2, init/1]).
-export([handle_info/2, handle_cast/2, handle_call/3]).

-record(ucb, {rt_port = 0,
              rt_ip = 0,
              lc_ip = 0,
              lc_port = 0,
              options = #{},
              obs = {},
              rbuf,
              ref
             }).

start(new, Options) ->
    {ok, Pid} = gen_server:start(?MODULE, [Options, self()], []),
    Pid.

init([Options, Owner]) ->
    process_flag(trap_exit, true),
    Options = #{},
    Ref = erlang:monitor(process, Owner),
    {ok, #ucb{rbuf = queue:new(), options = #{{otp, owner} => Owner}, ref = Ref}}.

handle_info({udp, {_Lc_Ip, _Lc_Port, Rt_Ip, Rt_Port}, Data}, Ucb) ->
    Rbuf = queue:in({#{family => inet, port => Rt_Port, addr => etcpip_socket:unmap_ip(Rt_Ip)}, Data},
                    Ucb#ucb.rbuf),
    Ucb1 = case Ucb#ucb.obs of
        {_, notified, _} -> Ucb#ucb{rbuf = Rbuf};
        {To, _Length, SelectHandle} ->
            To ! {'$socket', {etcpip, self()}, select, SelectHandle},
            Ucb#ucb{obs = {To, notified, SelectHandle}, rbuf = Rbuf};
        {} -> Ucb#ucb{rbuf = Rbuf}
    end,
    {noreply, Ucb1};

handle_info(Info, Ucb) ->
    io:format("ucb ~p got info ~p~n~p~n", [self(), Info, Ucb]),
    {noreply, Ucb}.

handle_call({getopt, {otp, domain}}, _From, Ucb) ->
    {reply, {ok, inet}, Ucb};

handle_call({setopt, {otp, meta}, Map}, _From, Ucb) ->
    NewUcb = maps:fold(fun(Key, Val, T) ->
        {reply, ok, T2} = handle_call({setopt, {otp, Key}, Val}, {}, T),
        T2
    end, Ucb, Map),
    {reply, ok, NewUcb};
handle_call({setopt, {otp, Key}, Val}, _From, Ucb = #ucb{options = Options}) ->
    {reply, ok, Ucb#ucb{options = Options#{{otp, Key} => Val}}};
handle_call({getopt, {otp, meta}}, _From, Ucb) ->
    Meta = maps:fold(fun
        ({otp, Key}, Val, Acc) -> Acc#{Key => Val};
        (_K, _V, Acc) -> Acc
    end, #{}, Ucb#ucb.options),
    {reply, {ok, Meta}, Ucb};

handle_call({recvfrom, Length, [peek], Timeout}, From, Ucb) when Length /= 0 ->
    handle_call({recv, -Length, [], Timeout}, From, Ucb);

handle_call({recvfrom, Length, Flags, Timeout}, From = {To, _Tag}, Ucb)
    when Flags == [], (Ucb#ucb.obs == {} orelse element(1, Ucb#ucb.obs) == To) ->
    case queue:out(Ucb#ucb.rbuf) of
        {{value, {Source, Data}}, Q2} ->
            {reply, {ok, {Source, Data}}, Ucb#ucb{rbuf = Q2, obs = {}}};
        {empty, _} when Timeout == nowait ->
            Handle = make_ref(),
            {reply, {select, {select_info, recv, Handle}}, Ucb#ucb{obs = {To, Length, Handle}}};
        {empty, _} when Timeout == infinity ->
            {noreply, Ucb#ucb{obs = {From, Length}}};
        {empty, _} when is_integer(Timeout) ->
            {noreply, Ucb#ucb{obs = {From, Length}}}
    end;
handle_call({cancel, {select_info, recv, Ref}}, _From, #ucb{obs = {_, _, Ref}} = Ucb) ->
    %io:format("cancel select~n", []),
    {reply, ok, Ucb#ucb{obs = {}}};
handle_call({cancel, SelectInfo}, _From, Ucb) ->
    {reply, {error, {invalid, SelectInfo}}, Ucb};

handle_call({bind, #{addr := InetAddr, family := inet, port := Port}}, _From, Ucb) ->
    Addr = etcpip_socket:map_ip(InetAddr),
    case udp:open(Addr, Port) of
        {ok, RealAddr, RealPort} ->
            %io:format("ucb ~p, bound to ~p:~B~n", [self(), RealAddr, RealPort]),
            {reply, ok, Ucb#ucb{lc_port = RealPort, lc_ip = RealAddr}};
        E ->
            io:format("ucb ~p, got ~p~n", [self(), E]),
            {reply, E, Ucb}
    end;

handle_call(close, From, Ucb) ->
    %io:format("ucb ~p closing ~2000p~n", [self(), Ucb]),
    % TODO: notify listeners!
    gen_server:reply(From, ok),
    {stop, normal, Ucb};

handle_call({queue, Data, Dest, _Flags, _Timeout}, _From, Ucb) ->
    DestAddr = etcpip_socket:map_ip(maps:get(addr, Dest)),
    udp:send(Ucb#ucb.lc_ip, Ucb#ucb.lc_port, DestAddr, maps:get(port, Dest), Data),
    {reply, ok, Ucb};

handle_call(Call, From, Ucb) ->
    io:format("ucb ~p got call ~p from ~p (Ucb ~p)~n", [self(), Call, From, Ucb]),
    {reply, {error, unimpl}, Ucb}.

handle_cast(Cast, Ucb) ->
    io:format("ucb ~p got cast ~p~n", [self(), Cast]),
    {noreply, Ucb}.
