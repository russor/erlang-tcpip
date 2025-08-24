%%%-------------------------------------------------------------------
%%% File    : tcb.erl
%%% Author  : Javier Paris Fernandez <javier.paris@udc.es>
%%% Description : Tcb process
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

-module(tcb).

-export([start/3, start/2, init/2, init/3]).
-export([handle_info/2, handle_cast/2, handle_call/3, terminate/2]).

-include("tcb.hrl").
-include("tcp_packet.hrl").
-include("ip.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start(listen, Port) -> proc_lib:spawn(?MODULE, init, [listen, self(), Port]);

start(new, Options) -> proc_lib:spawn(?MODULE, init, [new, self(), Options]).

start(new, Rt_Ip, Rt_Port) ->
    proc_lib:spawn(?MODULE, init, [new, self(), Rt_Ip, Rt_Port]).

clone(Tcb, Socket, Irs, Mss) ->
    Rcv_Next = seq:add(Irs, 1),
    {Lc_ip, _Lc_port, Rt_ip, Rt_port} = Socket,
    <<Iss:32>> = crypto:strong_rand_bytes(4),
    N_Tcb=Tcb#tcb{syn_queue=[],
		  open_queue=queue:new(),
		  rt_ip = Rt_ip, rt_port = Rt_port,
		  lc_ip = Lc_ip,
		  rcv_nxt = Rcv_Next,
		  irs = Irs, snd_wl1 = Irs, snd_wl2 = Rcv_Next,
		  state = syn_rcvd,
		  obs = self(),
		  iss = Iss, snd_nxt = Iss, snd_una = Iss,
		  snd_max = seq:add(Iss, 1),
		  send_type = ack,
		  smss = Mss
		  },
    NTcb_Proc = proc_lib:spawn(tcb, init, [N_Tcb, self()]),
    NTcb_Proc.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

init(listen, Owner, Lc_Port) ->
    process_flag(trap_exit, true),
    monitor(process, Owner),
    Tcb = init_tcb(0, 0, listen),
    {ok, Lc_Ip, Lc_Port} = tcp_pool:add({local, {0, Lc_Port}}, self()),
    Tcb1 = Tcb#tcb{lc_ip = Lc_Ip, lc_port = Lc_Port},
    gen_server:enter_loop(?MODULE, [], Tcb1#tcb{owner = Owner});

init(new, Owner, Options) ->
    process_flag(trap_exit, true),
    monitor(process, Owner),
    Options = #{},
    Tcb = init_tcb(0, 0, new),
    gen_server:enter_loop(?MODULE, [], Tcb#tcb{owner = Owner}).

% from clone in listen, need to send synack
init(Tcb, _Parent) when is_record(Tcb, tcb) ->
    process_flag(trap_exit, true),
    monitor(process, Tcb#tcb.owner),
    {noreply, Tcb1} = send_packet(Tcb),
    gen_server:enter_loop(?MODULE, [], Tcb1).

init(new, Owner, Rt_Ip, Rt_Port) ->
    process_flag(trap_exit, true),
    monitor(process, Owner),
    Tcb = init_tcb(Rt_Ip, Rt_Port, new),
    gen_server:enter_loop(?MODULE, [], Tcb#tcb{owner = Owner}).

handle_info({state, established, Socket}, Tcb) ->
    send_packet(set_open_queue(Tcb, Socket));

handle_info({'DOWN', _Ref, process, Pid, Reason}, Tcb) ->
    if Pid == Tcb#tcb.owner ->
        io:format("owner shutdown ~p: ~p~n", [Tcb#tcb.state, Reason]);
    true ->
        io:format("non-owner shutdown: ~p, pid: ~p, owner: ~p~n", [Reason, Pid, Tcb#tcb.owner])
    end,
    {noreply, Tcb};

% delayed ack trigger
handle_info({event, ack}, Tcb) ->
    send_packet(Tcb#tcb{send_type = any});

handle_info(timeout, Tcb = #tcb{state = time_wait}) ->
    send_packet(Tcb#tcb{state = closed});

handle_info({state, _State, _}, Tcb) -> % Erase them if the connection closes??
    send_packet(Tcb).

handle_call({queue, Data, _Flags, _Timeout}, From, Tcb) ->
    {Tcb1, Reply} = queue(Tcb, Data),
    gen_server:reply(From, Reply),
    send_packet(Tcb1);

handle_call({recv, Length, [peek], Timeout}, From, Tcb) when Length /= 0 ->
    handle_call({recv, -Length, [], Timeout}, From, Tcb);

handle_call({recv, Length, Flags, Timeout}, From = {To, _Tag}, Tcb)
    when Flags == [], (Tcb#tcb.obs == {} orelse element(1, Tcb#tcb.obs) == To) ->
    case Tcb#tcb.state of
	closing -> {reply, {error, closed}, Tcb};
	last_ack -> {reply, {error, closed}, Tcb};
	time_wait when Tcb#tcb.rbsize == 0 -> {reply, {error, closed}, Tcb};
	listen -> {reply, {error, no_connection}, Tcb};
	close_wait when Tcb#tcb.rbsize == 0 -> {reply, {error, closed}, Tcb};
	_ when Length < 0 andalso Tcb#tcb.rbsize >= -Length ->
	    %io:format("peek data len ~B rbsize ~B~n", [Length, Tcb#tcb.rbsize]),
            {Data, _Rem} = get_data(Tcb#tcb.rbuf, -Length, <<>>),
            gen_server:reply(From, {ok, Data}),
            send_packet(Tcb#tcb{obs = {}});
	_ when (Tcb#tcb.rbsize > 0 andalso Length == 0) orelse
	       (Tcb#tcb.rbsize >= Length andalso Length > 0) orelse
	       Tcb#tcb.state == close_wait orelse
	       Tcb#tcb.state == time_wait ->
            Size = min(Length, Tcb#tcb.rbsize),
            {Data, Rem} = get_data(Tcb#tcb.rbuf, Size, <<>>),
            gen_server:reply(From, {ok, Data}),

            New_Size = Tcb#tcb.rbsize - size(Data),
            Free_Buf = max(Tcb#tcb.maxrbsize-New_Size, 0),
            Rcv_Wnd = min(?TCP_MAX_WINDOW, Free_Buf),

            send_packet(Tcb#tcb{rbuf=Rem, rbsize=New_Size, rcv_wnd = Rcv_Wnd, obs = {}});
        _ when Timeout == nowait ->
            Handle = make_ref(),
            gen_server:reply(From, {select, {select_info, recv, Handle}}),
            send_packet(Tcb#tcb{obs = {To, Length, Handle}});
        _ when Timeout == infinity ->
            send_packet(Tcb#tcb{obs = {From, Length}});
        _ when is_integer(Timeout) ->
            send_packet(Tcb#tcb{obs = {From, Length}})
    end;

handle_call({cancel, {select_info, recv, Ref}}, _From, #tcb{obs = {_, _, Ref}} = Tcb) ->
    %io:format("cancel select~n", []),
    {reply, ok, Tcb#tcb{obs = {}}};
handle_call({cancel, SelectInfo}, _From, Tcb) ->
    {reply, {error, {invalid, SelectInfo}}, Tcb};

handle_call(close, From, #tcb{state = listen} = Tcb) ->
    % TODO: notify listeners!
    gen_server:reply(From, ok),
    {stop, normal, Tcb};

handle_call(close, From, #tcb{state = new} = Tcb) ->
    gen_server:reply(From, ok),
    {stop, normal, Tcb};

handle_call(close, From, Tcb) ->
    NewState = case Tcb#tcb.state of
        established -> fin_wait_1;
        close_wait -> last_ack;
        syn_rcvd -> fin_wait_1
    end,
    Tcb1 = set_state(Tcb#tcb{send_fin = 1, send_type = any, snd_max = seq:add(Tcb#tcb.snd_max, 1)}, NewState),
    gen_server:reply(From, ok),
    send_packet(Tcb1);

handle_call({bind, #{addr := InetAddr, family := inet, port := Port}}, _From, Tcb) ->
    Addr = etcpip_socket:map_ip(InetAddr),
    {reply, ok, Tcb#tcb{lc_port = Port, lc_ip = Addr}};

% TODO: Backlog
handle_call({listen, _Backlog}, _From, Tcb) when Tcb#tcb.state == new ->
    case Tcb#tcb.lc_port of
        N when is_integer(N), N >= 0, N < 65536 ->
            case tcp_pool:add({local, {Tcb#tcb.lc_ip, Tcb#tcb.lc_port}}, self()) of
                {ok, ListenedIp, ListenedPort} ->
                    {reply, ok, Tcb#tcb{state = listen, lc_ip = ListenedIp, lc_port=ListenedPort}};
                Other -> {reply, Other, Tcb}
            end;
        _ -> {reply, {error, badarg}, Tcb}
    end;

handle_call({accept, Timeout}, From, Tcb) ->
    case queue:out_r(Tcb#tcb.open_queue) of
	{empty, _} when Timeout == infinity ->
		{noreply, Tcb#tcb{obs=queue:cons(From, Tcb#tcb.obs)}};
%	{empty, _} when Timeout == nowait ->
%		{Pid, Tag} = From,
%		SelectRef = make_ref(),
%		{reply, {select, {select_info, SelectRef, SelectRef}},
%			Tcb#tcb{obs=queue:cons({nowait, Pid, SelectRef}, Tcb#tcb.obs)}};
	{empty, _} -> % TODO timeouts/select info!
		{noreply, Tcb#tcb{obs=queue:cons(From, Tcb#tcb.obs)}};
	{{value, Socket}, Q2} ->
		{reply, {ok, Socket}, Tcb#tcb{open_queue = Q2}}
    end;

handle_call({connect, DestAddr, _Timeout}, From, Tcb) when Tcb#tcb.state == new ->
    Rt_Ip = etcpip_socket:map_ip(maps:get(addr, DestAddr)),
    Rt_Port = maps:get(port, DestAddr),
    case tcp_pool:add({connect, {Tcb#tcb.lc_ip, Tcb#tcb.lc_port, Rt_Ip, Rt_Port}}, self()) of
        {ok, Lc_Ip, Lc_Port} ->
            send_packet(Tcb#tcb{ rt_ip = Rt_Ip, rt_port = Rt_Port,
                                 lc_ip = Lc_Ip, lc_port = Lc_Port,
                                 state = syn_sent,
                                 snd_max = seq:add(Tcb#tcb.iss, 1),
                                 send_type = ack, obs = From
            });
        O -> {reply, O, Tcb}
    end;

handle_call(sockname, _From, Tcb) ->
    {reply, {ok, #{family => inet, port => Tcb#tcb.lc_port, addr => etcpip_socket:unmap_ip(Tcb#tcb.lc_ip)}}, Tcb};
handle_call(peername, _From, Tcb) ->
    {reply, {ok, #{family => inet, port => Tcb#tcb.rt_port, addr => etcpip_socket:unmap_ip(Tcb#tcb.rt_ip)}}, Tcb};
handle_call(info, _From, Tcb) ->
    {reply, #{domain => inet, type => stream, protocol => tcp,
              owner => client, ctype => normal,
              counters => #{read_pkg => Tcb#tcb.read_pkg, write_pkg => Tcb#tcb.write_pkg}
             }, Tcb};

% TODO: option validity
handle_call({setopt, {socket, reuseaddr}, _Val}, _From, Tcb) ->
    {reply, ok, Tcb};

handle_call({setopt, {tcp, nodelay}, _Val}, _From, Tcb) ->
    {reply, ok, Tcb};

handle_call({setopt, {otp, meta}, Map}, _From, Tcb) ->
    NewTcb = maps:fold(fun(Key, Val, T) ->
        {reply, ok, T2} = handle_call({setopt, {otp, Key}, Val}, {}, T),
        T2
    end, Tcb, Map),
    {reply, ok, NewTcb};

handle_call({setopt, {otp, Key}, Val}, _From, Tcb = #tcb{options = Options}) ->
    {reply, ok, Tcb#tcb{options = Options#{{otp, Key} => Val}}};

handle_call({getopt, {otp, meta}}, _From, Tcb) ->
    Meta = maps:fold(fun
        ({otp, Key}, Val, Acc) -> Acc#{Key => Val};
        (_K, _V, Acc) -> Acc
    end, #{}, Tcb#tcb.options),
    {reply, {ok, Meta}, Tcb}.

handle_cast({in, Pkt}, Tcb) ->
    send_packet(in(Tcb#tcb.state, Tcb, Pkt)).

terminate(Reason, Tcb) ->
    % TODO: notify listeners!
    % TODO: remove from tcp_pool
    if Tcb#tcb.state == closed -> ok;
    true ->
        io:format("tcb ~p terminated ~p~n", [Tcb#tcb.state, Reason])
    end.

send_packet(Tcb = #tcb{state = closed}) ->
    {stop, normal, Tcb};
send_packet(Tcb = #tcb{send_type = ack}) ->
    send_packet(send_packet_impl(Tcb#tcb{send_type = none}, ack));

send_packet(Tcb = #tcb{send_type = any}) ->
    case erlang:process_info(self(), message_queue_len) of
        % delay sending if we have messages pending
        % this may enable fuller packets to be sent
        {message_queue_len, N} when N > 3 -> {noreply, Tcb};
        % send_packet will set send_type = none when
        % all queued data within the send window is sent
        _ -> send_packet(send_packet_impl(Tcb, any))
    end;

send_packet(Tcb = #tcb{send_type = none, state = time_wait}) ->
    {noreply, Tcb, 2 * ?DEFAULT_MSL};
send_packet(Tcb = #tcb{send_type = none}) -> {noreply, Tcb}.

%%%%%%%%%%%%%%%%%%%%%%  GET DATA FUNCTIONS %%%%%%%%%%%%%%%%%%%
get_sdata(Tcb, Type) ->
    Size = get_data_size(Tcb),
    if
        Size == 0 orelse Type == ack ->
	    {Tcb#tcb{send_type = none}, <<>>, Tcb#tcb.snd_nxt, 0, 0};
	Size > 0 ->
	    {Data, Rem} = get_data(Tcb#tcb.sbuf, Size, <<>>),
	    if
		Tcb#tcb.dack_timer == -1 -> ok;
		true -> erlang:cancel_timer(Tcb#tcb.dack_timer)
	    end,
	    Sbsize = (Tcb#tcb.sbsize - size(Data)),
	    {Fin, SendFin} = if
		 Sbsize == 0 andalso Tcb#tcb.send_fin > 0 -> {1, 2};
		 true -> {0, Tcb#tcb.send_fin}
	    end,
	    {Type1, Psh} = if
	         % syn/fin, not a push, no more data to send
	         Sbsize == 0 andalso size(Data) == 0 -> {none, 0};
	         Sbsize == 0 -> {none, 1};
	         true -> {Tcb#tcb.send_type, 0}
	    end,
	    {Tcb#tcb{sbuf       = Rem,
                     sbsize     = Sbsize,
                     snd_nxt    = seq:add(Tcb#tcb.snd_nxt, size(Data) + Fin),
                     dack_timer = -1,
                     dack_data  = 0,
                     send_fin   = SendFin,
                     send_type  = Type1},
	     Data, Tcb#tcb.snd_nxt, Fin, Psh}
    end.

get_rqueue(Tcb) ->
    case catch queue:last(Tcb#tcb.rqueue) of
	{'EXIT', _} -> {Tcb, empty};
	{_, Packet} ->
	    if Packet#pkt.data_size > Tcb#tcb.smss -> {Tcb, Packet};% PMTU. Do not increase.
	    true ->
		Rto = round(min(?MAX_RTO, Tcb#tcb.rto * 2)),
		Rtcount = Tcb#tcb.rtcount + 1,
		Timer = erlang:send_after(Rto, self(), {event, rto}),
		{Tcb#tcb{rto = Rto, rtcount = Rtcount, rtimer = Timer,
		         rttimer = -1, rtseq = -1}, Packet}
	    end
    end.

%%%%%%%%%%%%%%%%%%%%%%%%% Set Data Functions %%%%%%%%%%%%%%%%%%%%%%%%%%%

queue(Tcb, _Data) when Tcb#tcb.state == closing -> {Tcb, {error, connection_closing}};
queue(Tcb, _Data) when Tcb#tcb.state == fin_wait_1 -> {Tcb, {error, connection_closing}};
queue(Tcb, _Data) when Tcb#tcb.state == fin_wait_2 -> {Tcb, {error, connection_closing}};
queue(Tcb, _Data) when Tcb#tcb.state == last_ack -> {Tcb, {error, connection_closing}};
queue(Tcb, _Data) when Tcb#tcb.state == listen -> {Tcb, {error, no_connection}};
queue(Tcb, _Data) when Tcb#tcb.state == time_wait -> {Tcb, {error, connection_closing}};
queue(Tcb, _Data) when Tcb#tcb.state == closed -> {Tcb, {error, connection_closed}};

queue(Tcb, Data) ->
    Data1 = iolist_to_binary(Data),
    Sbuf = queue:cons(Data1, Tcb#tcb.sbuf),
    Tcb1 = Tcb#tcb{sbuf = Sbuf, sbsize = Tcb#tcb.sbsize + size(Data1),
                   snd_max = seq:add(Tcb#tcb.snd_max, size(Data1)),
                   write_pkg = Tcb#tcb.write_pkg + 1},
    case get_data_size(Tcb1) of
	0 -> {Tcb1, ok};
	_ -> {Tcb1#tcb{send_type = any}, ok}
    end.

set_snd_wnd(Tcb, {Wnd, Seq, Ack}) ->
    case seq:lt(Tcb#tcb.snd_wl1, Seq) orelse
	((Tcb#tcb.snd_wl1 == Seq) andalso seq:le(Tcb#tcb.snd_wl2, Ack)) of
    true ->
        Tcb1 = Tcb#tcb{snd_wnd = Wnd, snd_wl1 = Seq, snd_wl2= Ack},
	case get_data_size(Tcb1) of
	    0 -> Tcb1;
	    _ -> Tcb1#tcb{send_type = any}
        end;
    false -> Tcb
    end.

set_snd_una(Tcb, Snd_Una) ->
    {Queue, Timer} = update_rqueue(Tcb, Snd_Una),
    {Cwnd, Ssthr} = congestion:cgt_ctl(Tcb#tcb.rtcount, Tcb#tcb.snd_nxt,
				         Tcb#tcb.snd_una, Tcb#tcb.smss,
				         Tcb#tcb.cwnd,    Tcb#tcb.ssthr),
    {Rttimer, RtSeq, Rto, Srtt, Rttvar} =
	etcpip_rtt:check_rttimer(Tcb#tcb.rtseq, Tcb#tcb.rtcount, Tcb#tcb.rttimer,
			  Tcb#tcb.srtt, Tcb#tcb.rttvar, Tcb#tcb.rto, Snd_Una),

    Tcb#tcb{snd_una = Snd_Una, snd_nxt = seq:max(Snd_Una, Tcb#tcb.snd_nxt),
            rqueue = Queue, rtimer=Timer, rtcount = 0,
            cwnd = Cwnd, ssthr = Ssthr, rttimer = Rttimer,
	    rtseq = RtSeq, rto = Rto, srtt = Srtt, rttvar = Rttvar}.

set_del_ack(Tcb, Size) ->
    case Tcb#tcb.dack_timer of
	    -1 ->
		Timer = erlang:send_after(?DEFAULT_DACK_TIME, self(), {event, ack}),
		%io:format("Setting ack Timer for ~w ~w~n",[?DEFAULT_DACK_TIME, Tcb]),
		Tcb#tcb{dack_timer = Timer, dack_data = Size};
	Timer ->
	    New_Size = Tcb#tcb.dack_data + Size,
	    if
		New_Size >= (2*Tcb#tcb.rmss) ->
		    catch erlang:cancel_timer(Timer),
		    Tcb#tcb{send_type = any, dack_timer = -1, dack_data = 0};
		true ->
		    Tcb#tcb{dack_data = New_Size}
	    end
    end.

set_rqueue(Tcb, Data) ->
    Timer = set_rtimer(Tcb),
    Q = queue:cons(Data, Tcb#tcb.rqueue),
    Tcb#tcb{rqueue= Q, rtimer = Timer}.

set_state(Tcb = #tcb{obs = Listener}, established) when is_pid(Listener) ->
    Listener ! {state, established, self()},
    Tcb#tcb{state = established, obs = {}};

set_state(Tcb = #tcb{obs = From}, established) ->
    gen_server:reply(From, ok),
    Tcb#tcb{state = established, obs = {}};

% TODO: cancel readers when transitioning to CLOSING
set_state(Tcb, State) -> Tcb#tcb{state = State}.

set_rdata(Tcb, <<>>) -> Tcb;
set_rdata(Tcb, Data) ->
    New_Data = queue:cons(Data, Tcb#tcb.rbuf),
    New_Size = Tcb#tcb.rbsize + size(Data),
    
    Rcv_Nxt = seq:add(Tcb#tcb.rcv_nxt, size(Data)),
    Free_Buf = max(Tcb#tcb.maxrbsize-New_Size, 0),
    Rcv_Wnd = min(?TCP_MAX_WINDOW, Free_Buf),
    
    Tcb1 = Tcb#tcb{rbuf = New_Data, rbsize = New_Size,
                   rcv_nxt = Rcv_Nxt, rcv_wnd = Rcv_Wnd,
                   read_pkg = Tcb#tcb.read_pkg + 1},
    case Tcb#tcb.obs of
	{} -> Tcb1;
	{From, Length} ->
	    case handle_call({recv, Length, [], infinity}, From, Tcb1#tcb{obs = {}}) of
	        {noreply, Tcb2} -> Tcb2;
	        {noreply, Tcb2, _Timeout} -> Tcb2
	    end;
	{_, notified, _} -> Tcb1;
	{To, Length, SelectHandle} when Length < 0 andalso New_Size >= -Length ->
	    %io:format("select peek ~B ~B~n", [Length, New_Size]),
	    To ! {'$socket', {etcpip, self()}, select, SelectHandle},
	    Tcb1#tcb{obs = {To, notified, SelectHandle}};
	{To, Length, SelectHandle} when Length >= 0 andalso New_Size >= Length ->
	    %io:format("select ~B ~B~n", [Length, New_Size]),
	    To ! {'$socket', {etcpip, self()}, select, SelectHandle},
	    Tcb1#tcb{obs = {To, notified, SelectHandle}};
	{To, _Length, SelectHandle} when Tcb1#tcb.state == close_wait; Tcb1#tcb.state == time_wait ->
	    %io:format("select closing ~p~n", [Tcb1#tcb.obs]),
	    To ! {'$socket', {etcpip, self()}, select, SelectHandle},
	    Tcb1#tcb{obs = {To, notified, SelectHandle}};
	{_To, _Length, _SelectHandle} ->
	    %io:format("still waiting length ~B, new size ~B~n", [Length, New_Size]),
	    Tcb1
    end.

set_open_queue(Tcb, Socket) ->
    N_syn_queue = lists:filter(fun
        (X) when X == Socket -> false;
        (_) -> true
    end, Tcb#tcb.syn_queue),
    case queue:out_r(Tcb#tcb.obs) of
        {{value, O}, New_Q} ->
            gen_server:reply(O, {ok, Socket}),
            Tcb#tcb{syn_queue = N_syn_queue, obs = New_Q};
        {empty, _} ->
            Tcb#tcb{syn_queue = N_syn_queue,
                    open_queue = queue:cons(Socket, Tcb#tcb.open_queue)}
    end.


%%%%%%%%%%%%%%%%%%%%% Observer add and remove %%%%%%%%%%%%%%%%%%%%%%%

%remove(listener_queue, From, Tcb) ->
%    Tcb#tcb{obs = queue:filter(fun(O) -> O =/= From end, Tcb#tcb.obs)}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

init_tcb(Rt_Ip, Rt_Port, State) ->
    <<Iss:32>> = crypto:strong_rand_bytes(4),
    #tcb{
	  rt_port = Rt_Port,
	  rt_ip   = Rt_Ip,
	  state   = State,
	  snd_una = Iss,
	  snd_nxt = Iss,
	  iss     = Iss
	}.

get_data(Buf, Size, Acc) ->
    case catch queue:last(Buf) of
	{'EXIT', _} ->
	    {Acc, Buf};
	Data ->
	    if Size == 0; size(Data) == Size ->
		    {<<Acc/binary, Data/binary>>, queue:init(Buf)};
	       size(Data) > Size ->
		    <<Partial_Data:Size/binary, Rem/binary>> = Data,
		    {<<Acc/binary, Partial_Data/binary>>,
		     queue:snoc((queue:init(Buf)), Rem)};
	       true ->
		    get_data(queue:init(Buf), Size - size(Data), 
			     <<Acc/binary, Data/binary>>)
	    end
    end.

get_available_window(Tcb) ->
    min(Tcb#tcb.snd_wnd, round(Tcb#tcb.cwnd)) -
	seq:sub(Tcb#tcb.snd_nxt, Tcb#tcb.snd_una).

get_data_size(Tcb) ->
    Queued = if
        Tcb#tcb.state == syn_sent orelse Tcb#tcb.state == syn_rcvd -> 1 + Tcb#tcb.sbsize;
        Tcb#tcb.send_fin > 0 andalso Tcb#tcb.snd_nxt /= Tcb#tcb.snd_max -> 1 + Tcb#tcb.sbsize;
        true -> Tcb#tcb.sbsize
    end,
    max(0, min(get_available_window(Tcb), min(Tcb#tcb.smss, Queued))).

set_rtimer(Tcb) ->
    case queue:is_empty(Tcb#tcb.rqueue) of
	 true -> erlang:send_after(round(Tcb#tcb.rto), self(), {event, rto});
	 false -> Tcb#tcb.rtimer
    end.

update_rqueue(Tcb, Snd_Una) ->
    update_rqueue_1(Tcb, Tcb#tcb.rqueue, Snd_Una).

update_rqueue_1(Tcb, Queue, Snd_Una) ->
    case catch queue:last(Queue) of
	{'EXIT', _} -> % Queue empty => Everything acked. Turn off timer
	    catch erlang:cancel_timer(Tcb#tcb.rtimer),
	    {Queue, ok};
	{Last_Seq, _} ->
	    case seq:le(Last_Seq, Snd_Una) of
		true -> % Unqueue Packet
		    update_rqueue_1(Tcb, queue:init(Queue), Snd_Una);
		false -> % This packet is not acked -> Restart timer
		    erlang:cancel_timer(Tcb#tcb.rtimer),
		    Rto = round(Tcb#tcb.rto),
		    Timer = erlang:send_after(Rto, self(), {event, rto}),
		    {Queue, Timer}
	    end
    end.

% handle incoming packets depending on state
in(_, Tcb, Pkt) when Pkt#pkt.is_rst == 1 ->
    % RFC 5961 compliant RST handling
    SeqDiff = seq:sub(Pkt#pkt.seq, Tcb#tcb.rcv_nxt),
    if
        % ignore reset that matched to listen socket
        Tcb#tcb.state == listen -> Tcb;
        % close connection if sequence == rcv_nxt
        Pkt#pkt.seq == Tcb#tcb.rcv_nxt -> set_state(Tcb, closed);
        % send ack only packet (should induce RST that matches)
        % TODO: trigger keep-alive, because some peers won't send us a working RST
        SeqDiff < Tcb#tcb.rcv_wnd ->
            io:format("reset challenge ack~n", []),
            Tcb#tcb{send_type = ack};
        true -> Tcb
    end;

in(listen, Tcb, Pkt) ->
    case {Pkt#pkt.is_ack, Pkt#pkt.is_syn, Pkt#pkt.is_fin} of
        % ignore silly packets
	{0, 0, _} -> Tcb;
	{0, 1, 1} -> Tcb;
	% TODO: Send an rst to an ack packet
	{1, _, _} -> Tcb;
	{0, 1, 0} ->
	    Socket = {Pkt#pkt.dip, Pkt#pkt.dport,
	              Pkt#pkt.sip, Pkt#pkt.sport},
	    case tcp_pool:get(Socket) of
		{ok, Conn} ->
		     % duplicate syn, arrived in listen backlock before syn_rcvd
		     % socket was registered, forward for processing
		     gen_server:cast(Conn, {in, Pkt}),
		     Tcb;
		_ ->
		    % TODO: syn_queue scalability (ala syncache/syncookie,
		    % also a big list of in progress connections will be bad
		    Mss = case Pkt#pkt.mss of
		        -1 -> ?DEFAULT_SMSS;
		        N when N > Tcb#tcb.rmss -> Tcb#tcb.rmss;
		        N -> N
		    end,

		    N_Tcb = clone(Tcb, Socket, Pkt#pkt.seq, Mss),
		    tcp_pool:add({connect, Socket}, N_Tcb),
		    Tcb#tcb{syn_queue = [N_Tcb | Tcb#tcb.syn_queue]}
	    end
    end;
    
in(syn_sent, Tcb, Pkt) ->
    case {Pkt#pkt.is_ack, Pkt#pkt.is_syn, Pkt#pkt.is_fin} of
        {1, 1, 0} when Pkt#pkt.ack == Tcb#tcb.snd_max ->
	    Tcb1 = case Pkt#pkt.mss of
		-1 -> Tcb#tcb{rcv_nxt = seq:add(Pkt#pkt.seq, 1), irs = Pkt#pkt.seq};
		Smss -> Tcb#tcb{rcv_nxt = seq:add(Pkt#pkt.seq, 1), irs = Pkt#pkt.seq, smss = Smss, cwnd = 2*Smss} % TODO: initial congestion window?
	    end,
	    Tcb2 = set_snd_wnd(Tcb1, {Pkt#pkt.window, Pkt#pkt.seq, Pkt#pkt.ack}),
	    {ok, newack, Tcb3} = check_ack(Tcb2, Pkt),
	    set_state(Tcb3#tcb{send_type = any}, established);
	{0, 1, 0} -> % simultaneous syn
	    Tcb1 = case Pkt#pkt.mss of
		-1 -> Tcb#tcb{rcv_nxt = seq:add(Pkt#pkt.seq, 1), irs = Pkt#pkt.seq};
		Smss -> Tcb#tcb{rcv_nxt = seq:add(Pkt#pkt.seq, 1), irs = Pkt#pkt.seq, smss = Smss, cwnd = 2*Smss} % TODO: initial congestion window?
	    end,
	    set_state(Tcb1#tcb{send_type = ack}, syn_rcvd);
	_ -> Tcb % TODO send RST probably
    end;

in(State, Tcb, Pkt) -> process_packet(Tcb, Pkt, State).


check_ack(Tcb, Pkt) ->
    {Snd_Una, Snd_Nxt} = {Tcb#tcb.snd_una, Tcb#tcb.snd_max},
    case Pkt#pkt.is_ack of
	1 ->
	    Dup_Ack = seq:le(Pkt#pkt.ack, Snd_Una),
	    New_Data = (not Dup_Ack) andalso seq:le(Pkt#pkt.ack, Snd_Nxt),
	    if
		New_Data ->
		    {ok, newack, set_snd_una(Tcb, Pkt#pkt.ack)};
		true ->
		    if Dup_Ack ->
			{ok, oldack};
		    true ->
		        io:format("bad ack Snd_Una ~B, Snd_Nxt ~B, Ack ~B~n", [Snd_Una, Snd_Nxt, Pkt#pkt.ack]),
			{error, badack}
		    end
	    end;
	0 ->
	    {ok, noack}
    end.

process_packet(Tcb, Pkt, State) ->
    case pkt_data(Tcb, Pkt) of
        % sequence acceptable
	{ok, Data} -> process_ack(Tcb, Pkt, State, Data);
	{error, _} ->
	    io:format("seq challenge ack~w~w~w~n", [self(), Tcb, Pkt]),
	    timer:sleep(1000),
	    Tcb#tcb{send_type = ack} % challenge ack
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%% HELPER FUNCTIONS %%%%%%%%%%%%%%%%%%%%%

process_ack(Tcb, Pkt, State, Data) ->
    if Pkt#pkt.is_syn == 1 -> Tcb#tcb{send_type = ack};
    true -> case check_ack(Tcb, Pkt) of
	{ok, newack, Tcb1} ->
	    Tcb2 = process_window(Tcb1, Pkt),
	    Tcb3 = process_data(Tcb2, Pkt, State, Data),
	    newack_action(State, Tcb3);
	{ok, oldack} ->
	    Tcb1 = process_window(Tcb, Pkt),
	    process_data(Tcb1, Pkt, State, Data);
	{ok, noack} -> Tcb; % Packet should have an ack, so drop
	{error, badack} ->
	    io:format("badack challenge ack~n", []),
            Tcb#tcb{send_type = ack} % challenge ACK
        end
    end.

process_window(Tcb, Pkt) ->
    set_snd_wnd(Tcb, {Pkt#pkt.window, Pkt#pkt.seq, Pkt#pkt.ack}).

process_data(Tcb, Pkt, State, Data) ->
    case seq:lt(Tcb#tcb.rcv_nxt, Pkt#pkt.seq) of
        true ->  % Out of order data
            NewOut = out_order:merge_data(Tcb#tcb.out_order, {Pkt#pkt.seq, Pkt#pkt.is_fin, Data}),
            Tcb#tcb{out_order = NewOut, send_type = any};
        false ->
            case data_action(State) of
                ok ->
                    Tcb1 = set_rdata(Tcb, Data),
                    check_out_order(Tcb1, State, size(Data), Pkt);
                _ -> Tcb
            end
    end.

check_out_order(Tcb, State, Data_Size, Pkt) ->
    case out_order:get_out_order(Tcb#tcb.out_order, Tcb#tcb.rcv_nxt) of
	{{Lseq, Is_Fin, Data}, T} ->
	    process_data(Tcb#tcb{out_order = T}, #pkt{seq = Lseq, is_fin = Is_Fin }, State, Data);
	_ ->
	    process_fin(Tcb, Pkt#pkt.is_fin, State,
			del_ack, Data_Size)
    end.

process_fin(Tcb, Is_Fin, State, Ack, Data_Size) ->
  case Is_Fin of
      1 -> fin_action(State, Tcb);
      0 ->
	  case Ack of
	      ack -> Tcb#tcb{send_type = any};
	      del_ack -> set_del_ack(Tcb, Data_Size);
	      no_ack -> Tcb
	  end
  end.

pkt_data(Tcb, Pkt) ->
    Seg_Len = size(Pkt#pkt.data),
    {Rcv_Nxt, Rcv_Wnd} = {Tcb#tcb.rcv_nxt, Tcb#tcb.rcv_wnd},
    if   % 99% of packets should fall in the first condition
	(Pkt#pkt.seq == Rcv_Nxt) and (Seg_Len =< Rcv_Wnd) ->
	    {ok, Pkt#pkt.data};
	true ->
	    case {Seg_Len, Rcv_Wnd} of
		{_, 0} -> % Check if the sequence number is the one
		    case Pkt#pkt.seq == Rcv_Nxt of
			true ->
			    {ok, <<>>};
			false ->
			    {error, badseq}
		    end;
		{0, _} -> % Check if sequence number is in window
		    case seq:le(Rcv_Nxt, Pkt#pkt.seq) andalso
			seq:lt(Pkt#pkt.seq, seq:add(Rcv_Nxt, Rcv_Wnd)) of
			true ->
			    {ok, <<>>};
			false ->
			    {error, badseq}
		    end;
		{_, _} -> % Check that it either starts or ends in the window
		    trim_packet(Pkt, Rcv_Nxt, Rcv_Wnd, Seg_Len)
	    end
    end.

%% Cuts data that is not in the window

trim_packet(Pkt, Rcv_Nxt, Rcv_Wnd, Seg_Len) ->
    Pkt_End = seq:add(Pkt#pkt.seq, Seg_Len),
    Wnd_End = seq:add(Rcv_Nxt, Rcv_Wnd),

    Start = seq:max(Pkt#pkt.seq, Rcv_Nxt),
    End = seq:min(Wnd_End, Pkt_End),

    case seq:gt(Start, End) of
	true ->
	    {error, badseq};
	false ->
	    Size = End - Start,
	    Off = case seq:gt(Rcv_Nxt, Pkt#pkt.seq) of
		      true ->
			  seq:sub(Rcv_Nxt, Pkt#pkt.seq);
		      false ->
			  0
		  end,
	    <<_:Off/binary,Data:Size/binary,_/binary>> = Pkt#pkt.data,
	    {ok, Data}
    end.

newack_action(closing, Tcb) ->
    if Tcb#tcb.send_fin == 2 andalso Tcb#tcb.snd_una == Tcb#tcb.snd_max ->
	set_state(Tcb, time_wait);
    true -> Tcb
    end;
newack_action(fin_wait_1, Tcb) ->
    if Tcb#tcb.send_fin == 2 andalso Tcb#tcb.snd_una == Tcb#tcb.snd_max ->
	set_state(Tcb, fin_wait_2);
    true -> Tcb
    end;
newack_action(last_ack, Tcb) ->
    % All data acked, close
    if Tcb#tcb.send_fin == 2 andalso Tcb#tcb.snd_una == Tcb#tcb.snd_max ->
        set_state(Tcb, closed);
    true -> Tcb
    end;
newack_action(syn_rcvd, Tcb) -> set_state(Tcb, established);
newack_action(_, Tcb) -> Tcb.

data_action(established) -> ok;
data_action(fin_wait_1) -> ok;
data_action(fin_wait_2) -> ok;
data_action(syn_rcvd) -> ok;
data_action(_) -> none.

fin_action(established, Tcb) ->
    set_rdata(set_state(Tcb#tcb{rcv_nxt = seq:add(Tcb#tcb.rcv_nxt, 1), send_type = any}, close_wait), <<>>);
fin_action(syn_rcvd, Tcb) ->
    set_rdata(set_state(Tcb#tcb{rcv_nxt = seq:add(Tcb#tcb.rcv_nxt, 1), send_type = any}, close_wait), <<>>);
fin_action(fin_wait_1, Tcb) ->
    if Tcb#tcb.send_fin == 2 andalso Tcb#tcb.snd_una == Tcb#tcb.snd_max ->
        set_state(Tcb#tcb{rcv_nxt = seq:add(Tcb#tcb.rcv_nxt, 1), send_type = any}, time_wait);
    true ->
        set_state(Tcb#tcb{rcv_nxt = seq:add(Tcb#tcb.rcv_nxt, 1), send_type = any}, closing)
    end;
fin_action(fin_wait_2, Tcb) ->
    set_state(Tcb#tcb{rcv_nxt = seq:add(Tcb#tcb.rcv_nxt, 1), send_type = any}, time_wait);
fin_action(_, Tcb) -> Tcb#tcb{send_type = ack}.

%%%%%%%%%%%%%%%%%%% PACKET BUILDING %%%%%%%%%%%%%%%%%%%%%%%%%

send_packet_impl(Tcb, Type) ->
    {ok, Tcb1, Pkt} = build_packet(Tcb, Type),
    send_packet_1(Tcb1, Pkt).

%send_packet(Pkt) ->
%    {Packet, Len} = build_bin_packet(Pkt),
%    ip:send(Packet, Len, tcp, Pkt#pkt.dip).

send_packet_1(Tcb, Pkt) ->
    {Bin_Packet, Len} = build_bin_packet(Tcb, Pkt),
    ip:send(Bin_Packet, Len, tcp, Pkt#pkt.dip),
    Tcb.

%    Seq_Len = size(Pkt#pkt.data)+Pkt#pkt.is_syn+Pkt#pkt.is_fin,
%    prepare_retransmit(Tcb, Pkt#pkt.seq, Seq_Len, Pkt).

%prepare_retransmit(Tcb, Snd_Nxt, Seq_Len, Packet) when Seq_Len > 0 ->
%    set_rqueue(Tcb, {seq:add(Snd_Nxt, Seq_Len), Packet});
%prepare_retransmit(Tcb, _, _, _) -> Tcb.

build_options(Options) ->
    OptBin = lists:filtermap(fun build_option/1, Options),
    O0 = << <<X/binary>> || X <- OptBin >>,
    case byte_size(O0) rem 4 of
        0 -> O0;
        P -> << O0/binary, 0:((4 - P) * 8) >>
    end.

build_option({mss, Value})->
    {true, <<2:8, 4:8, Value:16/big-integer>>};
build_option(_) ->
    false.

options_size(Options) ->
    S0 = lists:foldl(fun option_size/2, 0, Options),
    case S0 rem 4 of
        0 -> S0;
        P -> S0 + (4 - P)
    end.

option_size({mss, _}, Acc) -> Acc + 4;
option_size(_, Acc) -> Acc.

calculate_offset(Options) ->
    5 + (options_size(Options) div 4).

build_bin_packet(Tcb, Pkt) ->
    Options =
        case Pkt#pkt.is_syn of
            1 -> [{mss, Tcb#tcb.rmss}];
            0 -> []
        end,
    Offset = calculate_offset(Options),
    SPkt = Pkt#pkt{options = Options,
                   offset = Offset,
                   segment_len = (Offset * 4) + Pkt#pkt.data_size
                  },
    {Pre_Chk, Post_Chk} = build_bin_packet_1(SPkt),
    OptBin = build_options(Options),
    add_checksum(SPkt#pkt.sip, SPkt#pkt.dip, Pre_Chk, Post_Chk,
		 OptBin, SPkt#pkt.data, SPkt#pkt.data_size).

build_bin_packet_1(Pkt) ->
    {<<(Pkt#pkt.sport):16/big-integer,
     (Pkt#pkt.dport):16/big-integer,
     (Pkt#pkt.seq):32/big-integer,
     (Pkt#pkt.ack):32/big-integer,
     (Pkt#pkt.offset):4/integer,
     0:6/integer, % Reserved
     (Pkt#pkt.is_urg):1/integer,
     (Pkt#pkt.is_ack):1/integer,
     (Pkt#pkt.is_psh):1/integer,
     (Pkt#pkt.is_rst):1/integer,
     (Pkt#pkt.is_syn):1/integer,
     (Pkt#pkt.is_fin):1/integer,
     (Pkt#pkt.window):16/big-integer>>,
     <<(Pkt#pkt.urgent):16/big-integer>>}.

add_checksum(Src_Ip, Dst_Ip, Pre_Chk, Post_Chk, Options, Data, Data_Size) ->
    Checksum = packet_check:compute_checksum(Src_Ip, Dst_Ip, ?IP_PROTO_TCP,
				[Pre_Chk, Post_Chk, Options, Data],
				20+size(Options) + Data_Size),
    {[Pre_Chk, <<Checksum:16/big-integer>>, Post_Chk, Options, Data],
     20+size(Options) + Data_Size}.

% Ack, Psh, Rst, Syn, Fin, Snd_Nxt, Data

build_packet(Tcb, Type) ->
    {Is_Ack, Is_Syn} = case Tcb#tcb.state of
        syn_sent -> {0, 1};
        syn_rcvd -> {1, 1};
        _        -> {1, 0}
    end,
    {Tcb1, Data, SndNext, Is_Fin, Is_Psh} = get_sdata(Tcb, Type),
    Pkt = #pkt{sip   = Tcb1#tcb.lc_ip,
	       dip   = Tcb1#tcb.rt_ip,
               sport = Tcb1#tcb.lc_port,
	       dport = Tcb1#tcb.rt_port,
	       seq   = SndNext,
	       ack   = Tcb1#tcb.rcv_nxt,
	       is_urg= 0,
	       is_ack= Is_Ack,
	       is_psh= Is_Psh,
	       is_rst= 0,
	       is_syn= Is_Syn,
	       is_fin= Is_Fin,
	       window= Tcb1#tcb.rcv_wnd,
	       urgent= 0,
	       data = Data,
	       data_size = size(Data)},
    {ok, Tcb1, Pkt}.

%% Retransmissions

%retransmit(Tcb, Packet, Smss) when Packet#pkt.data_size =< Smss ->
%    {Bin_Packet, Len} = build_bin_packet(Tcb, Packet),
%    ip:send(Bin_Packet, Len, tcp, Packet#pkt.dip);
%retransmit(Tcb,Packet, Smss) ->
%    <<Data:Smss/binary, Rem/binary>> = Packet#pkt.data,
%    Send_Packet= Packet#pkt{data = Data, data_size = Smss},
%
%    {Bin_Packet, Len} = build_bin_packet(Tcb, Send_Packet),
%    ip:send(Bin_Packet, Len, tcp, Send_Packet#pkt.dip),
%    retransmit(Tcb, Packet#pkt{seq = seq:add(Packet#pkt.seq,Smss),
%			       data = Rem, data_size = size(Rem)}, Smss).
