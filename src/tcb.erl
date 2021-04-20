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

-export([start/3, start/2, init/2, init/3, subscribe/2, unsubscribe/2]).
-export([handle_info/2, handle_cast/2, handle_call/3]).
-export([set_snd_wnd/2, set_snd_una/2, set_del_ack/2,
         set_rqueue/2, set_state/2,
         get_rqueue/1]).

-include("tcb.hrl").
-include("tcp_packet.hrl").
-include("ip.hrl").

-define(min(X,Y), case X < Y of true -> X; false -> Y end).
-define(max(X,Y), case X > Y of true -> X; false -> Y end).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start(listen, Port) ->
    proc_lib:spawn_link(tcb, init, [listen, Port]).

start(closed, Rt_Ip, Rt_Port) ->
    proc_lib:spawn_link(tcb, init, [closed, Rt_Ip, Rt_Port]).

clone(Tcb, Socket, Irs, Mss) ->
    Rcv_Next = seq:add(Irs, 1),
    {Lc_ip, _Lc_port, Rt_ip, Rt_port} = Socket,
    Iss = crypto:rand_uniform(0, 4294967296),
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

subscribe(Tcb, Attr) ->
    Tcb ! {subscribe, Attr, self()},
    receive
	{tcb, ok} ->
	    ok
    end.

unsubscribe(Tcb, Attr) ->
    Tcb ! {unsubscribe, Attr, self()}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

init(listen, Lc_Port) ->
    Tcb = init_tcb(-1, -1, listen),
    {ok, Lc_Ip, Lc_Port} = tcp_pool:add({local, Lc_Port}, self()),
    Tcb1 = Tcb#tcb{lc_ip = Lc_Ip, lc_port = Lc_Port},
    gen_server:enter_loop(?MODULE, [], Tcb1);

% from clone in listen, need to send synack
init(Tcb, _Parent) ->
    {noreply, Tcb1} = send_packet(Tcb),
    gen_server:enter_loop(?MODULE, [], Tcb1).

init(closed, Rt_Ip, Rt_Port) ->
    Tcb = init_tcb(Rt_Ip, Rt_Port, closed),
    gen_server:enter_loop(?MODULE, [], Tcb).

handle_info({subscribe, Param, From}, Tcb) ->
    From ! {tcb,ok},
    send_packet(add(Param, From, Tcb));

handle_info({unsubscribe, Param, From}, Tcb) ->
    send_packet(remove(Param, From, Tcb));

handle_info({state, established, Socket}, Tcb) ->
    send_packet(set_open_queue(Tcb, Socket));

% delayed ack trigger
handle_info({event, ack}, Tcb) ->
    send_packet(Tcb#tcb{send_type = any});

handle_info(timeout, Tcb = #tcb{state = time_wait}) ->
    send_packet(Tcb#tcb{state = closed});

handle_info({state, _State, _}, Tcb) -> % Erase them if the connection closes??
    send_packet(Tcb).

handle_call({queue, Data}, From, Tcb) ->
    {Tcb1, Reply} = queue(Tcb, Data),
    gen_server:reply(From, Reply),
    send_packet(Tcb1);

handle_call({read, Bytes}, From, Tcb) ->
    case Tcb#tcb.state of
	closing -> {reply, {error, connect_closing}, Tcb};
	last_ack -> {reply, {error, connect_closing}, Tcb};
	time_wait -> {reply, {error, connect_closing}, Tcb};
	listen -> {reply, {error, no_connection}, Tcb};
	close_wait when Tcb#tcb.rbsize == 0 -> {reply, {error, connection_closing}, Tcb};
	_ ->
	    if Bytes == 0 orelse Tcb#tcb.rbsize > 0 ->
		Size = ?min(Bytes, Tcb#tcb.rbsize),
		{Data, Rem} = get_data(Tcb#tcb.rbuf, Size, <<>>),
		New_Size = Tcb#tcb.rbsize - Size,
		Free_Buf = ?max(Tcb#tcb.maxrbsize-New_Size, 0),
		Rcv_Wnd = ?min(?TCP_MAX_WINDOW, Free_Buf),

		Tcb1 = Tcb#tcb{rbuf=Rem, rbsize=New_Size, rcv_wnd = Rcv_Wnd},
		% TODO: if window went from zero to non-zero, send packet
		gen_server:reply(From, Data),
		send_packet(Tcb1);
	    true ->
	        send_packet(Tcb#tcb{obs = {From, Bytes}})
	    end
    end;

handle_call(close, From, Tcb) ->
    NewState = case Tcb#tcb.state of
        established -> fin_wait_1;
        close_wait -> last_ack;
        listen -> closed;
        syn_rcvd -> fin_wait_1
    end,
    Tcb1 = set_state(Tcb#tcb{send_fin = 1, send_type = any, snd_max = seq:add(Tcb#tcb.snd_max, 1)}, NewState),
    gen_server:reply(From, ok),
    send_packet(Tcb1).

handle_cast({in, Pkt}, Tcb) ->
    send_packet(in(Tcb#tcb.state, Tcb, Pkt)).

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
		Rto = round(?min(?MAX_RTO, Tcb#tcb.rto * 2)),
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
    Sbuf = queue:cons(Data, Tcb#tcb.sbuf),
    Tcb1 = Tcb#tcb{sbuf = Sbuf, sbsize = Tcb#tcb.sbsize + size(Data),
                   snd_max = seq:add(Tcb#tcb.snd_max, size(Data))},
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

set_state(Tcb = #tcb{obs = Listener}, established) when Listener /= {}->
    Listener ! {state, established, self()},
    Tcb#tcb{state = established, obs = {}};

% TODO: cancel readers when transitioning to CLOSING
set_state(Tcb, State) -> Tcb#tcb{state = State}.

set_rdata(Tcb, Data) ->
    New_Data = queue:cons(Data, Tcb#tcb.rbuf),
    New_Size = Tcb#tcb.rbsize + size(Data),
    
    Rcv_Nxt = seq:add(Tcb#tcb.rcv_nxt, size(Data)),
    Free_Buf = ?max(Tcb#tcb.maxrbsize-New_Size, 0),
    Rcv_Wnd = ?min(?TCP_MAX_WINDOW, Free_Buf),
    
    Tcb1 = Tcb#tcb{rbuf = New_Data, rbsize = New_Size,
		      rcv_nxt = Rcv_Nxt, rcv_wnd = Rcv_Wnd, obs = {}},
    case Tcb#tcb.obs of
	{} -> Tcb1;
	{From, Bytes} ->
	    case handle_call({read, Bytes}, From, Tcb1) of
	        {noreply, Tcb2} -> Tcb2;
	        {noreply, Tcb2, _Timeout} -> Tcb2
	    end
    end.

set_open_queue(Tcb, Socket) ->
    N_syn_queue = lists:filter(fun (X) -> if X==Socket -> false; 
					     true -> true end end,
			       Tcb#tcb.syn_queue),
    case queue:out_r(Tcb#tcb.obs) of
        {{value, O}, New_Q} ->
            O ! {open_con, Socket},
            Tcb#tcb{syn_queue = N_syn_queue, obs = New_Q};
        {empty, _New_Q} ->
            Tcb#tcb{syn_queue = N_syn_queue,
                     open_queue = queue:cons(Socket, Tcb#tcb.open_queue)}
    end.
    

%%%%%%%%%%%%%%%%%%%%% Observer add and remove %%%%%%%%%%%%%%%%%%%%%%%

add(listener_queue, From, Tcb) ->
    Tcb1 = Tcb#tcb{obs=queue:cons(From, Tcb#tcb.obs)},
    case queue:out_r(Tcb#tcb.open_queue) of
	{empty, _} -> Tcb1;
	{{value, Socket}, Q2} ->
	    From ! {open_con, Socket},
	    Tcb#tcb{open_queue = Q2}
    end.

remove(listener_queue, From, Tcb) ->
    Tcb#tcb{obs = queue:filter(fun(O) -> O =/= From end, Tcb#tcb.obs)}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

init_tcb(Rt_Ip, Rt_Port, State) ->
    Iss = crypto:rand_uniform(0, 4294967296),
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
	    if size(Data) > Size ->
		    <<Partial_Data:Size/binary, Rem/binary>> = Data,
		    {<<Acc/binary, Partial_Data/binary>>,
		     queue:snoc((queue:init(Buf)), Rem)};
	       size(Data) == Size ->
		    {<<Acc/binary, Data/binary>>, queue:init(Buf)};
	       true ->
		    get_data(queue:init(Buf), Size - size(Data), 
			     <<Acc/binary, Data/binary>>)
	    end
    end.

get_available_window(Tcb) ->
    ?min(Tcb#tcb.snd_wnd, round(Tcb#tcb.cwnd)) -
	seq:sub(Tcb#tcb.snd_nxt, Tcb#tcb.snd_una).

get_data_size(Tcb) ->
    Queued = if
        Tcb#tcb.state == syn_sent orelse Tcb#tcb.state == syn_rcvd -> 1 + Tcb#tcb.sbsize;
        Tcb#tcb.send_fin > 0 andalso Tcb#tcb.snd_nxt /= Tcb#tcb.snd_max -> 1 + Tcb#tcb.sbsize;
        true -> Tcb#tcb.sbsize
    end,
    ?max(0, ?min(get_available_window(Tcb), ?min(Tcb#tcb.smss, Queued))).

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
        {1, 1, 0} when Pkt#pkt.ack == Tcb#tcb.snd_una ->
	    Tcb1 = case Pkt#pkt.mss of
		-1 -> Tcb#tcb{rcv_nxt = seq:add(Pkt#pkt.seq, 1), irs = Pkt#pkt.seq};
		Smss -> Tcb#tcb{rcv_nxt = seq:add(Pkt#pkt.seq, 1), irs = Pkt#pkt.seq, smss = Smss, cwnd = 2*Smss} % TODO: initial congestion window?
	    end,
	    Tcb2 = set_snd_wnd(Tcb1, {Pkt#pkt.window, Pkt#pkt.seq, Pkt#pkt.ack}),
	    set_state(Tcb2#tcb{send_type = any}, established);
	{0, 1, 0} -> % simultaneous syn
	    Tcb1 = case Pkt#pkt.mss of
		-1 -> Tcb#tcb{rcv_nxt = seq:add(Pkt#pkt.seq, 1), irs = Pkt#pkt.seq};
		Smss -> Tcb#tcb{rcv_nxt = seq:add(Pkt#pkt.seq, 1), irs = Pkt#pkt.seq, smss = Smss, cwnd = 2*Smss} % TODO: initial congestion window?
	    end,
	    set_state(Tcb1#tcb{send_type = ack}, syn_received);
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
	{ok, Rcv_Nxt, Data} -> process_ack(Tcb, Pkt, State, Rcv_Nxt, Data);
	{error, _} ->
	    io:format("seq challenge ack~w~w~n", [Tcb, Pkt]),
	    timer:sleep(1000),
	    Tcb#tcb{send_type = ack} % challenge ack
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%% HELPER FUNCTIONS %%%%%%%%%%%%%%%%%%%%%

process_ack(Tcb, Pkt, State, Rcv_Nxt, Data) ->
    if Pkt#pkt.is_syn == 1 -> Tcb#tcb{send_type = ack};
    true -> case check_ack(Tcb, Pkt) of
	{ok, newack, Tcb1} ->
	    Tcb2 = process_window(Tcb1, Pkt),
	    Tcb3 = process_data(Tcb2, Pkt, State, Rcv_Nxt, Data),
	    newack_action(State, Tcb3, Pkt);
	{ok, oldack} ->
	    Tcb1 = process_window(Tcb, Pkt),
	    process_data(Tcb1, Pkt, State, Rcv_Nxt, Data);
	{ok, noack} -> Tcb; % Packet should have an ack, so drop
	{error, badack} ->
	    io:format("badack challenge ack~n", []),
            Tcb#tcb{send_type = ack} % challenge ACK
        end
    end.

process_window(Tcb, Pkt) ->
    set_snd_wnd(Tcb, {Pkt#pkt.window, Pkt#pkt.seq, Pkt#pkt.ack}).

process_data(Tcb, Pkt, State, Rcv_Nxt, <<>>) ->
    process_fin(Tcb, Pkt#pkt.is_fin, Rcv_Nxt, State, no_ack, 0);
process_data(Tcb, Pkt, State, Rcv_Nxt, Data) ->
    if
	Rcv_Nxt < Pkt#pkt.seq ->  % Out of order data
	    Out_Order_Data = {Pkt#pkt.seq, Pkt#pkt.is_fin, Data},
	    tcb:out_order_action(State, Tcb, Out_Order_Data);
	true ->
	    case data_action(State, Tcb, Data) of
		{ok, Tcb1} ->
		    NRcv_Nxt = seq:add(Rcv_Nxt, size(Data)),
		    check_out_order(Tcb1, NRcv_Nxt, State, size(Data), Pkt);
		_ -> Tcb
	    end
    end.

check_out_order(Tcb, Rcv_Nxt, State, Data_Size, Pkt) ->
    case out_order:get_out_order(Tcb#tcb.out_order, Tcb#tcb.rcv_nxt) of
	{_, Is_Fin, Data} ->
	    State = Tcb#tcb.state,
	    data_action(State, Tcb, Data),
	    process_fin(Tcb, Is_Fin, Rcv_Nxt, State,
			ack, size(Data));
	_ ->
	    process_fin(Tcb, Pkt#pkt.is_fin, Rcv_Nxt, State,
			del_ack, Data_Size)
    end.

process_fin(Tcb, Is_Fin, Rcv_Nxt, State, Ack, Data_Size) ->
  case Is_Fin of
      1 -> fin_action(State, Tcb, Rcv_Nxt);
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
	    {ok, Rcv_Nxt, Pkt#pkt.data};
	true ->
	    case {Seg_Len, Rcv_Wnd} of
		{_, 0} -> % Check if the sequence number is the one
		    case Pkt#pkt.seq == Rcv_Nxt of
			true ->
			    {ok, Rcv_Nxt, <<>>};
			false ->
			    {error, badseq}
		    end;
		{0, _} -> % Check if sequence number is in window
		    case seq:le(Rcv_Nxt, Pkt#pkt.seq) andalso
			seq:lt(Pkt#pkt.seq, seq:add(Rcv_Nxt, Rcv_Wnd)) of
			true ->
			    {ok, Rcv_Nxt, <<>>};
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
	    {ok, Rcv_Nxt, Data}
    end.

newack_action(closing, Tcb, _) ->
    if Tcb#tcb.send_fin == 2 andalso Tcb#tcb.snd_una == Tcb#tcb.snd_max ->
	set_state(Tcb, time_wait);
    true -> Tcb
    end;
newack_action(fin_wait_1, Tcb, _) ->
    if Tcb#tcb.send_fin == 2 andalso Tcb#tcb.snd_una == Tcb#tcb.snd_max ->
	set_state(Tcb, fin_wait_2);
    true -> Tcb
    end;
newack_action(last_ack, Tcb, _) ->
    % All data acked, close
    if Tcb#tcb.send_fin == 2 andalso Tcb#tcb.snd_una == Tcb#tcb.snd_max ->
        set_state(Tcb, closed);
    true -> Tcb
    end;
newack_action(syn_rcvd, Tcb, _) -> set_state(Tcb, established);
newack_action(_, Tcb, _) -> Tcb.

data_action(established, Tcb, Data) -> {ok, set_rdata(Tcb, Data)};
data_action(fin_wait_1, Tcb, Data) -> {ok, set_rdata(Tcb, Data)};
data_action(fin_wait_2, Tcb, Data) -> {ok, set_rdata(Tcb, Data)};
data_action(syn_rcvd, Tcb, Data) -> {ok, set_rdata(Tcb, Data)};
data_action(_, _, _) -> none.

%out_order_action(established, Tcb, Data) ->
%    set_tcbdata(Tcb, out_order, Data),
%    send_packet(Tcb, ack); % For fast retransmit
%out_order_action(fin_wait_1, Tcb, Data) ->
%    set_tcbdata(Tcb, out_order, Data),
%    send_packet(Tcb, ack); % For fast retransmit
%out_order_action(fin_wait_2, Tcb, Data) ->
%    set_tcbdata(Tcb, out_order, Data),
%    send_packet(Tcb, ack); % For fast retransmit
%out_order_action(syn_rcvd, Tcb, Data) ->
%    set_tcbdata(Tcb, out_order, Data),
%    send_packet(Tcb, ack); % For fast retransmit
%out_order_action(_, Tcb, _) -> Tcb.

fin_action(established, Tcb, Rcv_Nxt) ->
    set_state(Tcb#tcb{rcv_nxt = seq:add(Rcv_Nxt, 1), send_type = any}, close_wait);
fin_action(syn_rcvd, Tcb, Rcv_Nxt) ->
    set_state(Tcb#tcb{rcv_nxt = seq:add(Rcv_Nxt, 1), send_type = any}, close_wait);
fin_action(fin_wait_1, Tcb, Rcv_Nxt) ->
    if Tcb#tcb.send_fin == 2 andalso Tcb#tcb.snd_una == Tcb#tcb.snd_max ->
        set_state(Tcb#tcb{rcv_nxt = seq:add(Rcv_Nxt, 1), send_type = any}, time_wait);
    true ->
        set_state(Tcb#tcb{rcv_nxt = seq:add(Rcv_Nxt, 1), send_type = any}, closing)
    end;
fin_action(fin_wait_2, Tcb, Rcv_Nxt) ->
    set_state(Tcb#tcb{rcv_nxt = seq:add(Rcv_Nxt, 1), send_type = any}, time_wait);
fin_action(_, Tcb, _) -> Tcb#tcb{send_type = ack}.

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

prepare_retransmit(Tcb, Snd_Nxt, Seq_Len, Packet) when Seq_Len > 0 ->
    set_rqueue(Tcb, {seq:add(Snd_Nxt, Seq_Len), Packet});
prepare_retransmit(Tcb, _, _, _) -> Tcb.

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

build_bin_packet(Pkt) ->
    {Pre_Chk, Post_Chk} = build_bin_packet_1(Pkt),
    add_checksum(Pkt#pkt.sip, Pkt#pkt.dip, Pre_Chk, Post_Chk,
		 <<>>, Pkt#pkt.data, Pkt#pkt.data_size).

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

retransmit(Tcb, Packet, Smss) when Packet#pkt.data_size =< Smss ->
    {Bin_Packet, Len} = build_bin_packet(Tcb, Packet),
    ip:send(Bin_Packet, Len, tcp, Packet#pkt.dip);
retransmit(Tcb,Packet, Smss) ->
    <<Data:Smss/binary, Rem/binary>> = Packet#pkt.data,
    Send_Packet= Packet#pkt{data = Data, data_size = Smss},
    
    {Bin_Packet, Len} = build_bin_packet(Tcb, Send_Packet),
    ip:send(Bin_Packet, Len, tcp, Send_Packet#pkt.dip),
    retransmit(Tcb, Packet#pkt{seq = seq:add(Packet#pkt.seq,Smss), 
			       data = Rem, data_size = size(Rem)}, Smss).   
