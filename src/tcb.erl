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

-export([start/3, start/2, init/2, init/3, subscribe/2, unsubscribe/2, clone/3]).
-export([handle_info/2, handle_cast/2, handle_call/3]).
-export([queue/2, set_snd_wnd/2, set_snd_una/2, set_del_ack/2, set_snd_nxt/2,
         set_rqueue/2, get_sdata/1, set_state/2, set_rdata/2, send_packet/2,
         get_rqueue/1]).

-include("tcb.hrl").
-include("tcp_packet.hrl").

-define(min(X,Y), case X < Y of true -> X; false -> Y end).
-define(max(X,Y), case X > Y of true -> X; false -> Y end).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start(listen, Port) ->
    proc_lib:spawn_link(tcb, init, [listen, Port]).

start(closed, Rt_Ip, Rt_Port) ->
    proc_lib:spawn_link(tcb, init, [closed, Rt_Ip, Rt_Port]).

clone(Tcb, Socket, Irs) ->
    Rcv_Next = seq:add(Irs, 1),
    {Rt_ip, Rt_port} = Socket,
    N_Tcb=Tcb#tcb{syn_queue=[],
		  open_queue=queue:new(),
		  rt_ip = Rt_ip, rt_port = Rt_port,
		  rcv_nxt = Rcv_Next,
		  irs = Irs, snd_wl1 = Irs, snd_wl2 = Rcv_Next,
		  state = syn_rcvd,
		  obs = self()
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
init(Tcb, _Parent) -> gen_server:enter_loop(?MODULE, [], send_packet(Tcb, synack)).

init(closed, Rt_Ip, Rt_Port) ->
    Tcb = init_tcb(Rt_Ip, Rt_Port, closed),
    gen_server:enter_loop(?MODULE, [], Tcb).

%handle_info({set, open_queue, Value, _From}, Tcb) ->
%    {New_Tcb, New_Observers} = set(Tcb, open_queue, Value),
%    {noreply, {New_Tcb, New_Observers}};

%handle_info({set, Param, Value, _From}, Tcb) ->
%    New_Tcb = set(Tcb, Observers, Param, Value),
%    {noreply, {New_Tcb, Observers}};

%handle_info({syncset, Param, Value, From}, Tcb) ->
%    New_Tcb = set(Tcb, Observers, Param, Value),
%    From ! {syncset, ok},
%    {noreply, {New_Tcb, Observers}};

%handle_info({get, Param, From}, Tcb) ->
%    New_Tcb = get(Tcb, Observers, Param, From),
%    {noreply, {New_Tcb, Observers}};

handle_info({subscribe, Param, From}, Tcb) ->
    From ! {tcb,ok},
    {noreply, add(Param, From, Tcb)};

handle_info({unsubscribe, Param, From}, Tcb) ->
    {noreply, remove(Param, From, Tcb)};

handle_info(close, Tcb) ->
    cancel_timers(Tcb),
    set(Tcb, state, closed),
    notify(Tcb, closed),
    lists:foreach(fun(S) -> etcpip_socket:close(S) end,
		  queue:to_list(Tcb#tcb.open_queue)),
    {stop, normal, {}};

handle_info({event, Message}, Tcb) -> {noreply, send_packet(Tcb, Message)};

handle_info({state, established, Socket}, Tcb) ->
    {noreply, set(Tcb, open_queue, Socket)};

handle_info({state, _State, _}, Tcb) -> % Erase them if the connection closes??
    {noreply, Tcb}.

handle_call({queue, Data}, _From, Tcb) ->
    case can_queue(Tcb#tcb.state) of
	ok -> {reply, ok, queue(Tcb, Data)};
	Error -> {reply, Error, Tcb}
    end;

handle_call({read, Bytes}, From, Tcb) ->
    State = Tcb#tcb.state,
    case read(State, Tcb) of
	ok ->
	    if Bytes == 0 orelse Tcb#tcb.rbsize > 0 ->
		Size = ?min(Bytes, Tcb#tcb.rbsize),
		{Data, Rem} = get_data(Tcb#tcb.rbuf, Size, <<>>),
		New_Size = Tcb#tcb.rbsize - Size,
		Free_Buf = ?max(Tcb#tcb.maxrbsize-New_Size, 0),
		Rcv_Wnd = ?min(?TCP_MAX_WINDOW, Free_Buf),

		NewTcb = Tcb#tcb{rbuf=Rem, rbsize=New_Size, rcv_wnd = Rcv_Wnd},
		{reply, Data, NewTcb};
	    true ->
		{noreply, Tcb#tcb{obs = {From, Bytes}}}
	    end;
	{error, Error} ->
	    {error, Error}
    end;

handle_call(close, _From, Tcb) ->
    {reply, ok, send_packet(Tcb, fin)}.

handle_cast({in, Pkt}, Tcb) -> {noreply, in(Tcb#tcb.state, Tcb, Pkt)}.

%%%%%%%%%%%%%%%%%%%%%%  GET DATA FUNCTIONS %%%%%%%%%%%%%%%%%%%
get_sdata(Tcb) ->
    Size = get_data_size(Tcb),
    if
	Size > 0 ->
	    {Data, Rem} = get_data(Tcb#tcb.sbuf, Size, <<>>),
	    if
		Tcb#tcb.dack_timer == -1 -> ok;
		true -> erlang:cancel_timer(Tcb#tcb.dack_timer)
	    end,
	    SndNext = Tcb#tcb.snd_nxt,
	    Sbsize = (Tcb#tcb.sbsize - size(Data)),
	    {Fin, SendFin} = if
		Sbsize == 0 andalso Tcb#tcb.send_fin -> {1, false};
		true -> {0, Tcb#tcb.send_fin}
	    end,
	    {Tcb#tcb{sbuf       = Rem,
                     sbsize     = Sbsize,
                     snd_nxt    = seq:add(Tcb#tcb.snd_nxt, size(Data) + Fin),
                     dack_timer = -1,
                     dack_data  = 0,
                     send_fin   = SendFin},
	     Data, SndNext, Fin};
       true ->
	    {Tcb, <<>>, Tcb#tcb.snd_nxt, 0}
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

get(Tcb, _, reader, From) ->
%    From ! {tcbdata, Tcb#tcb.reader},
    Tcb;
get(Tcb, _, writer, From) ->
%    From ! {tcbdata, Tcb#tcb.writer},
    Tcb;
get(Tcb, _, socket, From) ->
    
    From ! {tcbdata, {Tcb#tcb.lc_ip, Tcb#tcb.lc_port,
		      Tcb#tcb.rt_ip, Tcb#tcb.rt_port,
		      Tcb#tcb.rcv_nxt, Tcb#tcb.rcv_wnd}},
    Tcb;
get(Tcb, _, state, From) ->
    From ! {tcbdata, Tcb#tcb.state},
    Tcb;
get(Tcb, _, sbufsize, From) ->
    From ! {tcbdata, Tcb#tcb.sbsize},
    Tcb;
get(Tcb, _, maxsbufsize, From) ->
    From ! {tcbdata, Tcb#tcb.maxsbsize},
    Tcb;
get(Tcb, _, data_available, From) ->
    From ! {tcbdata, get_data_size(Tcb)},
    Tcb;
get(Tcb, _, rbufsize, From) ->
    From ! {tcbdata, Tcb#tcb.rbsize},
    Tcb;
get(Tcb, _, maxrbufsize, From) ->
    From ! {tcbdata, Tcb#tcb.maxrbsize},
    Tcb;
get(Tcb, _, cw_ss, From) ->
    From ! {tcbdata, {Tcb#tcb.cwnd, Tcb#tcb.ssthr}},
    Tcb; 
get(Tcb, _, rmss, From) ->
    From ! {tcbdata, Tcb#tcb.rmss},
    Tcb;
get(Tcb, _, smss, From) ->
    From ! {tcbdata, Tcb#tcb.smss},
    Tcb;
get(Tcb, _, snd, From) ->
    From ! {tcbdata, {Tcb#tcb.snd_una, Tcb#tcb.snd_nxt,
		      Tcb#tcb.snd_wnd, Tcb#tcb.snd_up}},
	Tcb;
get(Tcb, _, rto, From) ->
    From ! {tcbdata, {Tcb#tcb.rto, Tcb#tcb.rtcount,
		      Tcb#tcb.srtt, Tcb#tcb.rttvar}},
    Tcb;
get(Tcb, _, sndwl, From) ->
    From ! {tcbdata, {Tcb#tcb.snd_wl1, Tcb#tcb.snd_wl2}},
    Tcb;
get(Tcb, _, iss, From) ->
    From ! {tcbdata, Tcb#tcb.iss},
    Tcb;
get(Tcb, _, rcv, From) ->
    From ! {tcbdata, {Tcb#tcb.rcv_nxt, Tcb#tcb.rcv_wnd,
		      Tcb#tcb.rcv_up}},
    Tcb;
get(Tcb, _, irs, From) ->
    From ! {tcbdata, Tcb#tcb.irs},
    Tcb;
get(Tcb, _, out_order, From) ->
    {Element, New_List} = out_order:get_out_order(Tcb#tcb.out_order, 
						  Tcb#tcb.rcv_nxt),
    From ! {tcbdata, Element},
    Tcb#tcb{out_order = New_List};
get(Tcb, _, open_queue, From) ->
    case queue:out_r(Tcb#tcb.open_queue) of
	{empty, _} ->
	    From ! {tcbdata, empty},
	    Tcb;
	{{value, Socket}, Q2} ->
	    From ! {tcbdata, Socket},
	    Tcb#tcb{open_queue = Q2}
    end.

%%%%%%%%%%%%%%%%%%%%%%%%% Set Data Functions %%%%%%%%%%%%%%%%%%%%%%%%%%%

queue(Tcb, Data) ->
    Sbuf = queue:cons(Data, Tcb#tcb.sbuf),
    Tcb1 = Tcb#tcb{sbuf = Sbuf, sbsize = Tcb#tcb.sbsize + size(Data)},
    case get_data_size(Tcb1) of
	0 -> Tcb1;
	_ -> send_packet(Tcb1, data)
    end.
set_snd_wnd(Tcb, {Wnd, Seq, Ack}) ->
    case seq:lt(Tcb#tcb.snd_wl1, Seq) orelse
	((Tcb#tcb.snd_wl1 == Seq) andalso seq:le(Tcb#tcb.snd_wl2, Ack)) of
    true ->
        Tcb1 = Tcb#tcb{snd_wnd = Wnd, snd_wl1 = Seq, snd_wl2= Ack},
	case get_data_size(Tcb1) of
	    0 -> Tcb1;
	    _ -> send_packet(Tcb1, data)
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
    Tcb#tcb{snd_una = Snd_Una, rqueue = Queue, rtimer=Timer,
	    rtcount = 0, cwnd = Cwnd, ssthr = Ssthr, rttimer = Rttimer,
	    rtseq = RtSeq, rto = Rto, srtt = Srtt, rttvar = Rttvar}.

set_del_ack(Tcb, Size) ->
    case Tcb#tcb.dack_timer of
	    -1 ->
		Timer = erlang:send_after(?DEFAULT_DACK_TIME, self(), {event, ack}),
		%io:format("Setting ack Timer for ~w ~w ~w~n",[?DEFAULT_DACK_TIME, Tcb#tcb.writer, ack]),
		Tcb#tcb{dack_timer = Timer, dack_data = Size};
	Timer ->
	    New_Size = Tcb#tcb.dack_data + Size,
	    if
		New_Size >= (2*Tcb#tcb.rmss) ->
		    Tcb1 = send_packet(Tcb, ack),
		    catch erlang:cancel_timer(Timer),
		    Tcb1#tcb{dack_timer = -1, dack_data = 0};
		true ->
		    Tcb#tcb{dack_data = New_Size}
	    end
    end.

set_snd_nxt(Tcb, Inc) ->
    {Timer, Seq} = etcpip_rtt:set_rttimer(Tcb#tcb.rttimer, Tcb#tcb.snd_nxt,
				   Tcb#tcb.rtseq),
    Tcb#tcb{snd_nxt = seq:add(Tcb#tcb.snd_nxt, Inc),
	    rttimer = Timer, rtseq = Seq}.

set_rqueue(Tcb, Data) ->
    Timer = set_rtimer(Tcb),
    Q = queue:cons(Data, Tcb#tcb.rqueue),
    Tcb#tcb{rqueue= Q, rtimer = Timer}.

set_state(Tcb = #tcb{obs = Listener}, established) when Listener /= {}->
    Listener ! {state, established, self()},
    Tcb#tcb{state = established, obs = {}};

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
	    {reply, Reply, Tcb2} = handle_call({read, Bytes}, From, Tcb1),
	    gen_server:reply(From, Reply),
	    Tcb2
    end.

set(Tcb, cwnd, Cwnd) ->
    Tcb#tcb{cwnd = Cwnd};
set(Tcb, ssthr, Ssthr) ->
    Tcb#tcb{ssthr = Ssthr};
set(Tcb, rmss, Mss) ->
    Tcb#tcb{rmss = Mss};
set(Tcb, smss, Mss) -> % Either Starting, or PMTU. Force a retransmit.
    case catch queue:last(Tcb#tcb.rqueue) of
	{'EXIT', _} ->
	    ok;
	{_, Packet} ->
	    if Packet#pkt.data_size > Mss -> send_packet(Tcb, rto);
	       true -> ok
	    end
    end,
    Tcb#tcb{smss = Mss};
set(Tcb, rto, {Rto, Srtt, Rttvar}) ->
    Tcb#tcb{rto = Rto, srtt = Srtt, rttvar = Rttvar};
set(Tcb, rtcount, Rttcount) ->
    Tcb#tcb{rtcount = Rttcount};
set(Tcb, rcv_nxt, Nxt) ->
    Tcb#tcb{rcv_nxt = Nxt};
set(Tcb, rcv_wnd, Wnd) ->
    Tcb#tcb{rcv_wnd = Wnd};
set(Tcb, irs, Irs) ->
    Tcb#tcb{irs = Irs, snd_wl1 = Irs, snd_wl2 = Tcb#tcb.snd_nxt};
set(Tcb, twtimer, Proc) ->
    catch erlang:cancel_timer(Tcb#tcb.twtimer),
    Timer = erlang:send_after(?DEFAULT_MSL*2, Proc, time_wait),
    Tcb#tcb{twtimer = Timer};
set(Tcb, out_order, Data) ->
    New_List = out_order:merge_data(Tcb#tcb.out_order, Data),
    Tcb#tcb{out_order = New_List};
set(Tcb, open_queue, Socket) ->
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
notify(Tcb, closed) ->
    lists:foreach(fun(O) -> O ! {open_con, closed} end, queue:to_list(Tcb#tcb.obs)).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

init_tcb(Rt_Ip, Rt_Port, State) ->
    Iss = iss:get_iss(),
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
        Tcb#tcb.send_fin -> 1 + Tcb#tcb.sbsize;
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

% Cancels all the timers
cancel_timers(Tcb) ->
    catch erlang:cancel_timer(Tcb#tcb.rtimer),
    catch erlang:cancel_timer(Tcb#tcb.twtimer).

% per state can we read
read(close_wait, Tcb) ->
    case Tcb#tcb.rbsize of
	0 -> {error, connection_closing};
	_ -> ok
    end;
read(closing, _) -> {error, connection_closing};
read(established, _) -> ok;
read(fin_wait_1, _) -> ok;
read(fin_wait_2,_) -> ok;
read(last_ack, _) -> {error, connection_closing};
read(listen, _) -> {error, no_connection};
read(syn_rcvd, _) -> ok;
read(syn_sent, _) -> ok;
read(time_wait, _) -> {error, connection_closing}.

% handle incoming packets depending on state

in(listen, Tcb, Pkt) ->
    case {Pkt#pkt.is_rst, Pkt#pkt.is_ack, Pkt#pkt.is_syn} of
	{1, _, _} -> Tcb; % Discard rsts
	{0, 1, _} -> Tcb; % TODO: Send an rst to an ack packet
	{0, 0, 0} -> Tcb;
	{0, 0, 1} ->
	    N_Tcb = clone(Tcb, {Pkt#pkt.sip, Pkt#pkt.sport}, Pkt#pkt.seq),

	    Socket = {Pkt#pkt.dip, Pkt#pkt.dport,
		      Pkt#pkt.sip, Pkt#pkt.sport},
	    % TODO: handle race condition here; duplicate SYN could be in listen socket mailbox
	    % would lead to two TCB processes on the same tcp 4-tuple; and therefore sadness
	    tcp_pool:add({connect, Socket}, N_Tcb),

	    Tcb#tcb{syn_queue = [N_Tcb | Tcb#tcb.syn_queue]}
    end;
in(syn_sent, Tcb, Pkt) ->
    case tcp_input:check_ack(Tcb, Pkt) of
	{ok, nonewdata} -> send_packet(Tcb, rst);
	{error, badack} -> send_packet(Tcb, rst);
	{ok, newdata, Tcb1} -> recv_1(Tcb1, Pkt, newdata);
	{ok, noack} -> recv_1(Tcb, Pkt, noack)
    end;
in(time_wait, Tcb, Pkt) ->
    %TODO tcb:set_tcbdata(Tcb, twtimer, Writer),
    tcp_input:process_packet(Tcb, Pkt, time_wait);
in(State, Tcb, Pkt) -> tcp_input:process_packet(Tcb, Pkt, State).

recv_1(Tcb, Pkt, Ack_State) ->
    case {Pkt#pkt.is_rst, Pkt#pkt.is_syn} of
	{1, _} when Ack_State == newdata -> tcp_con:abort(Tcb, connection_reset);
	{1, _} -> Tcb;
	{0, 0} -> Tcb;
	{0, 1} -> % connection established!
	    Tcb1 = Tcb#tcb{rcv_nxt = seq:add(Pkt#pkt.seq, 1), irs = Pkt#pkt.seq},
	    case Ack_State of
		newdata ->
		    Tcb2 = case Pkt#pkt.mss of
			-1 -> Tcb1;
			Smss -> Tcb1#tcb{smss = Smss, cwnd = 2*Smss} % TODO: initial congestion window?
		    end,
		    Tcb3 = set_snd_wnd(Tcb2, {Pkt#pkt.window, Pkt#pkt.seq, Pkt#pkt.ack}),
		    Tcb4 = send_packet(Tcb3, ack),
		    set_state(Tcb4, established);
		noack -> send_packet(set_state(Tcb1, syn_received), synack)
	    end
    end.

can_queue(close_wait) -> ok;
can_queue(closing) -> {error, connection_closing};
can_queue(established) -> ok;
can_queue(fin_wait_1) -> {error, connection_closing};
can_queue(fin_wait_2) -> {error, connection_closing};
can_queue(last_ack) -> {error, connection_closing};
can_queue(listen) -> {error, no_connection};
can_queue(syn_sent) -> ok;
can_queue(syn_rcvd) -> ok;
can_queue(time_wait) -> {error, connection_closing};
can_queue(closed) -> {error, connection_closed}.

send_packet(Tcb, Type) -> state_send(Tcb#tcb.state, Tcb, Type).

state_send(close_wait, Tcb, ack) -> tcp_packet:send_packet(Tcb, ack);
state_send(close_wait, Tcb, data) -> tcp_packet:send_packet(Tcb, data);
state_send(close_wait, Tcb, fin) ->
    if Tcb#tcb.sbsize == 0 -> tcp_packet:send_packet(set_state(Tcb#tcb{send_fin = true}, last_ack), data);
    true -> set_state(Tcb#tcb{send_fin = true}, last_ack)
    end;
state_send(close_wait, Tcb, rto) -> tcp_packet:send_packet(Tcb, rto);

state_send(closing, Tcb, ack) -> tcp_packet:send_packet(Tcb, ack);
state_send(closing, Tcb, rto) -> tcp_packet:send_packet(Tcb, rto);

state_send(established, Tcb, ack) -> tcp_packet:send_packet(Tcb, ack);
state_send(established, Tcb, data) -> tcp_packet:send_packet(Tcb, data);
state_send(established, Tcb, fin) ->
    if Tcb#tcb.sbsize == 0 -> tcp_packet:send_packet(set_state(Tcb#tcb{send_fin = true}, fin_wait_1), data);
    true -> set_state(Tcb#tcb{send_fin = true}, fin_wait_1)
    end;
state_send(established, Tcb, rto) -> tcp_packet:send_packet(Tcb, rto);

state_send(fin_wait_1, Tcb, ack) -> tcp_packet:send_packet(Tcb, ack);
state_send(fin_wait_1, Tcb, data) -> tcp_packet:send_packet(Tcb, data);
state_send(fin_wait_1, Tcb, rto) -> tcp_packet:send_packet(Tcb, rto);

state_send(fin_wait_2, Tcb, ack) -> tcp_packet:send_packet(Tcb, ack);
state_send(fin_wait_2, Tcb, rto) -> tcp_packet:send_packet(Tcb, rto);

state_send(last_ack, Tcb, data) -> tcp_packet:send_packet(Tcb, data);
state_send(last_ack, Tcb, rto) -> tcp_packet:send_packet(Tcb, rto);

state_send(listen, Tcb, fin) -> tcp_con:close_connection(Tcb);

state_send(syn_rcvd, Tcb, synack) -> tcp_packet:send_packet(Tcb, synack);
state_send(syn_rcvd, Tcb, rto) -> tcp_packet:send_packet(Tcb, rto);

state_send(syn_sent, Tcb, ack) -> tcp_packet:send_packet(Tcb, ack);
state_send(syn_sent, Tcb, synack) -> tcp_packet:send_packet(Tcb, synack);
state_send(syn_sent, Tcb, rto) -> tcp_packet:send_packet(Tcb, rto);

state_send(time_wait, Tcb, ack) -> tcp_packet:send_packet(Tcb, ack);
state_send(time_wait, Tcb, time_wait) -> tcp_con:close_connection(Tcb).
