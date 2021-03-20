%%%-------------------------------------------------------------------
%%% File    : tcp_input.erl
%%% Author  : Javier Paris Fernandez <javier.paris@udc.es>
%%% Description : Tcp input packet processing
%%%
%%% Created :  6 Sep 2004 by Javier Paris Fernandez <javier.paris@udc.es>
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

-module(tcp_input).

-export([check_ack/2, process_packet/3]).

-include("tcb.hrl").
-include("tcp_packet.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%% API %%%%%%%%%%%%%%%%%%%%%%%%%%%%

check_ack(Tcb, Pkt) ->
    {Snd_Una, Snd_Nxt} = {Tcb#tcb.snd_una, Tcb#tcb.snd_nxt},
    case Pkt#pkt.is_ack of
	1 ->
	    Dup_Ack = seq:le(Pkt#pkt.ack, Snd_Una),
	    New_Data = (not Dup_Ack) andalso
		       seq:le(Pkt#pkt.ack, Snd_Nxt),
	    if
		New_Data ->
		    Tcb1 = tcb:set_snd_una(Tcb, Pkt#pkt.ack),
		    {ok, newdata, Tcb1};
		true ->
		    if
			Dup_Ack ->
			    {ok, nonewdata};
			true ->
			    {error, badack}
		    end
	    end;
	0 ->
	    {ok, noack}
    end.

process_packet(Tcb, Pkt, State) ->
    case get_data(Tcb, Pkt) of
	{ok, Rcv_Nxt, Data} -> % Data acceptable
	    process_rst(Tcb, Pkt, State, Rcv_Nxt, Data);
	{error, _} -> % Sequence number not correct, just discard
	    %TODO: check logic
	    if Pkt#pkt.is_rst -> ok; %Just drop
	        true -> tcb:send_packet(Tcb, ack)
	    end
    end.

%%%%%%%%%%%%%%%%%%%%%%%%%%% HELPER FUNCTIONS %%%%%%%%%%%%%%%%%%%%%

process_rst(Tcb, Pkt, State, Rcv_Nxt, Data) ->
    if Pkt#pkt.is_rst == 1 orelse Pkt#pkt.is_syn == 1 -> tcp_con:abort_connection(Tcb);
    true -> case check_ack(Tcb, Pkt) of
	{ok, newdata, Tcb1} ->
	    Tcb2 = process_window(Tcb1, Pkt),
	    Tcb3 = process_data(Tcb2, Pkt, State, Rcv_Nxt, Data),
	    newdata_action(State, Tcb3, Pkt);
	{ok, nonewdata} ->
	    Tcb1 = process_window(Tcb, Pkt),
	    process_data(Tcb1, Pkt, State, Rcv_Nxt, Data);
	{ok, noack} -> Tcb; % Packet should have an ack, so drop
	{error, badack} -> tcb:send_packet(Tcb, ack)
        end
    end.

process_window(Tcb, Pkt) ->
    tcb:set_snd_wnd(Tcb, {Pkt#pkt.window, Pkt#pkt.seq, Pkt#pkt.ack}).

process_data(Tcb, Pkt, State, Rcv_Nxt, <<>>) ->
    process_fin(Tcb, Pkt#pkt.is_fin, Rcv_Nxt, State, no_ack, 0);
process_data(Tcb, Pkt, State, Rcv_Nxt, Data) ->
    if
	Rcv_Nxt < Pkt#pkt.seq ->  % Out of order data
	    Out_Order_Data = {Pkt#pkt.seq, Pkt#pkt.is_fin, Data},
	    out_order_action(State, Tcb, Out_Order_Data);
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
	      ack -> tcb:send_packet(Tcb, ack);
	      del_ack -> tcb:set_del_ack(Tcb, Data_Size);
	      no_ack -> Tcb
	  end
  end.

get_data(Tcb, Pkt) ->
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

newdata_action(closing, Tcb, _) ->
    if Tcb#tcb.snd_una == Tcb#tcb.snd_nxt ->
	tcb:set_state(Tcb, time_wait);
	%TODO: tcb:set_tcbdata(Tcb, twtimer, Writer);
    true -> Tcb
    end;
newdata_action(fin_wait_1, Tcb, _) ->
    if Tcb#tcb.send_fin == false andalso Tcb#tcb.snd_una == Tcb#tcb.snd_nxt ->
	tcb:set_state(Tcb, fin_wait_2);
    true -> Tcb
    end;
newdata_action(last_ack, Tcb, _) ->
    % All data acked, close
    if Tcb#tcb.send_fin == false andalso Tcb#tcb.snd_una == Tcb#tcb.snd_nxt ->
        tcb:set_state(Tcb, closed);
    true -> Tcb
    end;
newdata_action(syn_rcvd, Tcb, _) -> tcb:set_state(Tcb, established);
newdata_action(_, Tcb, _) -> Tcb.

data_action(established, Tcb, Data) -> {ok, tcb:set_rdata(Tcb, Data)};
data_action(fin_wait_1, Tcb, Data) -> {ok, tcb:set_rdata(Tcb, Data)};
data_action(fin_wait_2, Tcb, Data) -> {ok, tcb:set_rdata(Tcb, Data)};
data_action(syn_rcvd, Tcb, Data) -> {ok, tcb:set_rdata(Tcb, Data)};
data_action(_, _, _) -> none.

out_order_action(established, Tcb, Data) ->
    tcb:set_tcbdata(Tcb, out_order, Data),
    tcb:send_packet(Tcb, ack); % For fast retransmit
out_order_action(fin_wait_1, Tcb, Data) ->
    tcb:set_tcbdata(Tcb, out_order, Data),
    tcb:send_packet(Tcb, ack); % For fast retransmit
out_order_action(fin_wait_2, Tcb, Data) ->
    tcb:set_tcbdata(Tcb, out_order, Data),
    tcb:send_packet(Tcb, ack); % For fast retransmit
out_order_action(syn_rcvd, Tcb, Data) ->
    tcb:set_tcbdata(Tcb, out_order, Data),
    tcb:send_packet(Tcb, ack); % For fast retransmit
out_order_action(_, Tcb, _) -> Tcb.

fin_action(established, Tcb, Rcv_Nxt) ->
    Tcb1 = tcb:set_state(Tcb#tcb{rcv_nxt = seq:add(Rcv_Nxt, 1)}, close_wait),
    tcb:send_packet(Tcb1, ack);
fin_action(syn_rcvd, Tcb, Rcv_Nxt) ->
    Tcb1 = tcb:set_state(Tcb#tcb{rcv_nxt = seq:add(Rcv_Nxt, 1)}, close_wait),
    tcb:send_packet(Tcb1, ack);
fin_action(fin_wait_1, Tcb, Rcv_Nxt) ->
    Tcb1 = if Tcb#tcb.snd_una == Tcb#tcb.snd_nxt -> tcb:set_state(Tcb#tcb{rcv_nxt = seq:add(Rcv_Nxt, 1)}, time_wait);
        true -> tcb:set_state(Tcb#tcb{rcv_nxt = seq:add(Rcv_Nxt, 1)}, closing)
    end,
    tcb:send_packet(Tcb1, ack);
fin_action(fin_wait_2, Tcb, Rcv_Nxt) ->
    Tcb1 = tcb:set_state(Tcb#tcb{rcv_nxt = seq:add(Rcv_Nxt, 1)}, time_wait),
    tcb:send_packet(Tcb1, ack);
fin_action(_, Tcb, _) -> tcb:send_packet(Tcb, ack).
