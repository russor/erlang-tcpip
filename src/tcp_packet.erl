%%%-------------------------------------------------------------------
%%% File    : tcp_packet.erl
%%% Author  : Javier Paris Fernandez <javier.paris@udc.es>
%%% Description : Tcp Packet Parser and Generator
%%%
%%% Created : 17 Aug 2004 by Javier Paris Fernandez <javier.paris@udc.es>
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

-module(tcp_packet).

-include("tcb.hrl").
-include("tcp_packet.hrl").
-include("ip.hrl").

-import(packet_check, [check_packet/4, compute_checksum/5]).
-export([parse/3, send_packet/2, send_packet/1, find_option/3]).

-define(DEFAULT_HDLEN, 5).

%%%%%%%%%%%%%%%%%%%%%%%% API %%%%%%%%%%%%%%%%%%%%%%%%%%%

parse(Src_Ip, Dst_Ip, Packet) ->
    case check_packet(Src_Ip, Dst_Ip, ?IP_PROTO_TCP, Packet) of
	ok ->
	    parse_packet(Src_Ip, Dst_Ip, Packet);
	{error, Error} ->
	    {error, Error}
    end.

send_packet(Tcb, rto) -> % Retransmit packet
    case tcb:get_rqueue(Tcb) of
	{Tcb1, empty} -> Tcb1;
	{Tcb1, Packet} ->
	    retransmit(Tcb, Packet, Tcb#tcb.smss),
	    Tcb1
    end;

send_packet(Tcb, Type) ->
    case build_packet(Tcb, Type) of
	{error, Error} ->
	    {error, Error, Tcb};
	{ok, Tcb1, Pkt} ->
	    send_packet_1(Tcb1, Pkt)
    end.

send_packet(Pkt) ->
    {Packet, Len} = build_bin_packet(Pkt),
    ip:send(Packet, Len, tcp, Pkt#pkt.dip).

%%%%%%%%%%%%%%%%%%%% PACKET PARSING %%%%%%%%%%%%%%%%%%%%

%% Takes data from binary packet to a pkt record

parse_packet(Src_Ip, Dst_Ip, Packet) ->
    <<SPort:16/big-integer,
      DPort:16/big-integer,
      Seq:32/big-integer,
      Ack:32/big-integer,
      Off:4/big-integer,
      _:6/big-integer,
      Is_Urg:1/integer,
      Is_Ack:1/integer,
      Is_Psh:1/integer,
      Is_Rst:1/integer,
      Is_Syn:1/integer,
      Is_Fin:1/integer,
      Window:16/big-integer,
      _Checksum:16/big-integer,
      Urgent:16/big-integer,
      Rem/binary>> = Packet,
    {Options, Data} = get_options(Off, Rem),
    {ok, #pkt{
      sip   = Src_Ip,
      dip   = Dst_Ip,
      sport = SPort,
      dport = DPort,
      seq   = Seq,
      ack   = Ack,
      is_urg= Is_Urg,
      is_ack= Is_Ack,
      is_psh= Is_Psh,
      is_rst= Is_Rst,
      is_syn= Is_Syn,
      is_fin= Is_Fin,
      window= Window,
      urgent= Urgent,
      mss   = find_option(Options, mss, -1),
      options = Options,
      data  = Data,
      data_size = size(Data),
      segment_len = size(Packet),
      offset = Off
     }}.

%% Separates options and Data
find_option(Opts, Key, Default) ->
    case lists:keyfind(Key, 1, Opts) of
        false ->
            Default;
        {Key, Value} ->
            Value
    end.

get_options(Off, Rem) ->
    case Off of
        5 -> % 20 bytes, ergo no options
            {[], Rem};
	X when X > 5 ->
	    Opt_Size = (Off-5) * 4,
	    <<Options:Opt_Size/binary,Data/binary>> = Rem,
            {parse_options(Options), Data};
	_ -> % Offset point to packet ??. Should return an error
            {[], Rem}
    end.

%% Options Parser

parse_options(Bin) ->
    parse_options(Bin, []).

parse_options(<<>>, Acc) -> % Should parse more options
    Acc;
parse_options(<<0:8, _Rem/binary>>, Acc) ->
    %% EOL
    Acc;
parse_options(<<1:8, Rem/binary>>, Acc) ->
    %% NOP
    parse_options(Rem, Acc);
parse_options(<<2:8, 4:8, Smss:16/integer, Rem/binary>>, Acc) ->
    %% MSS
    parse_options(Rem, [{mss, Smss} | Acc]);
parse_options(<<19:8, 18:8, MD5:16/binary, Rem/binary>>, Acc) ->
    %% RFC2385 MD5 hash
    parse_options(Rem, [{md5, MD5} | Acc]);
parse_options(<<Kind:8, Len:8/integer, Rem/binary>>, Acc) ->
    OptLen = (Len - 2) * 8,
    <<Opt:OptLen/integer, Rem1/binary>> = Rem,
    parse_options(Rem1, [{unknown, {Kind, Opt}} | Acc]).


%%%%%%%%%%%%%%%%%%% PACKET BUILDING %%%%%%%%%%%%%%%%%%%%%%%%%

send_packet_1(Tcb, Pkt) ->
    {Bin_Packet, Len} = build_bin_packet(Tcb, Pkt),
    ip:send(Bin_Packet, Len, tcp, Pkt#pkt.dip),
    
    Seq_Len = size(Pkt#pkt.data)+Pkt#pkt.is_syn+Pkt#pkt.is_fin,
    Tcb1 = prepare_retransmit(Tcb, Pkt#pkt.seq, Seq_Len, Pkt),
    if
	(Pkt#pkt.is_syn == 1) or (Pkt#pkt.is_fin == 1) ->
	    tcb:set_snd_nxt(Tcb1, 1);
	true ->
	    Tcb1
    end.

prepare_retransmit(Tcb, Snd_Nxt, Seq_Len, Packet) when Seq_Len > 0 ->
    tcb:set_rqueue(Tcb, {seq:add(Snd_Nxt, Seq_Len), Packet});
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
    Checksum = compute_checksum(Src_Ip, Dst_Ip, ?IP_PROTO_TCP,
				[Pre_Chk, Post_Chk, Options, Data],
				20+size(Options) + Data_Size),
    {[Pre_Chk, <<Checksum:16/big-integer>>, Post_Chk, Options, Data], 
     20+size(Options) + Data_Size}.

% Ack, Psh, Rst, Syn, Fin, Snd_Nxt, Data

build_packet(Tcb, syn) -> build_packet_1(Tcb, nodata, 0, 0, 0, 1);
build_packet(Tcb, synack) -> build_packet_1(Tcb, nodata, 1, 0, 0, 1);
build_packet(Tcb, data) ->
    {ok, Tcb1, Pkt} = build_packet_1(Tcb, data, 1, 1, 0, 0),
    if 
	size(Pkt#pkt.data) == 0 andalso Pkt#pkt.is_fin == 0 ->
	    {error, nodata, Tcb1};
	true ->
	    {ok, Tcb1, Pkt}
    end;
build_packet(Tcb, ack) ->
    {ok, Tcb1, Pkt} = build_packet_1(Tcb, data, 1, 0, 0, 0),
    if
	size(Pkt#pkt.data) > 0 -> {ok, Tcb1, Pkt#pkt{is_psh=1}};
	true -> {ok, Tcb1, Pkt}
    end;
build_packet(Tcb, rst) -> build_packet_1(Tcb, nodata, 1, 0, 1, 0).

build_packet_1(Tcb, Type, Is_Ack, Is_Psh, Is_Rst, Is_Syn) ->
    {Tcb1, Data, SndNext, Is_Fin} = case Type of
	nodata -> {Tcb, <<>>, Tcb#tcb.snd_nxt, 0};
	data -> tcb:get_sdata(Tcb)
    end,
    Pkt = #pkt{sip   = Tcb1#tcb.lc_ip,
	       dip   = Tcb1#tcb.rt_ip,
               sport = Tcb1#tcb.lc_port,
	       dport = Tcb1#tcb.rt_port,
	       seq   = SndNext,
	       ack   = Tcb1#tcb.rcv_nxt,
	       is_urg= 0,
	       is_ack= Is_Ack,
	       is_psh= Is_Psh,
	       is_rst= Is_Rst,
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
