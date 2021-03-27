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

-export([parse/3]).

-define(DEFAULT_HDLEN, 5).

%%%%%%%%%%%%%%%%%%%%%%%% API %%%%%%%%%%%%%%%%%%%%%%%%%%%

parse(Src_Ip, Dst_Ip, Packet) ->
    case packet_check:check_packet(Src_Ip, Dst_Ip, ?IP_PROTO_TCP, Packet) of
	ok ->
	    parse_packet(Src_Ip, Dst_Ip, Packet);
	{error, Error} ->
	    {error, Error}
    end.


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


