%%% File        : tcp_pkt.erl
%%% Author      : Ulf Norell
%%%
%%% Copyright (C) 2016, Quviq AB
%%%
%%% ------------------------------------------------------------------------
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
%%% ------------------------------------------------------------------------
-module(tcp_pkt).

-compile(export_all).

-include("tcp_pkt.hrl").

decode(SrcIP, DstIP, Data) ->
  Packet = decode(Data),
  case verify_checksum(SrcIP, DstIP, Data) of
    false -> error({checksum_failure, SrcIP, DstIP, Packet});
    true  -> Packet
  end.

decode(Packet) ->
  <<SPort:16/big-integer,
    DPort:16/big-integer,
    Seq:32/big-integer,
    Ack:32/big-integer,
    Off:4/big-integer,
    0:6/big-integer,
    IsUrg:1/integer,
    IsAck:1/integer,
    IsPsh:1/integer,
    IsRst:1/integer,
    IsSyn:1/integer,
    IsFin:1/integer,
    Window:16/big-integer,
    Checksum:16/big-integer,
    Urgent:16/big-integer,
    Rest/binary>> = Packet,
  OptionSize = (Off - 5) * 4,
  <<Options:OptionSize/binary, Data/binary>> = Rest,
  #pkt{
    sport    = SPort,
    dport    = DPort,
    seq      = Seq,
    ack      = Ack,
    flags    = [ Flag || {Flag, 1} <- [{urg, IsUrg}, {ack, IsAck}, {psh, IsPsh},
                                       {rst, IsRst}, {syn, IsSyn}, {fin, IsFin}] ],
    window   = Window,
    checksum = Checksum,
    urgent   = Urgent,
    options  = Options,
    data     = Data }.

encode(SrcIP, DstIP, Packet) ->
  encode(add_checksum(SrcIP, DstIP, Packet)).

encode(Packet) ->
  #pkt{ sport = SPort, dport = DPort, seq = Seq
      , ack = Ack, flags = Flags
      , window = Window, checksum = Checksum
      , urgent = Urgent, options = Options0, data = Data } = Packet,
  Is = fun(Flag) ->
        case lists:member(Flag, Flags) of
          true  -> 1;
          false -> 0
        end end,
  Pad     = (4 - size(Options0) rem 4) rem 4 * 8,
  Options = <<Options0/binary, 0:Pad>>,
  Off     = 5 + size(Options) div 4,
  <<SPort:16/big-integer,
    DPort:16/big-integer,
    Seq:32/big-integer,
    Ack:32/big-integer,
    Off:4/big-integer,
    0:6/big-integer,
    (Is(urg)):1/integer,
    (Is(ack)):1/integer,
    (Is(psh)):1/integer,
    (Is(rst)):1/integer,
    (Is(syn)):1/integer,
    (Is(fin)):1/integer,
    Window:16/big-integer,
    Checksum:16/big-integer,
    Urgent:16/big-integer,
    Options/binary,
    Data/binary>>.

-define(TCP_PROTOCOL_ID, 6).

add_checksum(SrcIP, DstIP, Packet) ->
  Packet#pkt{ checksum = checksum(SrcIP, DstIP, Packet) }.

verify_checksum(SrcIP, DstIP, Bin) when is_binary(Bin) ->
  checksum(pseudo_header(SrcIP, DstIP, Bin)) == 0;
verify_checksum(SrcIP, DstIP, Pkt = #pkt{}) ->
  eqc_statem:eq(Pkt#pkt.checksum, checksum(SrcIP, DstIP, Pkt)).

pseudo_header(SrcIP, DstIP, Bin) ->
  Len = size(Bin),
  <<SrcIP:32/big-integer, DstIP:32/big-integer,
    0:8, ?TCP_PROTOCOL_ID:8, Len:16/big-integer,
    Bin/binary>>.

checksum(SrcIP, DstIP, Packet) ->
  Bin = encode(Packet#pkt{ checksum = 0 }),
  checksum(pseudo_header(SrcIP, DstIP, Bin)).

checksum(Bin) when size(Bin) rem 2 == 1 ->
  checksum(<<Bin/binary, 0>>);
checksum(Bin) ->
  N = add_carry(16, lists:sum([ Word || <<Word:16/big-integer>> <= Bin ])),
  <<Checksum:16/big-integer>> = <<(bnot N):16/big-integer>>,
  Checksum.

add_carry(W, N) when N < 1 bsl W -> N;
add_carry(W, N) ->
  B = 1 bsl W,
  add_carry(W, N rem B + N div B).

