%%%-------------------------------------------------------------------
%%% File    : packet_check.erl
%%% Author  : Javier Paris Fernandez <javier.paris@udc.es>
%%% Description : Packet checker for udp and tcp.
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

-module(packet_check).

-include("tcb.hrl").
-include("tcp_packet.hrl").
-include("ip.hrl").

-import(checksum, [checksum/1, checksum_1/1]).
-export([check_packet/4, compute_checksum/5, verify_md5/2, calculate_md5/2]).

-define(BIG_PACKET, 100).

check_packet(Src_Ip, Dst_Ip, Protocol, Packet) ->
    Size = size(Packet),
    Chk_Packet = build_checksum_packet(Src_Ip, Dst_Ip, Protocol, 
				       Packet, Size),
    R = if Size < ?BIG_PACKET ->
		checksum_1(Chk_Packet);
	   true ->
		checksum(Chk_Packet)
	end,
    case R of
	0 ->
	    ok;
	_X ->
	    {error, bad_checksum}
    end.

build_checksum_packet(Src_Ip, Dst_Ip, Protocol, Packet, Len)
    when is_binary(Src_Ip), is_binary(Dst_Ip) ->
    Pad = case Len rem 4 of   % It must have even length
	      0 -> % Even Length
		  <<>>;
	      N -> % Odd Length
		  <<0:((4-N) * 8)/integer>>
	  end,
    [<<Src_Ip/binary,
       Dst_Ip/binary,
       Len:32/big-integer,
       0:24/integer,
       Protocol:8/integer>>,
     Packet,
     Pad];
build_checksum_packet(Src_Ip, Dst_Ip, Protocol, Packet, Len) ->
    Pad = case Len rem 2 of   % It must have even length
	      0 -> % Even Length
		  <<>>;
	      1 -> % Odd Length
		  <<0:8/integer>>
	  end,
    [<<Src_Ip:32/big-integer,
       Dst_Ip:32/big-integer,
       0:8/integer,
       Protocol:8/integer,
       Len:16/big-integer>>,
     Packet,
     Pad].

compute_checksum(Src_Ip, Dst_Ip, Protocol, Packet, Size) ->
    Chk_Packet = build_checksum_packet(Src_Ip, Dst_Ip, Protocol, Packet, Size),
    checksum(Chk_Packet).

%% RFC2385 verification
verify_md5(Tcb, Pkt) ->
    Pkt_Opt = tcp_packet:find_option(Pkt#pkt.options, md5, not_present),
    Tcb_Opt = tcb:get_tcbdata(Tcb, {rfc2385_keys, Pkt#pkt.sip}),
    verify_md5(Pkt, Tcb_Opt, Pkt_Opt).

verify_md5(_Pkt, [], not_present) ->
    ok;
verify_md5(_Pkt, TO, not_present) when length(TO) > 0 ->
    md5_missing_signature;
verify_md5(_Pkt, [], _Found) ->
    md5_unexepected_signature;
verify_md5(Pkt, TO, Opt) ->
    BaseHash = calculate_base_md5(Pkt),
    verify_md5_candidates(Opt, BaseHash, TO).

verify_md5_candidates(_Found, _BaseHash, []) ->
    %% None of the options gave a valid signature.
    md5_bad_signature;
verify_md5_candidates(Found, BaseHash, [{_I, Key} | Rem]) ->
    %% Update the base hash with our test key and check...
    C1 = crypto:hash_update(BaseHash, Key),
    Hash = crypto:hash_final(C1),
    case Hash =:= Found of
        true -> ok;
        _ -> %% Else continue on with remaining candidates
            verify_md5_candidates(Found, BaseHash, Rem)
    end.

%% Partial MD5 of the packet - just need to add the 'key' (which is
%% done when iterating the possible keys for a given connection
calculate_base_md5(Pkt) ->
    Pseudo_Header =
        <<(Pkt#pkt.sip):32/big-integer,
          (Pkt#pkt.dip):32/big-integer,
          (?IP_PROTO_TCP):16/big-integer,
          (Pkt#pkt.segment_len):16/big-integer,
          (Pkt#pkt.sport):16/big-integer,
          (Pkt#pkt.dport):16/big-integer,
          (Pkt#pkt.seq):32/big-integer,
          (Pkt#pkt.ack):32/big-integer,
          (Pkt#pkt.offset):4/big-integer,
          0:6/big-integer,
          (Pkt#pkt.is_urg):1/integer,
          (Pkt#pkt.is_ack):1/integer,
          (Pkt#pkt.is_psh):1/integer,
          (Pkt#pkt.is_rst):1/integer,
          (Pkt#pkt.is_syn):1/integer,
          (Pkt#pkt.is_fin):1/integer,
          (Pkt#pkt.window):16/big-integer,
          0:16/big-integer,       %% Assume checkum of zero
          (Pkt#pkt.urgent):16/big-integer>>,
    C1 = crypto:hash_init(md5),
    C2 = crypto:hash_update(C1, Pseudo_Header),
    C3 = crypto:hash_update(C2, Pkt#pkt.data),
    C3.

calculate_md5(Pkt, Key) ->
    C1 = calculate_base_md5(Pkt),
    C2 = crypto:hash_update(C1, Key),
    crypto:hash_final(C2).
