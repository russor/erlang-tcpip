-module(icmpv6_test).

-include_lib("eunit/include/eunit.hrl").
-include("ip.hrl").
-include("test_utils.hrl").

-import(icmpv6, [decode/1, encode/1]).

%--- API -----------------------------------------------------------------------

encode_decode_test_() ->
    ?pcap_packets("test/encode_decode/ipv6/icmpv6", Packet,
        fun() -> ?assert_encode_decode(strip(Packet)) end
    ).

%--- Internal ------------------------------------------------------------------

strip(Packet) ->
    #ipv6{headers = [{icmpv6, Data}|_]} = ipv6:decode(test_utils:strip_eth(Packet)),
    Data.
