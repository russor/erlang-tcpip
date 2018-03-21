-module(ipv6_test).

-include_lib("eunit/include/eunit.hrl").
-include("test_utils.hrl").

-import(ipv6, [decode/1, encode/1]).

%--- API -----------------------------------------------------------------------

encode_decode_test_() ->
    ?pcap_packets("test/encode_decode/ipv6", Packet,
        fun() -> ?assert_encode_decode(test_utils:strip_eth(Packet)) end
    ).

encode_decode_no_next_header_test() ->
    ?assert_encode_decode(<<
         96,   0,   0,   0,   0,   0,  59,   0,
        254, 128,   0,   0,   0,   0,   0,   0,
        112, 141, 254, 131,  65,  20, 165,  18,
         32,   1,   0,   0,  65,  55, 158,  80,
        128,   0, 241,  42, 185, 200,  40,  21
    >>).
