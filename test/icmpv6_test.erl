-module(icmpv6_test).

-include_lib("eunit/include/eunit.hrl").
-include("ip.hrl").
-include("test_utils.hrl").

-import(icmpv6, [decode/1, encode/1]).

%--- API -----------------------------------------------------------------------

encode_decode_test_() ->
    filelib:fold_files("test/encode_decode/ipv6/icmpv6", ".+\.pcap$", true, fun(F, Acc) ->
        Pcap = test_utils:pcap_to_packets(F),
        Acc ++ [
            {
                lists:flatten(io_lib:format("~s: packet #~b", [F, N])),
                fun() -> ?assert_encode_decode(strip(Packet)) end
            }
            ||
            #pcap_packet{number = N, data = Packet} <- Pcap#pcap.packets
        ]
    end, []).

%--- Internal ------------------------------------------------------------------

strip(Packet) ->
    #ipv6{headers = [{icmpv6, Data}|_]} = ipv6:decode(test_utils:strip_eth(Packet)),
    Data.
