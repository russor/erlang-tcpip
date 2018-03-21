-record(pcap, {
    magic_number,
    version,
    thiszone,
    sigfigs,
    snaplen,
    network,
    packets = []
}).

-record(pcap_packet, {
    number = 0,
    time,
    orig_len,
    data
}).

-define(assert_encode_decode(Packet),
    ?assertEqual(Packet, iolist_to_binary(encode(decode(Packet))))
).

-define(pcap_packets(Path, Variable, Test),
    filelib:fold_files(Path, ".+\.pcap$", true, fun(_F, _Acc) ->
        _Pcap = test_utils:pcap_to_packets(_F),
        _Acc ++ [
            {lists:flatten(io_lib:format("~s: packet #~b", [_F, _N])), Test}
            ||
            #pcap_packet{number = _N, data = Variable} <- _Pcap#pcap.packets
        ]
    end, [])
).
