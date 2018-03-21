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

-define(encode_decode_tests(Path, Filter),
    filelib:fold_files(Path, ".+\.bin$", true, fun(F, Acc) ->
        {ok, Raw} = file:read_file(F),
        [{F, fun() ->
            P = Filter(Raw),
            ?assert_encode_decode(P)
        end}|Acc]
    end, [])
).
