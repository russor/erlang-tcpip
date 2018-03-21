-module(test_utils).

-include("test_utils.hrl").

% API
-export([pcap_to_packets/1]).
-export([strip_eth/1]).

%--- API -----------------------------------------------------------------------

pcap_to_packets(File) ->
    {ok, PCap} = file:read_file(File),
    parse_pcap(PCap).


strip_eth(<<_Eth:14/binary, Packet/binary>>) -> Packet.

%--- Internal ------------------------------------------------------------------

parse_pcap(Bin) ->
    <<
        MagicNumber:32/unsigned,
        HeaderRest:20/binary,
        Rest/binary
    >> = Bin,
    MN = convert_magic_number(MagicNumber),
    {Version, ThisZone, SigFigs, SnapLen, Network} =  parse_header(MN, HeaderRest),
    #pcap{
        magic_number = MN,
        version = Version,
        thiszone = ThisZone,
        sigfigs = SigFigs,
        snaplen = SnapLen,
        network = Network,
        packets = parse_packets(MN, 1, Rest)
    }.

convert_magic_number(16#a1b2c3d4) -> {big,    microsecond};
convert_magic_number(16#d4c3b2a1) -> {little, microsecond};
convert_magic_number(16#a1b23c4d) -> {big,    nanosecond};
convert_magic_number(16#4d3cb2a1) -> {little, nanosecond}.

parse_header({big, _}, Bin) ->
    <<
        VersionMajor:16/unsigned-big,
        VersionMinor:16/unsigned-big,
        ThisZone:32/signed-big,
        SigFigs:32/unsigned-big,
        SnapLen:32/unsigned-big,
        Network:32/unsigned-big
    >> = Bin,
    {{VersionMajor, VersionMinor}, ThisZone, SigFigs, SnapLen, Network};
parse_header({little, _}, Bin) ->
    <<
        VersionMajor:16/unsigned-little,
        VersionMinor:16/unsigned-little,
        ThisZone:32/signed-little,
        SigFigs:32/unsigned-little,
        SnapLen:32/unsigned-little,
        Network:32/unsigned-little
    >> = Bin,
    {{VersionMajor, VersionMinor}, ThisZone, SigFigs, SnapLen, Network}.

parse_packets(_MN, _N, <<>>) ->
    [];
parse_packets(MN, N, Bin) ->
    {Sec, USec, InclLen, OrigLen, More} = parse_packet_header(MN, Bin),
    <<
        Data:InclLen/binary,
        Rest/binary
    >> = More,
    [#pcap_packet{
        number = N,
        time = convert_time(MN, Sec, USec),
        orig_len = OrigLen,
        data = Data
    }|parse_packets(MN, N + 1, Rest)].

convert_time({_, microsecond}, Sec, USec) -> Sec * 1000000 + USec;
convert_time({_, nanosecond}, Sec, USec)  -> Sec * 1000000000 + USec.

parse_packet_header({big, _}, Bin) ->
    <<Sec:32/big, USec:32/big, InclLen:32/big, OrigLen:32/big, Rest/binary>> = Bin,
    {Sec, USec, InclLen, OrigLen, Rest};
parse_packet_header({little, _}, Bin) ->
    <<Sec:32/little, USec:32/little, InclLen:32/little, OrigLen:32/little, Rest/binary>> = Bin,
    {Sec, USec, InclLen, OrigLen, Rest}.
