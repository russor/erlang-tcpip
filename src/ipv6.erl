-module(ipv6).

% API
-export([start_reader/0]).
-export([start_writer/0]).
-export([recv/1]).
-export([send/1]).

-ifdef(TEST).
-export([decode/1]).
-export([encode/1]).
-endif.

-include("ip.hrl").

%--- API -----------------------------------------------------------------------

start_reader() ->
    etcpip_proc:start_link(ipv6_reader, #{
        init        => fun() -> undefined end,
        handle_cast => fun reader_handle_cast/2
    }).

start_writer() ->
    etcpip_proc:start_link(ipv6_writer, #{
        init        => fun() -> undefined end,
        handle_cast => fun writer_handle_cast/2
    }).

recv(Bin) ->
    etcpip_proc:cast(ipv6_reader, {recv, Bin}).

send(Packet) ->
    etcpip_proc:cast(ipv6_writer, {send, Packet}).

%--- Reader --------------------------------------------------------------------

reader_handle_cast({recv, Data}, State) ->
    case decode(Data) of
        Packet = #ipv6{headers = [{Protocol = icmpv6, _Payload}|_]} ->
            Protocol:recv(Packet);
        _Drop ->
            ok
    end,
    {noreply, State}.

%--- Writer --------------------------------------------------------------------

writer_handle_cast({send, Packet}, State) ->
    eth:send(encode(Packet), ipv6, 95536995356), % TODO: Resolve destination address!
    {noreply, State}.

%--- Internal ------------------------------------------------------------------

decode(<<6:4, Bin/bitstring>>) ->
    <<
        TClass:8,
        Flow:20,
        PLen:16/big,
        Next:8/big,
        HLim:8/big,
        Src:128/bitstring,
        Dst:128/bitstring,
        Data/bitstring
    >> = Bin,
    Decoded = #ipv6{
        tclass = TClass,
        flow = Flow,
        plen = PLen,
        hlim = HLim,
        src = Src,
        dst = Dst
    },
    decode_headers(Decoded, Next, Data, []).

decode_headers(Packet, ?IP_PROTO_ICMPv6, Data, Headers) ->
    Packet#ipv6{headers = [{icmpv6, Data}|Headers]};
decode_headers(Packet, ?IP_PROTO_IPv6_NO_NEXT_HEADER, _Data, Headers) ->
    Packet#ipv6{headers = Headers};
decode_headers(Packet, ?IP_PROTO_TCP, Data, Headers) ->
    Packet#ipv6{headers = [{tcp, Data}|Headers]};
decode_headers(Packet, ?IP_PROTO_UDP, Data, Headers) ->
    Packet#ipv6{headers = [{udp, Data}|Headers]};
decode_headers(Packet, Type, <<Next, Len, Data/bitstring>>, Headers) ->
    Length = (Len + 1) * 8,
    <<Value:Length/bitstring, Rest/bitstring>> = Data,
    decode_headers(Packet, Next, Rest, [{Type, Value}|Headers]).

encode(Packet) when is_record(Packet, ipv6) ->
    #ipv6{
        tclass = TClass, flow = Flow, src = Src, hlim = HLim, dst = Dst, headers = Headers
    } = Packet,
    {PLen, Next, Payload} = encode_headers(Headers),
    [<<
        6:4,
        TClass,
        Flow:20,
        PLen:16/big,
        Next,
        HLim,
        Src:128/bitstring,
        Dst:128/bitstring
    >>, Payload].

encode_headers([])      -> {0, ?IP_PROTO_IPv6_NO_NEXT_HEADER, []};
encode_headers([{Type, Data}|Headers]) ->
    encode_headers(Headers, byte_size(Data), encode_type(Type), [Data]).

encode_headers([], PLen, Next, Acc) ->
    {PLen, Next, Acc};
encode_headers([{Type, Data}|Headers], PLen, Next, Acc) ->
    Len = byte_size(Data),
    encode_headers(Headers, PLen + Len + 2, encode_type(Type), [[Next, Len - 1, Data]|Acc]).

encode_type(udp)                        -> ?IP_PROTO_UDP;
encode_type(icmpv6)                     -> ?IP_PROTO_ICMPv6;
encode_type(Type) when is_integer(Type) -> Type.
