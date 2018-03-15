-module(ipv6).

% API
-export([start_reader/0]).
-export([start_writer/0]).
-export([recv/1]).
-export([send/1]).
-export([decode/1]). % DEBUG

-include("ip.hrl").

-define(HOP_LIMIT, 128).

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
        Packet = #ipv6{headers = [{Protocol = icmpv6, _}|_]} ->
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
        _TClass:8,
        _Flow:20,
        PLen:16/big,
        Next:8/big,
        HLim:8/big,
        Src:128/bitstring,
        Dst:128/bitstring,
        Data/bitstring
    >> = Bin,
    Decoded = #ipv6{
        plen = PLen,
        hlim = HLim,
        src = Src,
        dst = Dst
    },
    decode_headers(Decoded, Next, Data, []).

decode_headers(Packet, ?IP_PROTO_ICMPv6, Data, Headers) ->
    Packet#ipv6{headers = [{icmpv6, Data}|Headers]};
decode_headers(Packet, ?IP_PROTO_IPv6_NO_NEXT_HEADER, Data, Headers) ->
    Packet#ipv6{headers = [{ipv6_no_next, Data}|Headers]};
decode_headers(Packet, ?IP_PROTO_TCP, Data, Headers) ->
    Packet#ipv6{headers = [{tcp, Data}|Headers]};
decode_headers(Packet, ?IP_PROTO_UDP, Data, Headers) ->
    Packet#ipv6{headers = [{udp, Data}|Headers]};
decode_headers(Packet, Type, <<Next:8/big, Len:8/big, Data/bitstring>>, Headers) ->
    Length = (Len + 1) * 8,
    <<Value:Length/bitstring, Rest/bitstring>> = Data,
    decode_headers(Packet, Next, Rest, [{Type, Value}|Headers]).

encode(#ipv6{src = Src, dst = Dst, headers = Headers}) ->
    % PLen = ?TODO_length,
    % Next = ?TODO_next_header,
    {PLen, Next, Payload} = encode_headers(Headers),
    [<<
        6:4,
        0:8,
        0:20,
        PLen:16/big,
        Next:8/big,
        ?HOP_LIMIT:8/big,
        Src/bitstring,
        Dst/bitstring
    >>, Payload].

encode_headers([])      -> {0, ?IP_PROTO_IPv6_NO_NEXT_HEADER, []};
encode_headers(Headers) -> encode_headers(Headers, 0, undefined, []).

encode_headers([], PLen, Next, Acc) ->
    {PLen, Next, lists:reverse(Acc)};
encode_headers([{icmpv6, Data}|Headers], PLen, _Next, Acc) ->
    encode_headers(Headers, PLen + byte_size(Data), ?IP_PROTO_ICMPv6, [Data|Acc]).
