-module(icmpv6).

% API
-export([start_reader/2]).
-export([start_writer/0]).
-export([recv/1]).
-export([encode/1]).
-export([decode/1]).

-record(icmpv6, {
    type,
    code,
    payload
}).

-include("ip.hrl").

-define(ICMPV6_ECHO_REQUEST,           128).
-define(ICMPV6_ECHO_RESPONSE,          129).
-define(ICMPV6_ROUTER_SOLICITATION,    133).
-define(ICMPV6_ROUTER_ADVERTISEMENT,   134).
-define(ICMPV6_NEIGHBOR_SOLICITATION,  135).
-define(ICMPV6_NEIGHBOR_ADVERTISEMENT, 136).

-define(NS_SOURCE_LINK_LAYER_ADDR,     1).
-define(NS_TARGET_LINK_LAYER_ADDR,     2).

%--- API -----------------------------------------------------------------------

start_reader(IP6, Mac) ->
    etcpip_proc:start_link(icmpv6_reader, #{
        init        => fun() -> {IP6, Mac} end,
        handle_cast => fun reader_handle_cast/2
    }).

start_writer() ->
    etcpip_proc:start_link(icmpv6_writer, #{
        init        => fun() -> undefined end,
        handle_cast => fun writer_handle_cast/2
    }).

recv(Packet) -> etcpip_proc:cast(icmpv6_reader, {recv, Packet}).

send(Packet) -> etcpip_proc:cast(icmpv6_writer, {send, Packet}).

%--- Reader --------------------------------------------------------------------

reader_handle_cast({recv, Packet}, State) ->
    process(decode(Packet), State),
    {noreply, State}.

%--- Writer --------------------------------------------------------------------

writer_handle_cast({send, Packet}, State) ->
    ipv6:send(encode(Packet)),
    {noreply, State}.

%--- Internal ------------------------------------------------------------------

% Decode

decode(#ipv6{next = _Next, headers = [{icmpv6, Payload}|Headers]} = Packet) ->
    {Checksum, Decoded} = decode_icmp(Payload),
    <<Type, Code, _Checksum:16, Data/binary>> = Payload,
    WOChecksum = <<Type, Code, 0, 0, Data/binary>>,
    Checksum = checksum:checksum_1([
        Packet#ipv6.src,
        Packet#ipv6.dst,
        <<(Packet#ipv6.plen):32/big>>,
        <<0:24, ?IP_PROTO_ICMPv6>>,
        WOChecksum
    ]),
    Packet#ipv6{headers = [Decoded|Headers]}.

decode_icmp(<<RawType, Code, Checksum:16, Payload/binary>>) ->
    Type = decode_type(RawType),
    {Checksum, #icmpv6{
        type = Type,
        code = Code,
        payload = decode_payload(Type, Payload)
    }}.

decode_type(?ICMPV6_ROUTER_SOLICITATION)    -> router_solicitation;
decode_type(?ICMPV6_ROUTER_ADVERTISEMENT)   -> router_advertisement;
decode_type(?ICMPV6_NEIGHBOR_SOLICITATION)  -> neighbor_solicitation;
decode_type(?ICMPV6_NEIGHBOR_ADVERTISEMENT) -> neighbor_advertisement;
decode_type(?ICMPV6_ECHO_REQUEST)           -> echo_request;
decode_type(?ICMPV6_ECHO_RESPONSE)          -> echo_response;
decode_type(Unknown)                        -> Unknown.

decode_payload(neighbor_solicitation, Payload) ->
    <<_Reserved:32, TargetAddress:16/binary, Options/binary>> = Payload,
    {TargetAddress, decode_ns_options(Options, [])};
decode_payload(_Type, Payload) ->
    Payload.

decode_ns_options(<<Type, Length, Payload/binary>>, Opts) ->
    Size = (Length * 8) - 2,
    <<Value:Size/binary, Rest/binary>> = Payload,
    decode_ns_options(Rest, [decode_ns_option(Type, Value)|Opts]);
decode_ns_options(<<>>, Opts) ->
    maps:from_list(Opts).

decode_ns_option(?NS_SOURCE_LINK_LAYER_ADDR, <<Addr:6>>) ->
    {source_link_layer_addr, Addr};
decode_ns_option(Type, Value) ->
    {Type, Value}.

% Encode

encode(#ipv6{headers = [{icmpv6, Payload}|Headers]} = Packet) ->
    <<Prefix:16, _:16, Rest/binary>> = Encoded = encode_icmp(Payload),
    Checksum = checksum:checksum_1([
        ipv6:pseudo_header(Packet, byte_size(Encoded)),
        Encoded
    ]),
    Final = <<Prefix:16, Checksum:16, Rest/binary>>,
    Packet#ipv6{headers = [{icmpv6, Final}|Headers]}.

encode_icmp(#icmpv6{type = Type, code = Code, payload = Payload}) ->
    <<
        (encode_type(Type)),
        Code,
        0:16, % Temporary checksum
        (encode_payload(Type, Payload))/binary
    >>.

encode_type(router_solicitation)        -> ?ICMPV6_ROUTER_SOLICITATION;
encode_type(router_advertisement)       -> ?ICMPV6_ROUTER_ADVERTISEMENT;
encode_type(neighbor_solicitation)      -> ?ICMPV6_NEIGHBOR_SOLICITATION;
encode_type(neighbor_advertisement)     -> ?ICMPV6_NEIGHBOR_ADVERTISEMENT;
encode_type(echo_request)               -> ?ICMPV6_ECHO_REQUEST;
encode_type(echo_response)              -> ?ICMPV6_ECHO_RESPONSE;
encode_type(Type) when is_integer(Type) -> Type.

encode_payload(echo_response, Payload) ->
    Payload;
encode_payload(neighbor_solicitation, {<<Addr:16/binary>>, Opts}) ->
    <<0:32, Addr, (encode_ns_options(Opts))/binary>>;
encode_payload(neighbor_advertisement, {Addr, Opts}) ->
    R = 0,
    S = 1,
    O = 1,
    <<R:1, S:1, O:1, 0:29, Addr:16/binary, (encode_ns_options(Opts))/binary>>;
encode_payload(_Type, Payload) when is_binary(Payload) ->
    Payload.

encode_ns_options(Opts) -> maps:fold(fun encode_ns_option/3, <<>>, Opts).

encode_ns_option(source_link_layer_addr, Mac, Acc) ->
    <<?NS_SOURCE_LINK_LAYER_ADDR, 1, Mac:48/big, Acc/binary>>;
encode_ns_option(target_link_layer_addr, Mac, Acc) ->
    <<?NS_TARGET_LINK_LAYER_ADDR, 1, Mac:48/big, Acc/binary>>;
encode_ns_option(Type, Value, Acc) when is_integer(Type) ->
    Size = (byte_size(Value) + 2) div 8,
    <<Type, Size, Value/binary, Acc/binary>>.

process(#ipv6{headers = [#icmpv6{type = echo_request}]} = Packet, {IP6, _}) ->
    #ipv6{src = Src, headers = [ICMPV6|_]} = Packet,
    #icmpv6{payload = Payload} = ICMPV6,
    send(#ipv6{
        src = IP6,
        dst = Src,
        next = ?IP_PROTO_ICMPv6,
        hlim = 16#FF,
        headers = [
            {icmpv6, #icmpv6{
                type = echo_response,
                code = 0,
                payload = Payload
            }}
        ]
    });
process(#ipv6{headers = [#icmpv6{type = neighbor_solicitation, payload = {IP6, _}}|_]} = Packet, {IP6, Mac}) ->
    #ipv6{src = Src} = Packet,
    send(#ipv6{
        src = IP6,
        dst = Src,
        next = ?IP_PROTO_ICMPv6,
        hlim = 16#FF,
        headers = [
            {icmpv6, #icmpv6{
                type = neighbor_advertisement,
                code = 0,
                payload = {IP6, #{target_link_layer_addr => Mac}}
            }}
        ]
    });
process(_Packet, _Message) ->
    drop.
