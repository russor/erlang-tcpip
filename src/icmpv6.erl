-module(icmpv6).

% API
-export([start_reader/2]).
-export([start_writer/0]).
-export([recv/1]).

-ifdef(TEST).
-export([encode/1]).
-export([decode/1]).
-endif.

-record(icmpv6, {
    type,
    code,
    checksum,
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
    process(decode_ipv6(Packet), State),
    {noreply, State}.

%--- Writer --------------------------------------------------------------------

writer_handle_cast({send, Packet = #ipv6{headers = [{icmpv6, Payload}|Headers]}}, State) ->
    ipv6:send(Packet#ipv6{headers = [{icmpv6, encode(Payload)}|Headers]}),
    {noreply, State}.

%--- Internal ------------------------------------------------------------------

% Decode

decode_ipv6(#ipv6{headers = [{icmpv6, Payload}|Headers]} = Packet) ->
    Packet#ipv6{headers = [decode(Payload)|Headers]}.

decode(<<RawType, Code, Checksum:16/integer, Payload/binary>>) ->
    Type = decode_type(RawType),
    #icmpv6{
        type = Type,
        code = Code,
        checksum = Checksum,  % TODO: verify
        payload = decode_payload(Type, Payload)
    }.

decode_type(?ICMPV6_NEIGHBOR_SOLICITATION) -> neighbor_solicitation;
decode_type(?ICMPV6_ECHO_REQUEST)          -> echo_request;
decode_type(Unknown)                       -> Unknown.

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

encode(#icmpv6{type = Type, code = Code, checksum = Checksum, payload = Payload}) ->
    [
        encode_type(Type),
        Code,
        <<Checksum:16/integer>>,
        encode_payload(Type, Payload)
    ].

encode_type(echo_request)               -> ?ICMPV6_ECHO_REQUEST;
encode_type(echo_response)              -> ?ICMPV6_ECHO_RESPONSE;
encode_type(neighbor_solicitation)      -> ?ICMPV6_NEIGHBOR_SOLICITATION;
encode_type(neighbor_advertisement)     -> ?ICMPV6_NEIGHBOR_ADVERTISEMENT;
encode_type(Type) when is_integer(Type) -> Type.

encode_payload(echo_response, Payload) ->
    Payload;
encode_payload(neighbor_solicitation, {<<Addr:16/binary>>, Opts}) ->
    [<<0:32>>, Addr, encode_ns_options(Opts)];
encode_payload(neighbor_advertisement, {Mac, Opts}) ->
    [Mac, encode_ns_options(Opts)];
encode_payload(_Type, Payload) when is_binary(Payload) ->
    Payload.

encode_ns_options(Opts) -> maps:fold(fun encode_ns_option/3, [], Opts).

encode_ns_option(source_link_layer_addr, Mac, Acc) ->
    [<<?NS_SOURCE_LINK_LAYER_ADDR, 1, Mac:48/big>>|Acc];
encode_ns_option(Type, Value, Acc) when is_integer(Type) ->
    Size = (byte_size(Value) + 2) div 8,
    [[Type, Size, Value]|Acc].

process(#ipv6{headers = [#icmpv6{type = echo_request}]} = Packet, _State) ->
    #ipv6{src = Src, dst = Dst, headers = [ICMPV6|_]} = Packet,
    #icmpv6{checksum = Checksum, payload = Payload} = ICMPV6,
    send(#ipv6{
        src = Dst,
        dst = Src,
        headers = [
            {icmpv6, #icmpv6{
                type = echo_response,
                code = 0,
                checksum = Checksum, % TODO: Compute
                payload = Payload
            }}
        ]
    });
process(#ipv6{headers = [#icmpv6{type = neighbor_solicitation}|_]} = Packet, {IP6, Mac}) ->
    #ipv6{src = Src, dst = Dst} = Packet,
    send(#ipv6{
        src = Dst,
        dst = Src,
        headers = [
            {icmpv6, #icmpv6{
                type = neighbor_advertisement,
                code = 0,
                checksum = 0,
                payload = {IP6, #{source_link_layer_addr => Mac}}
            }}
        ]
    });
process(_Packet, _Message) ->
    drop.
