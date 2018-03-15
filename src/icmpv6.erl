-module(icmpv6).

% API
-export([start_reader/0]).
-export([start_writer/0]).
-export([recv/1]).

-record(icmpv6, {
    type,
    code,
    checksum,
    payload
}).

-include("ip.hrl").

-define(ICMPV6_ECHO_REQUEST,  128).
-define(ICMPV6_ECHO_RESPONSE, 129).

%--- API -----------------------------------------------------------------------

start_reader() ->
    etcpip_proc:start_link(icmpv6_reader, #{
        init        => fun() -> undefined end,
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

reader_handle_cast({recv, #ipv6{headers = [{icmpv6, Payload}|_]} = Packet}, State) ->
    % io:format("ICMPv6 from ~p: ~p~n", [Src, ]),
    case decode(Payload) of
        #icmpv6{type = ?ICMPV6_ECHO_REQUEST} = EchoRequest ->
            send(echo_reply(Packet, EchoRequest));
        _Other ->
            ignore
    end,
    {noreply, State}.

%--- Writer --------------------------------------------------------------------

writer_handle_cast({send, Packet = #ipv6{headers = [{icmpv6, Payload}|Headers]}}, State) ->
    ipv6:send(Packet#ipv6{headers = [{icmpv6, encode(Payload)}|Headers]}),
    {noreply, State}.

%--- Internal ------------------------------------------------------------------

decode(Bin) ->
    <<Type:8/integer, Code:8/integer, Checksum:16/integer, Payload/binary>> = Bin,
    #icmpv6{
        type = Type,
        code = Code,
        checksum = Checksum,
        payload = Payload
    }.

encode(#icmpv6{type = Type, code = Code, checksum = Checksum, payload = Payload}) ->
    <<Type:8/integer, Code:8/integer, Checksum:16/integer, Payload/binary>>.

echo_reply(Request, #icmpv6{type = ?ICMPV6_ECHO_REQUEST, code = 0, payload = Payload, checksum = Checksum}) ->
    #ipv6{src = Src, dst = Dst} = Request,
    #ipv6{
        src = Dst,
        dst = Src,
        headers = [
            {icmpv6, #icmpv6{
                type = ?ICMPV6_ECHO_RESPONSE,
                code = 0,
                checksum = Checksum,
                payload = Payload
            }}
        ]
    }.
