-module(etcpip_util).

% API
-export([parse_ip6/1]).
-export([print_ip6/1]).

%--- API -----------------------------------------------------------------------

parse_ip6(String) ->
    case inet:parse_ipv6_address(String) of
        {error, einval} -> error({invalid_ipv6_address, String});
        {ok, {A, B, C, D, E, F, G, H}} ->
            <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>
    end.

print_ip6(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    Addr = [A, B, C, D, E, F, G, H],
    Hex = lists:map(fun(X) -> io_lib:format("~.16b", [X]) end, Addr),
    string:join(Hex, ":").
