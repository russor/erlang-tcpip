%%%-------------------------------------------------------------------
%%% File    : ip.hrl
%%% Author  : Javier Paris Fernandez <javier.paris@udc.es>
%%% Description : Ip Protocol Constants
%%%
%%% Created :  6 Aug 2004 by Javier Paris Fernandez <javier.paris@udc.es>
%%%
%%%
%%% erlang-tcpip, Copyright (C) 2004 Javier Paris
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%-------------------------------------------------------------------

%--- IPv4 ----------------------------------------------------------------------

-define(IP_PROTO_ICMP, 1).
-define(IP_PROTO_TCP,  6).
-define(IP_PROTO_UDP, 17).

%--- IPv6 ----------------------------------------------------------------------

-define(IP_PROTO_ICMPv6,              58).
-define(IP_PROTO_IPv6_NO_NEXT_HEADER, 59).

-define(IP6_HOP_LIMIT, 64). % TODO: Make configurable

-record(ipv6, {
    tclass = 0,
    flow = 0,
    plen,
    hlim = ?IP6_HOP_LIMIT,
    src,
    dst,
    src_mac,
    dst_mac,
    headers = []
}).
