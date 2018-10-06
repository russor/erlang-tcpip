%%%-------------------------------------------------------------------
%%% File    : nd.erl
%%% Author  : Rick Payne <rickp@rossfell.co.uk>
%%% Description : ND Cache Implementation
%%%
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
-module(nd).

-include("ip.hrl").

-export([start_resolver/2, start_ipv6_queue/2,
         send/1, update_cache/2]).


%%%%%%%%%%%%%%%%%%%%%%% API %%%%%%%%%%%%%%%%%%%%%%%%%%%

send(#ipv6{dst_mac = undef, dst = Dest} = Packet) ->
  %% Mac unresolved...
  case catch ets:lookup_element(nd_cache, Dest, 2) of
    {'EXIT', _} ->
      solve(Packet),
      queue(Packet);
    solving ->
      queue(Packet);
    Mac ->
       eth:send(ipv6:encode(Packet), ipv6, Mac)
  end;
send(#ipv6{} = Packet) ->
    eth:send(ipv6:encode(Packet), ipv6, Packet#ipv6.dst_mac).

update_cache(IP6, Mac) ->
    etcpip_proc:cast(nd_resolver, {resolved, IP6, Mac}).

start_resolver(Ip, Mac) ->
    etcpip_proc:start_link(nd_resolver, #{
        init        => fun() -> {Ip, Mac} end,
        handle_cast => fun resolver_handle_cast/2
    }).

start_ipv6_queue(Ip, Mac) ->
    etcpip_proc:start_link(ipv6_queue, #{
        init        => fun() -> {Ip, Mac, ets:new(ipv6_queue, [bag, private, named_table])} end,
        handle_cast => fun queue_handle_cast/2
    }).


%%%%%%%%%%%%%% ND Help Functions %%%%%%%%%%%%%%%%%%

resolver_handle_cast({solve, #ipv6{dst = DestIP} = Packet},
                     {LocalIp, LocalMac}) ->
    case catch ets:lookup_element(nd_cache, DestIP, 2) of
        {'EXIT', _} ->
            send_nd_query(DestIP, LocalIp, LocalMac),
            ets:insert(nd_cache, {DestIP, solving});
        solving ->
            noop;
        Mac ->
            send(Packet#ipv6{dst_mac = Mac})
    end,
    {noreply, {LocalIp, LocalMac}};
resolver_handle_cast({resolved, DestIP, Mac}, State) ->
    ets:insert(nd_cache, {DestIP, Mac}),
    etcpip_proc:cast(ipv6_queue, {nd, DestIP, Mac}),
    {noreply, State}.

solve(Packet) ->
  etcpip_proc:cast(nd_resolver, {solve, Packet}),
  ok.

send_nd_query(DestIP, LocalIP, LocalMac) ->
  SNMA = solicited_node_multicast_address(DestIP),
  Req = #ipv6{
           dst_mac = snma_to_mac(SNMA),
           src = LocalIP,
           dst =  SNMA,
           next = ?IP_PROTO_ICMPv6,
           hlim = 16#FF,
           headers = [
                      {icmpv6, #icmpv6{
                                  type = neighbor_solicitation,
                                  code = 0,
                                  payload = {DestIP, #{source_link_layer_addr => LocalMac}}
                                 }}
                     ]
          },
    send(icmpv6:encode(Req)).
    

solicited_node_multicast_address(<<_:104,R:24>>) ->
    %% ff02:0000:0000:0000:0000:0001:ff
    <<16#ff:8, 2:8, 0:(9*8), 1, 16#ff:8, R:24>>.

snma_to_mac(<<_:96, R:32>>) ->
    <<M:48>> = <<16#33, 16#33, R:32>>,
    M.


%%%%%%%%%%%%%% Ip Queue Help Functions %%%%%%%%%%%%%%%%%%

queue_handle_cast({queue, #ipv6{dst = Addr} = Packet},
                  {Ip, Mac, Tab}) ->
    case catch ets:lookup_element(nd_cache, Addr, 2) of
        solving ->
            ets:insert(ipv6_queue, {Addr, Packet});
        {'EXIT', _} ->
            ets:insert(ipv6_queue, {Addr, Packet});
        Mac_Addr ->
            send(Packet#ipv6{dst_mac = Mac_Addr})
    end,
    {noreply, {Ip, Mac, Tab}};
queue_handle_cast({nd, Ip_Addr, Mac_Addr}, {Ip, Mac, Tab}) ->
    Packets = dequeue(Ip_Addr),
    lists:foreach(fun(Packet) ->
                          send(Packet#ipv6{dst_mac = Mac_Addr})
                  end, Packets),
    {noreply, {Ip, Mac, Tab}}.

queue(#ipv6{} = Packet) ->
  etcpip_proc:cast(ipv6_queue, {queue, Packet}).

dequeue(Ip_Addr) ->
  case catch ets:lookup_element(ipv6_queue, Ip_Addr, 2) of
    Packets when is_list(Packets) ->
      ets:delete(ipv6_queue, Ip_Addr),
      Packets;
    _ ->
      []
  end.
