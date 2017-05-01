%%% Author: Ulf Norell
%%% Copyright (C) 2016, Quviq AB
%%%
%%% ------------------------------------------------------------------------
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
%%% ------------------------------------------------------------------------
%%%
%%% QuickCheck model for TCP
%%% Needs Quviq QuickCheck version 1.39.2 to generate tests

-module(tcp_eqc).

-include_lib("eqc/include/eqc.hrl").
-include_lib("eqc/include/eqc_component.hrl").
-include("tcp_pkt.hrl").

-import(eqc_statem, [tag/2, conj/1]).

-compile(export_all).

%% NOTES
%%
%%  RACE CONDITION 1
%%
%%    Between accept and ACK. There's a window in tcp_con:accept() between
%%    tcb:get_tcbdata() and tcb:subscribe() where a connection might be missed.
%%
%%  RACE CONDITION 2
%%
%%    Call to tcp_con:usr_open(), but no SYN is sent.
%%
%%  RACE CONDITION 3
%%
%%    Race between incoming and outgoing FIN, causing the call to
%%    tcp_con:usr_close() to get stuck.
%%
%%  RACE CONDITION 4
%%
%%    Internal state change message leaks to application process. Ignore it in
%%    the model for now (by running usr_close() in a fresh process).
%%

%% -- State ------------------------------------------------------------------

-define(SET(Key, Value), ?APPLY(set, [#state.Key, Value])).
-define(INC(Key),        ?APPLY(inc, [#state.Key])).

-record(state,{tcp_state = undefined, ip, port, rip, rport, socket,
               socket_type, seq, rcvd, rseq}).

initial_state() ->
  #state{}.

in_tcp_state(S, TcpStates) when is_list(TcpStates) ->
  lists:member(S#state.tcp_state, TcpStates);
in_tcp_state(S, TcpState) ->
  in_tcp_state(S, [TcpState]).

%% -- Generators ------------------------------------------------------------

ip()   -> ?LET(Ip, uint32(), return(int2ip(Ip))).
port() -> uint16().

uint8()  -> choose(0, 16#ff).
uint16() -> choose(0, 16#ffff).
uint32() -> choose(0, 16#ffffffff).

packet() ->
  ?LET({Options, Data}, {[{mss, uint16()}], binary()},
  #pkt{sport    = port(),
       dport    = port(),
       seq      = uint32(),
       ack      = uint32(),
       flags    = sublist([urg, ack, psh, rst, syn, fin]),
       window   = uint16(),
       checksum = uint16(),
       urgent   = uint16(),
       options  = Options,
       data     = Data }).

%% -- Common pre-/post-conditions --------------------------------------------

command_precondition_common(S, start) ->
  in_tcp_state(S, undefined);
command_precondition_common(S, _Cmd) ->
  not in_tcp_state(S, undefined).

postcondition_common(S, Call = {call, _, Cmd, _, _}, Res) ->
  case lists:member(Cmd, [open, listen, accept]) of
    true  -> true;
    false -> eq(Res, return_value(S, Call))
  end.

%% -- User operations --------------------------------------------------------

%% --- start ---

start_args(_S) ->
  [ip()].

start(Ip) ->
  tcp_pool:start(ip2int(Ip)),
  iss:start(),
  tcp:start(),
  ok.

start_callouts(_S, [Ip]) ->
  ?SET(tcp_state, closed),
  ?SET(ip, Ip).

%% --- open (connect) ---

open_pre(S) ->
  in_tcp_state(S, closed).

open_args(_S) ->
  [ip(), port()].

%% We cannot use the _next to bind the socket, because we block
open(RemoteIp, RemotePort) ->
  mock:set_socket(tcp_con:usr_open(ip2int(RemoteIp), RemotePort)).

open_process(_, _) ->
  spawn.

open_callouts(_S, [RemoteIp, RemotePort]) ->
  ?SET(rip,   RemoteIp),
  ?SET(rport, RemotePort),
  ?MATCH(Port, ?APPLY(sent_syn, [])),
  ?SET(tcp_state, syn_sent),
  ?SET(port, Port),
  ?BLOCK(syn_sent),
  ?PAR([ ?APPLY(set_socket, [])
       , ?APPLY(sent_ack, []) ]),
  ?SET(socket_type, connect),
  ?SET(tcp_state, established).

%% --- listen ---

listen_pre(S) ->
  in_tcp_state(S, closed).

listen_args(_S) ->
  [ port() ].

listen(Port) ->
  tcp_con:usr_listen(Port).

listen_callouts(_S, [Port]) ->
  ?SET(tcp_state, listen),
  ?SET(socket_type, listen),
  ?SET(port, Port).

listen_next(S, V, _) ->
  S#state{socket = V}.

%% --- accept ---

accept_pre(S) ->
  in_tcp_state(S, [listen, syn_rcvd, established, close_wait]) andalso
  S#state.socket_type == listen.

accept_args(S) ->
  [S#state.socket].

accept_pre(S, [Socket]) ->
  S#state.socket == Socket.

accept_adapt(S, _) -> [S#state.socket].

accept(Socket) ->
  mock:set_socket(tcp_con:usr_accept(Socket)).

accept_callouts(S, [_Socket]) ->
  ?SET(socket_type, accept),
  ?WHEN(in_tcp_state(S, [listen, syn_rcvd]), ?BLOCK(accept)),
  ?APPLY(set_socket, []),
  ?RET(ok).

accept_process(_S, [_Socket]) ->
  spawn.

%% --- close ---

close_pre(S) ->
  in_tcp_state(S, [established, close_wait, listen]) andalso
  lists:member(S#state.socket_type, [accept, connect]).


close_args(S) ->
  [S#state.socket].

close_pre(S, [Socket]) ->
  S#state.socket == Socket.

close_adapt(S, _) -> [S#state.socket].

close(Socket) ->
  Root = self(),
  %% Work around for RACE CONDITION 4
  Pid = spawn(fun() -> Root ! {self(), tcp_con:usr_close(Socket)} end),
  receive {Pid, _Res} -> ok end.


close_callouts(S, [_]) ->
  case S#state.tcp_state of
    close_wait ->
      ?APPLY(sent_fin, []),
      ?SET(tcp_state, last_ack),
      ?BLOCK(close);
    established ->
      ?APPLY(sent_fin, []),
      ?SET(tcp_state, fin_wait_1),
      ?BLOCK(close);
    _ ->
      ?APPLY(reset, []),
      ?SET(tcp_state, closed),
      ?SET(socket_type, undefined),
      ?BLOCK(close)
  end.

close_process(_, _) -> spawn.


%% -- Backend operations -----------------------------------------------------

%% --- syn ---

syn_pre(S) ->
  in_tcp_state(S, listen).

syn_args(S) ->
  [S#state.ip, S#state.port, ip(), port(), uint32()].

syn(Ip, Port, RemoteIp, RemotePort, RemoteSeq) ->
  Packet =
    #pkt{sport = RemotePort,
         dport = Port,
         seq   = RemoteSeq,
         flags = [syn] },
  Data = encode(RemoteIp, Ip, Packet),
  inject(RemoteIp, Ip, Data),
  ok.

syn_pre(S, [Ip, Port, _, _, _]) ->
  S#state.ip   == Ip andalso
  S#state.port == Port.

syn_adapt(S, [_, _ | Args]) ->
  [S#state.ip, S#state.port | Args].

syn_callouts(_S, [_Ip,  _Port, RemoteIp, RemotePort, RemoteSeq]) ->
  ?SET(rip, RemoteIp),
  ?SET(rport, RemotePort),
  ?SET(rseq, {RemoteSeq, 1}),
  ?APPLY(sent_syn_ack, []),
  ?SET(tcp_state, syn_rcvd).


%% --- syn_ack ---

syn_ack_pre(S) ->
  in_tcp_state(S, syn_sent) andalso
  S#state.rcvd == S#state.seq.

syn_ack_args(S) ->
  [S#state.ip, S#state.port, S#state.rip,
   S#state.rport, uint32(), S#state.seq].

syn_ack_pre(S, [Ip, Port, RIp, RPort, _, Seq]) ->
  Ip    == S#state.ip    andalso
  Port  == S#state.port  andalso
  RIp   == S#state.rip   andalso
  RPort == S#state.rport andalso
  Seq   == S#state.seq.

syn_ack_adapt(S, [_, _, _, _, Seq, _]) ->
  [S#state.ip, S#state.port, S#state.rip,
   S#state.rport, Seq, S#state.seq].

syn_ack(Ip, Port, RemoteIp, RemotePort, Seq, Ack) ->
  Packet =
    #pkt{sport = RemotePort,
        dport  = Port,
        seq    = counter(Seq),
        ack    = counter(Ack),
        flags  = [ack, syn] },
  Data = encode(Ip, RemoteIp, Packet),
  inject(RemoteIp, Ip, Data),
  ok.

syn_ack_callouts(_S, [_Ip, _Port, _RemoteIp, _RemotePort, Seq, _Ack]) ->
  ?SET(rseq, {Seq, 1}),
  ?UNBLOCK(syn_sent, ok).


%% --- ack ---

ack_pre(S) ->
  in_tcp_state(S, [syn_rcvd, last_ack, fin_wait_1, closing]) andalso
  S#state.seq == S#state.rcvd.

ack_args(S) ->
  [S#state.ip, S#state.port,
   S#state.rip,
   S#state.rport,
   S#state.rseq,
   S#state.seq].

ack_pre(S, Args) ->
  Args == ack_args(S).

ack_adapt(S, _) -> ack_args(S).

ack(Ip,  Port, RemoteIp, RemotePort, Seq, Ack) ->
  Packet =
    #pkt{sport = RemotePort,
         dport = Port,
         seq   = counter(Seq),
         ack   = counter(Ack),
         flags = [ack] },
  Data = encode(RemoteIp, Ip, Packet),
  inject(RemoteIp, Ip, Data),
  ok.

ack_callouts(S, [_Ip, _Port, _RemoteIp, _RemotePort, _Seq, _Ack]) ->
  case S#state.tcp_state of
    syn_rcvd ->
      ?WHEN(S#state.socket_type == accept, ?UNBLOCK(accept, ok)),
      ?SET(tcp_state, established);
    fin_wait_1 ->
      ?SET(tcp_state, fin_wait_2);
    closing ->
      ?UNBLOCK(close, ok),
      ?SET(tcp_state, time_wait);
    last_ack ->
      ?UNBLOCK(close, ok),
      ?APPLY(reset, []),
      ?SET(tcp_state, closed)
  end.

%% --- fin ---

fin_pre(S) ->
  in_tcp_state(S, [established, fin_wait_1, fin_wait_2]).

fin_args(S) ->
  [S#state.ip, S#state.port,
   S#state.rip, S#state.rport,
   S#state.rseq, S#state.rcvd].

fin_pre(S, Args) ->
  fin_args(S) == Args.

fin_adapt(S, _) -> fin_args(S).

fin(Ip, Port, RemoteIp, RemotePort, Seq, Ack) ->
  Packet =
    #pkt{sport = RemotePort,
         dport = Port,
         seq   = counter(Seq),
         ack   = counter(Ack),
         flags = [ack, fin] },
  Data = encode(RemoteIp, Ip, Packet),
  inject(RemoteIp, Ip, Data),
  ok.

fin_callouts(S, [_Ip, _Port, _RemoteIp, _RemotePort, _Seq, _]) ->
  ?INC(rseq),
  ?APPLY(sent_ack, []),
  case S#state.tcp_state of
    established ->
      ?SET(tcp_state, close_wait);
    fin_wait_1 ->
      case S#state.seq == S#state.rcvd of %% FIN+ACK ?
        true ->
          ?UNBLOCK(close, ok),
          ?SET(tcp_state, time_wait);
        false ->
          ?SET(tcp_state, closing)
      end;
    fin_wait_2  ->
      ?UNBLOCK(close, ok),
      ?SET(tcp_state, time_wait)
  end.

%% --- deliver ---

deliver_pre(S) ->
  S#state.rcvd /= S#state.seq.

deliver_args(_S) -> [].

deliver() -> timer:sleep(1).

deliver_callouts(S, []) ->
  ?SET(rcvd, S#state.seq).

%% -- Local operations -------------------------------------------------------

reset_callouts(_S, []) ->
  ?SET(port,  undefined),
  ?SET(rport, undefined),
  ?SET(seq,   undefined),
  ?SET(rseq,  undefined).

sent_syn_callouts(_S, []) ->
  ?MATCH(Packet, ?APPLY(sent, [])),
  Port = {call, erlang, element, [#pkt.sport, Packet]},
  ?ASSERT(?MODULE, check_packet, [Packet, '_', '_', [syn]]),
  ?SET(seq, {{call, erlang, element, [#pkt.seq, Packet]}, 1}),
  ?RET(Port).

sent_ack_callouts(S, []) ->
  ?MATCH(Packet, ?APPLY(sent, [])),
  ?ASSERT(?MODULE, check_packet, [Packet, S#state.seq, S#state.rseq, [ack]]),
  ?RET(ok).

sent_fin_callouts(S, []) ->
  ?MATCH(Packet, ?APPLY(sent, [])),
  ?ASSERT(?MODULE, check_packet, [Packet, S#state.seq, S#state.rseq, [ack, fin]]),
  ?INC(seq),
  ?RET(ok).

sent_syn_ack_callouts(S, []) ->
  ?MATCH(Packet, ?APPLY(sent, [])),
  ?ASSERT(?MODULE, check_packet, [Packet, '_', S#state.rseq, [ack, syn]]),
  ?SET(seq, {{call, erlang, element, [#pkt.seq, Packet]}, 1}),
  ?RET(ok).

sent_callouts(S, []) ->
  ?MATCH({Packet, ok}, ?CALLOUT(ip, send_pkt, [?VAR, S#state.rip], ok)),
  ?ASSERT(?MODULE, verify_checksum, [S#state.ip, S#state.rip, Packet]),
  ?ASSERT(?MODULE, check_ports,     [S#state.port, S#state.rport, Packet]),
  ?RET(Packet).

set_socket_callouts(_, []) ->
  ?MATCH({Socket, ok}, ?CALLOUT(mock, set_socket, [?VAR], ok)),
  ?SET(socket, Socket).

set_next(S, _, [Key, Value]) ->
  setelement(Key, S, Value).

inc_next(S, _, [Key]) ->
  N = case element(Key, S) of
        {Init, Offs}         -> {Init, Offs + 1};
        M when is_integer(M) -> M + 1;
        undefined -> undefined
      end,
  setelement(Key, S, N).

check_ports(SPort, DPort, Packet) ->
  conj([tag(source_port,      match(Packet#pkt.sport, SPort)),
        tag(destination_port, match(Packet#pkt.dport, DPort))]).

check_packet(Packet, Seq, Ack, Flags) ->
  conj([tag(seq, match(Packet#pkt.seq, counter(Seq))),
        tag(ack, match(Packet#pkt.ack, counter(Ack))),
        eq(Packet#pkt.flags, Flags)]).

match(_, '_')       -> true;
match(_, undefined) -> true;
match(X, Y)         -> eq(X, Y).

%% -- Helpers

ip2int(S) ->
  [A, B, C, D] = lists:map(fun list_to_integer/1, string:tokens(S, ".")),
  <<Ip:32/big-integer>> = <<A, B, C, D>>,
  Ip.

int2ip(Ip) ->
  <<A, B, C, D>> = <<Ip:32/big-integer>>,
  lists:flatten(io_lib:format("~p.~p.~p.~p", [A, B, C, D])).

encode(SrcIp, DstIp, Packet) ->
  tcp_pkt:encode(ip2int(SrcIp), ip2int(DstIp), Packet).

inject(SrcIp, DstIp, Data) ->
  tcp:recv(ip2int(SrcIp), ip2int(DstIp), Data).

verify_checksum(SrcIp, DstIp, Packet) ->
  tcp_pkt:verify_checksum(ip2int(SrcIp), ip2int(DstIp), Packet).

counter(N) when is_integer(N) -> N;
counter({Init, Offs}) -> Init + Offs;
counter('_') -> '_'.

%% -- Property ---------------------------------------------------------------
%% invariant(_S) ->
%% true.

weight(_S, send) -> 1;
weight(_S, _Cmd) -> 1.

prop_encode_decode() ->
  ?FORALL({SrcIp, DstIp, Packet}, {ip(), ip(), packet()},
  begin
    Src = ip2int(SrcIp),
    Dst = ip2int(DstIp),
    Checksum = tcp_pkt:checksum(Src, Dst, Packet),
    try tcp_pkt:encode(Src, Dst, Packet) of
      Bin ->
        try tcp_pkt:decode(Src, Dst, Bin) of
          Packet1 -> equals(Packet1, Packet#pkt{ checksum = Checksum })
        catch _:Err ->
          ?WHENFAIL(eqc:format("decode failure\n  Bin = ~p\n~p\n  ~p\n", [Bin, Err, erlang:get_stacktrace()]),
                    false)
        end
    catch _:Err ->
      ?WHENFAIL(eqc:format("encode failure\n~p\n  ~p\n", [Err, erlang:get_stacktrace()]),
                false)
    end
  end).

prop_checksum() ->
  ?FORALL({SrcIp, DstIp, Packet}, {ip(), ip(), packet()},
  begin
    Src = ip2int(SrcIp),
    Dst = ip2int(DstIp),
    Bin = tcp_pkt:encode(Src, Dst, Packet),
    tcp_pkt:verify_checksum(Src, Dst, Bin)
  end).

adjacent([X, Y | Xs]) -> [{X, Y} || X /= Y] ++ adjacent([Y | Xs]);
adjacent(_) -> [].

prop_tcp() ->
  eqc_statem:show_states(
  %eqc:dont_print_counterexample(
  with_parameter(default_process, worker,
  with_parameter(color, true,
  ?FORALL(Cmds, commands(?MODULE),
  begin
    eqc_mocking:start_mocking(api_spec()),
    error_logger:tty(false),
    cleanup(),
    checksum:start(),
    {H, S, Res} = run_commands(Cmds),
    cleanup(),
    TcpStates = [ TcpS || #state{tcp_state = TcpS} <- lists:map(fun eqc_statem:history_state/1, H) ++ [S] ],
    check_command_names(Cmds,
      measure(length, commands_length(Cmds),
      aggregate(TcpStates,
      aggregate(adjacent(TcpStates),
      eqc_component:pretty_commands(?MODULE, Cmds, {H, S, Res},
        Res == ok)))))
  end)))).

cleanup() -> cleanup([]).
cleanup(_Sockets) ->
  [ catch exit(whereis(P), kill)
    || P <- [tcp_reader, tcp_writer, tcp, iss, tcp_pool, checksum] ],
  timer:sleep(1).

used_sockets(H, S) ->
  used_sockets([H, S]).

used_sockets(#state{ socket = Socket }) ->
  [ Socket || Socket /= undefined ];
used_sockets([H | T]) ->
  lists:umerge(used_sockets(H), used_sockets(T));
used_sockets([]) -> [];
used_sockets(HE) ->
  used_sockets(eqc_statem:history_state(HE)).

cover() ->
  cover(prop_tcp()).

cover(Prop) ->
  CoverDir = "cover",
  file:make_dir(CoverDir),
  eqc_cover:start(),
  Res = quickcheck(Prop),
  Data = eqc_cover:stop(),
  eqc_cover:write_html(Data,  [{out_dir, CoverDir}, {css_dir, CoverDir}, {js_dir, CoverDir}]),
  Res.

%% -- API-spec ---------------------------------------------------------------
api_spec() ->
  #api_spec{
     language = erlang,
     mocking = eqc_mocking,
     modules =
       [ #api_module{
            name = ip, fallback = ?MODULE,
            functions =
              [ #api_fun{ name = send_pkt, arity = 2 }] },
         #api_module{
            name = mock,
            functions =
              [ #api_fun{ name = set_socket, arity = 1 }] }]
    }.

%% -- Stubs ------------------------------------------------------------------

send(Data, Size, Prot, DstIp) when is_list(Data) ->
  send(list_to_binary(Data), Size, Prot, DstIp);
send(Data, Size, _, _) when size(Data) /= Size -> ip:packet_size_mismatch(Data, size(Data), Size);
send(Data, _Size, tcp, DstIp) ->
  ip:send_pkt(tcp_pkt:decode(Data), int2ip(DstIp)).

