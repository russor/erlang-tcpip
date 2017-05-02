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

-define(SET(Id, Key, Value), ?APPLY(set, [Id, #state.Key, Value])).
-define(INC(Id, Key),        ?APPLY(inc, [Id, #state.Key])).

-record(state,{tcp_state = undefined, ip, port, rip, rport, socket,
               socket_type, seq, rcvd, rseq, id}).

initial_state() ->
  [].

in_tcp_state(Ss, Id, TcpStates) when is_list(TcpStates) ->
  case [ S#state.tcp_state || S<-Ss, S#state.id == Id] of
    [TcpS] ->
      lists:member(TcpS, TcpStates);
    [] -> false;
    Other -> erlang:error({several_copies, Other})
  end;
in_tcp_state(Ss, Id, TcpState) ->
  in_tcp_state(Ss, Id, [TcpState]).

%% in_tcp_state(S, TcpStates) when is_list(TcpStates) ->
%%   lists:member(S#state.tcp_state, TcpStates);
%% in_tcp_state(S, TcpState) ->
%%   in_tcp_state(S, [TcpState]).

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
  S == [];
command_precondition_common(S, _Cmd) ->
  S =/= [].

postcondition_common(S, Call = {call, _, Cmd, _, _}, Res) ->
  case lists:member(Cmd, [open, listen, accept]) of
    true  -> true;
    false -> eq(Res, return_value(S, Call))
  end.

%% -- User operations --------------------------------------------------------

%% --- start ---

start_args(_S) ->
  [ip(), choose(1,3)].

start(Ip, _) ->
  tcp_pool:start(ip2int(Ip)),
  iss:start(),
  tcp:start(),
  ok.

start_next(_S, _, [Ip, Nr]) ->
  [#state{tcp_state = closed,
          ip = Ip, 
          id = N} || N<-lists:seq(1,Nr)].

%% --- open (connect) ---

%% open_pre(S) ->
%%   in_tcp_state(S, closed).

open_args(Ss) ->
  [ip(), port(), choose(1,length(Ss))].

open_pre(Ss, [_, _, Id]) ->
  in_tcp_state(Ss, Id, closed).

%% We cannot use the _next to bind the socket, because we block
open(RemoteIp, RemotePort, _Id) ->
  mock:set_socket(tcp_con:usr_open(ip2int(RemoteIp), RemotePort)).

open_process(_, _) ->
  spawn.

open_callouts(_S, [RemoteIp, RemotePort, Id]) ->
  ?SET(Id, rip,   RemoteIp),
  ?SET(Id, rport, RemotePort),
  ?MATCH(Port, ?APPLY(sent_syn, [Id])),
  ?SET(Id, tcp_state, syn_sent),
  ?SET(Id, port, Port),
  ?BLOCK({syn_sent, Id}),
  ?PAR([ ?APPLY(set_socket, [Id])
       , ?APPLY(sent_ack, [Id]) ]),
  ?SET(Id, socket_type, connect),
  ?SET(Id, tcp_state, established).

%% --- listen ---

%% listen_pre(S) ->
%%   in_tcp_state(S, closed).

listen_args(Ss) ->
  [ port(), choose(1,length(Ss)) ].

listen_pre(Ss, [_, Id]) ->
  in_tcp_state(Ss, Id, closed).

listen(Port, _) ->
  tcp_con:usr_listen(Port).

listen_callouts(_S, [Port, Id]) ->
  ?SET(Id, tcp_state, listen),
  ?SET(Id, socket_type, listen),
  ?SET(Id, port, Port).

listen_next(Ss, V, [_, Id]) ->
  [ S ] = [ S || S<-Ss, S#state.id == Id],
  (Ss -- [S]) ++ [S#state{socket = V}].

%% --- accept ---

%% accept_pre(S) ->
%%   in_tcp_state(S, [listen, syn_rcvd, established, close_wait]) andalso
%%   S#state.socket_type == listen.

accept_args(Ss) ->
  ?LET(S, elements(Ss),
       [S#state.socket, S#state.id]).

accept_pre(Ss, [Socket, Id]) ->
  [ S ] = [ S || S<-Ss, S#state.id == Id ],
  S#state.socket == Socket andalso S#state.socket_type == listen andalso
    in_tcp_state(Ss, Id, [listen, syn_rcvd, established, close_wait]).

accept_adapt(Ss, [_, Id]) -> 
 case  [ S || S<-Ss, S#state.id == Id ] of
   [S] ->
     [S#state.socket, Id];
   _ ->
     false
 end.

accept(Socket, _) ->
  mock:set_socket(tcp_con:usr_accept(Socket)).

accept_callouts(Ss, [_Socket, Id]) ->
  ?SET(Id, socket_type, accept),
  ?WHEN(in_tcp_state(Ss, Id, [listen, syn_rcvd]), ?BLOCK({accept, Id})),
  ?APPLY(set_socket, [Id]),
  ?RET(ok).

accept_process(_S, [_Socket, _]) ->
  spawn.

%% --- close ---

%% close_pre(S) ->
%%   in_tcp_state(S, [established, close_wait, listen]) andalso
%%   lists:member(S#state.socket_type, [accept, connect]).

close_args(Ss) ->
  ?LET(S, elements(Ss),
       [S#state.socket, S#state.id]).

close_pre(Ss, [Socket, Id]) ->
  case [ S || S<-Ss, S#state.id == Id ] of
    [ S ] ->
      S#state.socket == Socket andalso
        in_tcp_state(Ss, Id, [established, close_wait, listen]) andalso
        lists:member(S#state.socket_type, [accept, connect, listen]);
    _ ->
      false
  end.

closet_adapt(Ss, [_, Id]) -> 
  case [ S || S<-Ss, S#state.id == Id ] of
    [ S ] ->
      [S#state.socket, Id];
    _ ->
      false
  end.

close(Socket, _) ->
  Root = self(),
  %% Work around for RACE CONDITION 4
  Pid = spawn(fun() -> Root ! {self(), tcp_con:usr_close(Socket)} end),
  receive {Pid, _Res} -> ok end.


close_callouts(Ss, [_, Id]) ->
  [ S ] = [ S || S<-Ss, S#state.id == Id ],
  case S#state.tcp_state of
    close_wait ->
      ?APPLY(sent_fin, [Id]),
      ?SET(Id, tcp_state, last_ack),
      ?BLOCK({close, Id});
    established ->
      ?APPLY(sent_fin, [Id]),
      ?SET(Id, tcp_state, fin_wait_1),
      ?BLOCK({close, Id});
    listen ->
      ?WHEN(S#state.socket_type == accept, ?UNBLOCK({accept, Id}, ok)),
      ?APPLY(reset, [Id]),
      ?SET(Id, tcp_state, closed),
      ?SET(Id, socket_type, undefined)
  end.

close_process(_, _) -> spawn.


%% -- Backend operations -----------------------------------------------------

%% --- syn ---

%% syn_pre(S) ->
%%   in_tcp_state(S, listen).

syn_args(Ss) ->
  ?LET(S, elements(Ss),
       [S#state.ip, S#state.port, ip(), port(), uint32(), S#state.id]).

syn(Ip, Port, RemoteIp, RemotePort, RemoteSeq, _Id) ->
  Packet =
    #pkt{sport = RemotePort,
         dport = Port,
         seq   = RemoteSeq,
         flags = [syn] },
  Data = encode(RemoteIp, Ip, Packet),
  inject(RemoteIp, Ip, Data),
  ok.

syn_pre(Ss, [Ip, Port, _, _, _, Id]) ->
  case [ S || S<-Ss, S#state.id == Id ] of
    [ S ] ->
      S#state.ip   == Ip andalso
        S#state.port == Port andalso
        in_tcp_state(Ss, Id, listen);
    _ ->
      false
  end.

syn_adapt(Ss, [_, _, Ip, Port, Seq, Id]) ->
  case [ S || S<-Ss, S#state.id == Id ] of
    [ S ] ->
      [S#state.ip, S#state.port, Ip, Port, Seq, Id];
    _ ->
      false
  end.

syn_callouts(_S, [_Ip,  _Port, RemoteIp, RemotePort, RemoteSeq, Id]) ->
  ?SET(Id, rip, RemoteIp),
  ?SET(Id, rport, RemotePort),
  ?SET(Id, rseq, {RemoteSeq, 1}),
  ?APPLY(sent_syn_ack, [Id]),
  ?SET(Id, tcp_state, syn_rcvd).


%% --- syn_ack ---

%% syn_ack_pre(S) ->
%%   in_tcp_state(S, syn_sent) andalso
%%   S#state.rcvd == S#state.seq.

syn_ack_args(Ss) ->
  ?LET(S, elements(Ss),
       [S#state.ip, S#state.port, S#state.rip,
        S#state.rport, uint32(), S#state.seq, S#state.id]).

syn_ack_pre(Ss, [Ip, Port, RIp, RPort, _, Seq, Id]) ->
  case [ S || S<-Ss, S#state.id == Id ] of
    [ S ] ->
      in_tcp_state(Ss, Id, syn_sent) andalso
        S#state.rcvd == S#state.seq andalso
        Ip    == S#state.ip    andalso
        Port  == S#state.port  andalso
        RIp   == S#state.rip   andalso
        RPort == S#state.rport andalso
        Seq   == S#state.seq;
    _ ->
      false
  end.

syn_ack_adapt(Ss, [_, _, _, _, Seq, _, Id]) ->
  case [ S || S<-Ss, S#state.id == Id ] of
    [ S ] ->
      [S#state.ip, S#state.port, S#state.rip,
       S#state.rport, Seq, S#state.seq, Id];
    _ ->
      false
  end.

syn_ack(Ip, Port, RemoteIp, RemotePort, Seq, Ack, _) ->
  Packet =
    #pkt{sport = RemotePort,
        dport  = Port,
        seq    = counter(Seq),
        ack    = counter(Ack),
        flags  = [ack, syn] },
  Data = encode(Ip, RemoteIp, Packet),
  inject(RemoteIp, Ip, Data),
  ok.

syn_ack_callouts(_S, [_Ip, _Port, _RemoteIp, _RemotePort, Seq, _Ack, Id]) ->
  ?SET(Id, rseq, {Seq, 1}),
  ?UNBLOCK({syn_sent, Id}, ok).


%% --- ack ---

%% ack_pre(S) ->
%%   in_tcp_state(S, [syn_rcvd, last_ack, fin_wait_1, closing]) andalso
%%   S#state.seq == S#state.rcvd.

ack_args(Ss) ->
  ?LET(S, elements(Ss),
       [S#state.ip, S#state.port,
        S#state.rip,
        S#state.rport,
        S#state.rseq,
        S#state.seq, S#state.id]).

ack_pre(Ss, [Ip,  Port, RIp, RPort, Seq, Ack, Id]) ->
  case [ S || S<-Ss, S#state.id == Id ] of
    [ S ] ->
      in_tcp_state(Ss, Id, [syn_rcvd, last_ack, fin_wait_1, closing]) andalso
        S#state.seq == S#state.rcvd andalso
        Ip    == S#state.ip    andalso
        Port  == S#state.port  andalso
        RIp   == S#state.rip   andalso
        RPort == S#state.rport andalso
        Seq   == S#state.rseq andalso
        Ack   == S#state.seq;
    _ ->
      false
  end.

ack_adapt(Ss, [_, _, _, _, _, _, Id]) ->
  case [ S || S<-Ss, S#state.id == Id ] of
    [ S ] ->
      [S#state.ip, S#state.port,
       S#state.rip,
       S#state.rport,
       S#state.rseq,
       S#state.seq, Id];
    _ ->
      false
  end.

ack(Ip,  Port, RemoteIp, RemotePort, Seq, Ack, _) ->
  Packet =
    #pkt{sport = RemotePort,
         dport = Port,
         seq   = counter(Seq),
         ack   = counter(Ack),
         flags = [ack] },
  Data = encode(RemoteIp, Ip, Packet),
  inject(RemoteIp, Ip, Data),
  ok.

ack_callouts(Ss, [_Ip, _Port, _RemoteIp, _RemotePort, _Seq, _Ack, Id]) ->
  [ S ] = [ S || S<-Ss, S#state.id == Id ],
  case S#state.tcp_state of
    syn_rcvd ->
      ?WHEN(S#state.socket_type == accept, ?UNBLOCK({accept, Id}, ok)),
      ?SET(Id, tcp_state, established);
    fin_wait_1 ->
      ?SET(Id, tcp_state, fin_wait_2);
    closing ->
      ?UNBLOCK({close, Id}, ok),
      ?SET(Id, tcp_state, time_wait);
    last_ack ->
      ?UNBLOCK({close, Id}, ok),
      ?APPLY(reset, [Id]),
      ?SET(Id, tcp_state, closed)
  end.

%% --- fin ---

%% fin_pre(S) ->
%%   in_tcp_state(S, [established, fin_wait_1, fin_wait_2]).

fin_agrs(Ss) ->
  ?LET(S, elements(Ss), 
       [S#state.ip, S#state.port,
        S#state.rip, S#state.rport,
        S#state.rseq, S#state.rcvd, S#state.id]). 

fin_pre(Ss, [Ip, Port, RIp, RPort, Seq, Ack, Id]) ->
  [ S ] = [ S || S<-Ss, S#state.id == Id ],
  in_tcp_state(Ss, Id, [established, fin_wait_1, fin_wait_2]) andalso
    Ip    == S#state.ip    andalso
    Port  == S#state.port  andalso
    RIp   == S#state.rip   andalso
    RPort == S#state.rport andalso
    Seq   == S#state.rseq andalso
    Ack   == S#state.rcvd.
    
fin_adapt(Ss, [_, _, _, _, _, _, Id]) -> 
  case [ S || S<-Ss, S#state.id == Id ] of
    [ S ] ->
      [S#state.ip, S#state.port,
       S#state.rip, S#state.rport,
       S#state.rseq, S#state.rcvd, Id];
    _ ->
      false
  end.

fin(Ip, Port, RemoteIp, RemotePort, Seq, Ack, _) ->
  Packet =
    #pkt{sport = RemotePort,
         dport = Port,
         seq   = counter(Seq),
         ack   = counter(Ack),
         flags = [ack, fin] },
  Data = encode(RemoteIp, Ip, Packet),
  inject(RemoteIp, Ip, Data),
  ok.

fin_callouts(Ss, [_Ip, _Port, _RemoteIp, _RemotePort, _Seq, _, Id]) ->
  [ S ] = [ S || S<-Ss, S#state.id == Id ],
  ?INC(Id, rseq),
  ?APPLY(sent_ack, [Id]),
  case S#state.tcp_state of
    established ->
      ?SET(Id, tcp_state, close_wait);
    fin_wait_1 ->
      case S#state.seq == S#state.rcvd of %% FIN+ACK ?
        true ->
          ?UNBLOCK({close, Id}, ok),
          ?SET(Id, tcp_state, time_wait);
        false ->
          ?SET(Id, tcp_state, closing)
      end;
    fin_wait_2  ->
      ?UNBLOCK({close, Id}, ok),
      ?SET(Id, tcp_state, time_wait)
  end.

%% --- deliver ---

%% deliver_pre(S) ->
%%   S#state.rcvd /= S#state.seq.

deliver_args(Ss) -> 
  [choose(1, length(Ss))].

deliver_pre(Ss, [Id]) ->
  [ S ] = [ S || S<-Ss, S#state.id == Id ],
  S#state.rcvd /= S#state.seq.

deliver(_) -> timer:sleep(1).

deliver_callouts(Ss, [Id]) ->
  [ S ] = [ S || S<-Ss, S#state.id == Id ],
  ?SET(Id, rcvd, S#state.seq).

%% -- Local operations -------------------------------------------------------

reset_callouts(_, [Id]) ->
  ?SET(Id, port,  undefined),
  ?SET(Id, rport, undefined),
  ?SET(Id, seq,   undefined),
  ?SET(Id, rseq,  undefined).

sent_syn_callouts(_, [Id]) ->
  ?MATCH(Packet, ?APPLY(sent, [Id])),
  Port = {call, erlang, element, [#pkt.sport, Packet]},
  ?ASSERT(?MODULE, check_packet, [Packet, '_', '_', [syn]]),
  ?SET(Id, seq, {{call, erlang, element, [#pkt.seq, Packet]}, 1}),
  ?RET(Port).

sent_ack_callouts(Ss, [Id]) ->
  [S] = [ S || S<-Ss, S#state.id == Id],
  ?MATCH(Packet, ?APPLY(sent, [Id])),
  ?ASSERT(?MODULE, check_packet, [Packet, S#state.seq, S#state.rseq, [ack]]),
  ?RET(ok).

sent_fin_callouts(Ss, [Id]) ->
  [S] = [ S || S<-Ss, S#state.id == Id],
  ?MATCH(Packet, ?APPLY(sent, [Id])),
  ?ASSERT(?MODULE, check_packet, [Packet, S#state.seq, S#state.rseq, [ack, fin]]),
  ?INC(Id, seq),
  ?RET(ok).

sent_syn_ack_callouts(Ss, [Id]) ->
  [S] = [ S || S<-Ss, S#state.id == Id],
  ?MATCH(Packet, ?APPLY(sent, [Id])),
  ?ASSERT(?MODULE, check_packet, [Packet, '_', S#state.rseq, [ack, syn]]),
  ?SET(Id, seq, {{call, erlang, element, [#pkt.seq, Packet]}, 1}),
  ?RET(ok).

sent_callouts(Ss, [Id]) ->
  [S] = [ S || S<-Ss, S#state.id == Id],
  ?MATCH({Packet, ok}, ?CALLOUT(ip, send_pkt, [?VAR, S#state.rip], ok)),
  ?ASSERT(?MODULE, verify_checksum, [S#state.ip, S#state.rip, Packet]),
  ?ASSERT(?MODULE, check_ports,     [S#state.port, S#state.rport, Packet]),
  ?RET(Packet).

set_socket_callouts(_, [Id]) ->
  ?MATCH({Socket, ok}, ?CALLOUT(mock, set_socket, [?VAR], ok)),
  ?SET(Id, socket, Socket).

set_next(Ss, _, [Id, Key, Value]) ->
  [ S ] = [ S || S<-Ss, S#state.id == Id],
  (Ss -- [ S ]) ++ [ setelement(Key, S, Value) ].

inc_next(Ss, _, [Id, Key]) ->
  [ S ] = [ S || S<-Ss, S#state.id == Id],
  N = case element(Key, S) of
        {Init, Offs}         -> {Init, Offs + 1};
        M when is_integer(M) -> M + 1;
        undefined -> undefined
      end,
  (Ss -- [ S ]) ++ [ setelement(Key, S, N) ].

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
  eqc:dont_print_counterexample(
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
  end))))).

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

