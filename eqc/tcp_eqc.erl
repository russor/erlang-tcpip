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

-define(SET(Id, Key, Value), ?APPLY(set, [Id, #socket.Key, Value])).
-define(INC(Id, Key),        ?APPLY(inc, [Id, #socket.Key])).

-define(MAX_SOCKETS, 5).

-record(socket,{tcp_state = undefined, ip, port, rip, rport, socket,
               socket_type, seq, rcvd, rseq, id, parent, accepts = []}).

-record(state, {ip, sockets = []}).

initial_state() ->
  #state{}.

in_tcp_state(S, Id, TcpStates) when is_list(TcpStates) ->
  case get_socket(S, Id) of
    #socket{ tcp_state = St } -> lists:member(St, TcpStates);
    false -> false
  end;
in_tcp_state(Ss, Id, TcpState) ->
  in_tcp_state(Ss, Id, [TcpState]).

get_socket(S, Id) ->
  lists:keyfind(Id, #socket.id, S#state.sockets).

set_socket(S, Id, Sock) ->
  S#state{ sockets = lists:keystore(Id, #socket.id, S#state.sockets, Sock) }.

%% -- Generators ------------------------------------------------------------

ip()   -> ?LET(Ip, uint32(), return(int2ip(Ip))).
port() -> noshrink(uint16()).

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
  S#state.ip == undefined;
command_precondition_common(S, _Cmd) ->
  S#state.ip /= undefined.

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

start_next(S, _, [Ip]) ->
  S#state{ ip = Ip }.

%% --- open (connect) ---

%% open_pre(S) ->
%%   in_tcp_state(S, closed).

open_args(_) ->
  [ip(), port()].

%% We cannot use the _next to bind the socket, because we block
open(RemoteIp, RemotePort) ->
  mock:set_socket(tcp_con:usr_open(ip2int(RemoteIp), RemotePort)).

open_process(_, _) ->
  spawn.

open_callouts(_S, [RemoteIp, RemotePort]) ->
  ?MATCH(Id, ?APPLY(spawn_socket, [])),
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

listen_args(_) ->
  [port()].

listen_dynamicpre(S, [Port]) ->
  not lists:keymember(Port, #socket.port, S#state.sockets).

listen(Port) ->
  mock:set_socket(tcp_con:usr_listen(Port)).

listen_callouts(_S, [Port]) ->
  ?MATCH(Id, ?APPLY(spawn_socket, [])),
  ?SET(Id, tcp_state, listen),
  ?SET(Id, socket_type, listen),
  ?SET(Id, port, Port),
  ?APPLY(set_socket, [Id]).

%% --- accept ---

%% accept_pre(S) ->
%%   in_tcp_state(S, [listen, syn_rcvd, established, close_wait]) andalso
%%   S#socket.socket_type == listen.

accept_pre(S) ->
  [] /= S#state.sockets.

accept_args(S) ->
  ?LET(Sock, elements(S#state.sockets),
       [Sock#socket.socket, Sock#socket.id]).

accept_pre(S, [Socket, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{} ->
      Sock#socket.socket == Socket andalso
      Sock#socket.socket_type == listen andalso
      in_tcp_state(S, Id, [listen, syn_rcvd, established, close_wait]);
    false -> false
  end.

accept_adapt(S, [_, Id]) -> 
 case get_socket(S, Id) of
   #socket{socket = Socket} ->
     [Socket, Id];
   _ ->
     false
 end.

accept(Socket, _) ->
  case tcp_con:usr_accept(Socket) of
    closed -> closed;
    Sock   -> mock:set_socket(Sock)
  end.

accept_callouts(S, [_Socket, Id]) ->
  case [ Sock || Sock <- S#state.sockets,
                 Sock#socket.parent == Id,
                 Sock#socket.tcp_state == established,
                 Sock#socket.socket == undefined ] of
    [Sock | _] ->
      NewId = Sock#socket.id,
      ?APPLY(set_socket, [NewId]);
    [] ->
      Sock = get_socket(S, Id),
      ?SET(Id, accepts, Sock#socket.accepts ++ [?SELF]),
      ?MATCH(NewId, ?BLOCK({accept, ?SELF})),
      ?APPLY(set_socket, [NewId])
  end.

accept_process(_S, [_Socket, _]) ->
  spawn.

%% --- close ---

%% close_pre(S) ->
%%   in_tcp_state(S, [established, close_wait, listen]) andalso
%%   lists:member(S#socket.socket_type, [accept, connect]).

close_pre(S) ->
  [] /= S#state.sockets.

close_args(S) ->
  ?LET(Sock, elements(S#state.sockets),
       [Sock#socket.socket, Sock#socket.id]).

close_pre(S, [Socket, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{} ->
      Sock#socket.socket == Socket andalso
      Socket /= undefined andalso
      in_tcp_state(S, Id, [established, close_wait, listen]) andalso
      lists:member(Sock#socket.socket_type, [accept, connect, listen]);
    _ ->
      false
  end.

close_adapt(S, [_, Id]) -> 
  case get_socket(S, Id) of
    #socket{socket = Socket} ->
      [Socket, Id];
    _ ->
      false
  end.

close(Socket, _) ->
  Root = self(),
  %% Work around for RACE CONDITION 4
  Pid = spawn(fun() -> Root ! {self(), tcp_con:usr_close(Socket)} end),
  receive {Pid, _Res} -> ok end.


close_callouts(S, [_, Id]) ->
  Sock = get_socket(S, Id),
  case {Sock#socket.tcp_state, Sock#socket.socket_type} of
    {listen, accept} ->
      ?UNBLOCK({accept, Id}, ok),
      ?APPLY(reset, [Id]),
      ?SET(Id, tcp_state, closed),
      ?SET(Id, socket_type, undefined);
    {_, listen} ->
      ?APPLY(reset, [Id]),
      ?SET(Id, tcp_state, closed),
      ?SET(Id, socket_type, undefined);
    {close_wait, _} ->
      ?APPLY(sent_fin, [Id]),
      ?SET(Id, tcp_state, last_ack),
      ?BLOCK({close, Id});
    {established, _} ->
      ?APPLY(sent_fin, [Id]),
      ?SET(Id, tcp_state, fin_wait_1),
      ?BLOCK({close, Id})
  end.

close_process(_, _) -> spawn.


%% -- Backend operations -----------------------------------------------------

%% --- syn ---

%% syn_pre(S) ->
%%   in_tcp_state(S, listen).

syn_pre(S) ->
  [] /= S#state.sockets.

syn_args(S) ->
  ?LET(Sock, elements(S#state.sockets),
       [Sock#socket.ip, Sock#socket.port, ip(), port(), uint32(), Sock#socket.id]).

syn(Ip, Port, RemoteIp, RemotePort, RemoteSeq, _Id) ->
  Packet =
    #pkt{sport = RemotePort,
         dport = Port,
         seq   = RemoteSeq,
         flags = [syn] },
  Data = encode(RemoteIp, Ip, Packet),
  inject(RemoteIp, Ip, Data),
  ok.

syn_pre(S, Args = [_, _, _, _, _, Id]) ->
  in_tcp_state(S, Id, listen) andalso
  syn_adapt(S, Args) == Args.

syn_adapt(S, [_, _, Ip, Port, Seq, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{} ->
      [Sock#socket.ip, Sock#socket.port, Ip, Port, Seq, Id];
    _ ->
      false
  end.

syn_callouts(_S, [_Ip,  Port, RemoteIp, RemotePort, RemoteSeq, Id]) ->
  ?MATCH(NewId, ?APPLY(spawn_socket, [])),
  ?SET(NewId, port,   Port),
  ?SET(NewId, rip,    RemoteIp),
  ?SET(NewId, rport,  RemotePort),
  ?SET(NewId, rseq,   {RemoteSeq, 1}),
  ?SET(NewId, socket_type, accept),
  ?SET(NewId, parent, Id),
  ?APPLY(sent_syn_ack, [NewId]),
  ?SET(NewId, tcp_state, syn_rcvd).


%% --- syn_ack ---

%% syn_ack_pre(S) ->
%%   in_tcp_state(S, syn_sent) andalso
%%   S#socket.rcvd == S#socket.seq.

syn_ack_pre(S) ->
  [] /= S#state.sockets.

syn_ack_args(S) ->
  ?LET(Sock, elements(S#state.sockets),
       [Sock#socket.ip, Sock#socket.port, Sock#socket.rip,
        Sock#socket.rport, uint32(), Sock#socket.seq, Sock#socket.id]).

syn_ack_pre(S, [Ip, Port, RIp, RPort, _, Seq, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{} ->
      in_tcp_state(S, Id, syn_sent) andalso
        Sock#socket.rcvd == Sock#socket.seq andalso
        Ip    == Sock#socket.ip    andalso
        Port  == Sock#socket.port  andalso
        RIp   == Sock#socket.rip   andalso
        RPort == Sock#socket.rport andalso
        Seq   == Sock#socket.seq;
    _ ->
      false
  end.

syn_ack_adapt(S, [_, _, _, _, Seq, _, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{} ->
      [Sock#socket.ip, Sock#socket.port, Sock#socket.rip,
       Sock#socket.rport, Seq, Sock#socket.seq, Id];
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
%%   S#socket.seq == S#socket.rcvd.

ack_pre(S) ->
  [] /= S#state.sockets.

ack_args(S) ->
  ?LET(Sock, elements(S#state.sockets),
       [Sock#socket.ip, Sock#socket.port,
        Sock#socket.rip,
        Sock#socket.rport,
        Sock#socket.rseq,
        Sock#socket.seq, Sock#socket.id]).

ack_pre(S, [Ip,  Port, RIp, RPort, Seq, Ack, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{} ->
      in_tcp_state(S, Id, [syn_rcvd, last_ack, fin_wait_1, closing]) andalso
        Sock#socket.seq == Sock#socket.rcvd andalso
        Ip    == Sock#socket.ip    andalso
        Port  == Sock#socket.port  andalso
        RIp   == Sock#socket.rip   andalso
        RPort == Sock#socket.rport andalso
        Seq   == Sock#socket.rseq  andalso
        Ack   == Sock#socket.seq;
    _ ->
      false
  end.

ack_adapt(S, [_, _, _, _, _, _, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{} ->
      [Sock#socket.ip, Sock#socket.port,
       Sock#socket.rip,
       Sock#socket.rport,
       Sock#socket.rseq,
       Sock#socket.seq, Id];
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

ack_callouts(S, [_Ip, _Port, _RemoteIp, _RemotePort, _Seq, _Ack, Id]) ->
  Sock = get_socket(S, Id),
  case Sock#socket.tcp_state of
    syn_rcvd ->
      P = Sock#socket.parent,
      Parent = get_socket(S, P),
      case Parent#socket.accepts of
        [Pid | Pids] ->
          ?UNBLOCK({accept, Pid}, Id),
          ?SET(P, accepts, Pids);
        [] -> ?EMPTY
      end,
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
       [S#socket.ip, S#socket.port,
        S#socket.rip, S#socket.rport,
        S#socket.rseq, S#socket.rcvd, S#socket.id]). 

fin_pre(Ss, [Ip, Port, RIp, RPort, Seq, Ack, Id]) ->
  [ S ] = [ S || S<-Ss, S#socket.id == Id ],
  in_tcp_state(Ss, Id, [established, fin_wait_1, fin_wait_2]) andalso
    Ip    == S#socket.ip    andalso
    Port  == S#socket.port  andalso
    RIp   == S#socket.rip   andalso
    RPort == S#socket.rport andalso
    Seq   == S#socket.rseq andalso
    Ack   == S#socket.rcvd.
    
fin_adapt(Ss, [_, _, _, _, _, _, Id]) -> 
  case [ S || S<-Ss, S#socket.id == Id ] of
    [ S ] ->
      [S#socket.ip, S#socket.port,
       S#socket.rip, S#socket.rport,
       S#socket.rseq, S#socket.rcvd, Id];
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
  [ S ] = [ S || S<-Ss, S#socket.id == Id ],
  ?INC(Id, rseq),
  ?APPLY(sent_ack, [Id]),
  case S#socket.tcp_state of
    established ->
      ?SET(Id, tcp_state, close_wait);
    fin_wait_1 ->
      case S#socket.seq == S#socket.rcvd of %% FIN+ACK ?
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
%%   S#socket.rcvd /= S#socket.seq.

deliver_pre(S) ->
  [] /= S#state.sockets.

deliver_args(S) ->
  ?LET(Sock, elements(S#state.sockets),
       [Sock#socket.id]).

deliver_pre(S, [Id]) ->
  Sock = get_socket(S, Id),
  is_record(Sock, socket) andalso
  Sock#socket.rcvd /= Sock#socket.seq.

deliver(_) -> timer:sleep(1).

deliver_callouts(S, [Id]) ->
  Sock = get_socket(S, Id),
  ?SET(Id, rcvd, Sock#socket.seq).

deliver_features(S, [Id], _) ->
  [ {Id, [Sock#socket.tcp_state || Sock <- S#state.sockets ]} ].

%% -- Local operations -------------------------------------------------------

spawn_socket_pre(S, _) ->
  length(S#state.sockets) < ?MAX_SOCKETS.

spawn_socket_next(S, _, [], Meta) ->
  Id = proplists:get_value(id, Meta),
  Sock = #socket{ id = Id, ip = S#state.ip },
  S#state{ sockets = S#state.sockets ++ [Sock] }.

spawn_socket_return(_, [], Meta) ->
  proplists:get_value(id, Meta).

reset_callouts(_, [Id]) ->
  ?SET(Id, port,  undefined),
  ?SET(Id, rport, undefined),
  ?SET(Id, rip, undefined),
  ?SET(Id, socket, undefined),
  ?SET(Id, rcvd,   undefined),
  ?SET(Id, seq,   undefined),
  ?SET(Id, rseq,  undefined).

sent_syn_callouts(_, [Id]) ->
  ?MATCH(Packet, ?APPLY(sent, [Id])),
  Port = {call, erlang, element, [#pkt.sport, Packet]},
  ?ASSERT(?MODULE, check_packet, [Packet, '_', '_', [syn]]),
  ?SET(Id, seq, {{call, erlang, element, [#pkt.seq, Packet]}, 1}),
  ?RET(Port).

sent_ack_callouts(S, [Id]) ->
  Sock = get_socket(S, Id),
  ?MATCH(Packet, ?APPLY(sent, [Id])),
  ?ASSERT(?MODULE, check_packet, [Packet, Sock#socket.seq, Sock#socket.rseq, [ack]]),
  ?RET(ok).

sent_fin_callouts(S, [Id]) ->
  Sock = get_socket(S, Id),
  ?MATCH(Packet, ?APPLY(sent, [Id])),
  ?ASSERT(?MODULE, check_packet, [Packet, Sock#socket.seq, Sock#socket.rseq, [ack, fin]]),
  ?INC(Id, seq),
  ?RET(ok).

sent_syn_ack_callouts(S, [Id]) ->
  Sock = get_socket(S, Id),
  ?MATCH(Packet, ?APPLY(sent, [Id])),
  ?ASSERT(?MODULE, check_packet, [Packet, '_', Sock#socket.rseq, [ack, syn]]),
  ?SET(Id, seq, {{call, erlang, element, [#pkt.seq, Packet]}, 1}),
  ?RET(ok).

sent_callouts(S, [Id]) ->
  Sock = get_socket(S, Id),
  ?MATCH({Packet, ok}, ?CALLOUT(ip, send_pkt, [?VAR, Sock#socket.rip], ok)),
  ?ASSERT(?MODULE, verify_checksum, [Sock#socket.ip, Sock#socket.rip, Packet]),
  ?ASSERT(?MODULE, check_ports,     [Sock#socket.port, Sock#socket.rport, Packet]),
  ?RET(Packet).

set_socket_callouts(_, [Id]) ->
  ?MATCH({Socket, ok}, ?CALLOUT(mock, set_socket, [?VAR], ok)),
  ?SET(Id, socket, Socket).

set_next(S, _, [Id, Key, Value]) ->
  Sock = get_socket(S, Id),
  set_socket(S, Id, setelement(Key, Sock, Value)).

inc_next(S, _, [Id, Key]) ->
  Sock = get_socket(S, Id),
  N = case element(Key, Sock) of
        {Init, Offs}         -> {Init, Offs + 1};
        M when is_integer(M) -> M + 1;
        undefined -> undefined
      end,
  set_socket(S, Id, setelement(Key, Sock, N)).

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
    TcpStates = [ TcpS || #socket{tcp_state = TcpS} <- lists:map(fun eqc_statem:history_state/1, H) ++ [S] ],
    check_command_names(Cmds,
      measure(length, commands_length(Cmds),
      aggregate(TcpStates,
      aggregate(adjacent(TcpStates),
      aggregate(call_features(H),
      eqc_component:pretty_commands(?MODULE, Cmds, {H, S, Res},
        Res == ok))))))
  end))))).

cleanup() -> cleanup([]).
cleanup(_Sockets) ->
  [ catch exit(whereis(P), kill)
    || P <- [tcp_reader, tcp_writer, tcp, iss, tcp_pool, checksum] ],
  timer:sleep(1).

used_sockets(H, S) ->
  used_sockets([H, S]).

used_sockets(#socket{ socket = Socket }) ->
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

