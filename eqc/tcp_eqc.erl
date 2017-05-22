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

-compile([export_all, nowarn_export_all]).

-ifdef(PULSE).
-compile({parse_transform, pulse_instrument}).
-compile({pulse_skip, [sleep/1]}).
-define(COMPONENT, pulse_component).
-define(MOCKING, pulse_mocking).
-else.
-define(COMPONENT, eqc_component).
-define(MOCKING, eqc_mocking).
-endif.

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
%%  RACE CONDITION 5
%%
%%    Race condition between ACK and usr_accept(), resulting in dropped connection
%%    and leaking internal {open_con, _} message.
%%
%%    Involved actors
%%      ListenSocket
%%      Connection1: established, in open_queue
%%      Connection2: in syn_rcvd
%%      User
%%
%%    User
%%      usr_accept()
%%        ListenSocket ! {subscribe, listener_queue, User}
%%
%%    ListenSocket
%%      receive {subscribe, listener_queue, User}
%%      pop Connection1 from open_queue
%%      User ! {open_con, Connection1}
%%
%%    Connection2
%%      receive ACK
%%      ListenSocket ! {state, established, Connection2}
%%
%%    ListenSocket
%%      receive {state, established, Connection2}
%%      pop User form listener_queue      %% second open_con message to User
%%      User ! {open_con, Connection2}    %% causing Connection2 to be dropped
%%
%%    User
%%      receive {open_con, Connection1}
%%      ListenSocket ! {unsubscribe, listener_queue}  %% unsubscribing too late

%% -- State ------------------------------------------------------------------

-define(SET(Id, Key, Value), ?APPLY(set, [Id, #socket.Key, Value])).
-define(INC(Id, Key),        ?APPLY(inc, [Id, #socket.Key])).
-define(UPD(Id, Key, Pat, Body),
  ?APPLY(upd, [Id, #socket.Key, fun(Pat) -> Body end])).

-define(MAX_SOCKETS, 5).

-record(socket,{tcp_state = undefined, ip, port, rip, rport, socket,
               socket_type, seq, rcvd, rseq, id, parent, blocked = [],
               accept_queue = []}).

-record(state, {ip, sockets = []}).

initial_state() ->
  #state{}.

in_tcp_state(Sock, TcpState) when not is_list(TcpState) ->
  in_tcp_state(Sock, [TcpState]);
in_tcp_state(#socket{tcp_state = St}, TcpStates) ->
  lists:member(St, TcpStates);
in_tcp_state(_, _) -> false.

in_tcp_state(S, Id, TcpStates) ->
  in_tcp_state(get_socket(S, Id), TcpStates).

sockets_in_state(S, TcpStates) when is_list(TcpStates) ->
  [ Sock || Sock <- S#state.sockets,
            lists:member(Sock#socket.tcp_state, TcpStates) ];
sockets_in_state(S, TcpState) ->
  sockets_in_state(S, [TcpState]).


get_socket(S, Id) ->
  lists:keyfind(Id, #socket.id, S#state.sockets).

set_socket(S, Id, Sock) ->
  S#state{ sockets = lists:keystore(Id, #socket.id, S#state.sockets, Sock) }.

%% -- Generators ------------------------------------------------------------

ip()   -> ?LET(Ip, noshrink(uint32()), return(int2ip(Ip))).
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

open_pre(S) ->
  length(S#state.sockets) < ?MAX_SOCKETS.

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
  ?SET(Id, socket_type, connect),
  ?SET(Id, port, Port),
  ?BLOCK({syn_sent, Id}),
  ?PAR([ ?APPLY(set_socket, [Id])
       , ?APPLY(sent_ack, [Id]) ]),
  ?SET(Id, tcp_state, established).

%% --- listen ---

listen_pre(S) ->
  length(S#state.sockets) < ?MAX_SOCKETS.

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

accept_pre(S) ->
  [] /= sockets_in_state(S, listen).

accept_args(S) ->
  ?LET(Sock, elements(sockets_in_state(S, listen)),
       [Sock#socket.socket, Sock#socket.id]).

accept_pre(S, [Socket, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{} ->
      Sock#socket.socket == Socket andalso
      Sock#socket.tcp_state == listen;
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
  Sock = get_socket(S, Id),
  case Sock#socket.accept_queue of
    [NewId | _] ->
      ?UPD(Id, accept_queue, [_ | Q], Q),
      ?APPLY(set_socket, [NewId]);
    [] ->
      ?SET(Id, blocked, Sock#socket.blocked ++ [?SELF]),
      ?MATCH(NewId, ?BLOCK({accept, ?SELF})),
      ?WHEN(NewId /= closed, ?APPLY(set_socket, [NewId]))
  end.

accept_process(_S, [_Socket, _]) ->
  spawn.

%% --- close ---

close_states() ->
  [established, close_wait, listen].

close_sockets(S) ->
  [ Sock || Sock <- sockets_in_state(S, close_states()),
            Sock#socket.socket /= undefined ].

close_pre(S) ->
  [] /= close_sockets(S).

close_args(S) ->
  ?LET(Sock, elements(close_sockets(S)),
       [Sock#socket.socket, Sock#socket.id]).

close_pre(S, [Socket, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{socket = Socket} ->
      Socket /= undefined andalso
      in_tcp_state(Sock, close_states());
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
  case Sock#socket.socket_type of
    listen ->
      ?PAR([ ?UNBLOCK({accept, Pid}, closed) || Pid <- Sock#socket.blocked ] ++
           %% BUG: only sends FIN to connections in the accept_queue
           [ ?APPLY(do_close, [Child]) || Child <- Sock#socket.accept_queue ]),
           %% Should be this:
           %% [ ?APPLY(do_close, [Child#socket.id]) ||
           %%   Child <- S#state.sockets, Child#socket.parent == Id,
           %%   Child#socket.socket == undefined ]))),
      ?APPLY(reset, [Id]);
    _ ->
      ?APPLY(do_close, [Id]),
      ?SET(Id, blocked, [?SELF]),
      ?BLOCK({close, ?SELF})
  end.

close_process(_, _) -> spawn.

do_close_callouts(S, [Id]) ->
  Sock = get_socket(S, Id),
  case Sock#socket.tcp_state of
    close_wait ->
      ?APPLY(sent_fin, [Id]),
      ?SET(Id, tcp_state, last_ack);
    established ->
      ?APPLY(sent_fin, [Id]),
      ?SET(Id, tcp_state, fin_wait_1);
    _ ->
      ?EMPTY
  end.

%% -- Backend operations -----------------------------------------------------

%% --- syn ---

syn_pre(S) ->
  length(S#state.sockets) < ?MAX_SOCKETS andalso
  [] /= sockets_in_state(S, listen).

syn_args(S) ->
  ?LET(Sock, elements(sockets_in_state(S, listen)),
       [Sock#socket.ip, Sock#socket.port, ip(), port(), uint32(), Sock#socket.id]).

syn_pre(S, Args = [_, _, _, _, _, Id]) ->
  in_tcp_state(S, Id, listen) andalso
  syn_adapt(S, Args) == Args.

syn(Ip, Port, RemoteIp, RemotePort, RemoteSeq, _Id) ->
  Packet =
    #pkt{sport = RemotePort,
         dport = Port,
         seq   = RemoteSeq,
         flags = [syn] },
  Data = encode(RemoteIp, Ip, Packet),
  inject(RemoteIp, Ip, Data),
  ok.

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

syn_ack_sockets(S) ->
  [ Sock || Sock <- sockets_in_state(S, syn_sent),
            Sock#socket.rcvd == Sock#socket.seq ].

syn_ack_pre(S) ->
  [] /= syn_ack_sockets(S).

syn_ack_args(S) ->
  ?LET(Sock, elements(syn_ack_sockets(S)),
       [Sock#socket.ip, Sock#socket.port, Sock#socket.rip,
        Sock#socket.rport, uint32(), Sock#socket.seq, Sock#socket.id]).

syn_ack_pre(S, [Ip, Port, RIp, RPort, _, Seq, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{} ->
      in_tcp_state(Sock, syn_sent) andalso
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

ack_states() ->
  [syn_rcvd, last_ack, fin_wait_1, closing].

ack_sockets(S) ->
  [ Sock || Sock <- sockets_in_state(S, ack_states()),
            Sock#socket.seq == Sock#socket.rcvd ].

ack_pre(S) ->
  [] /= ack_sockets(S).

ack_args(S) ->
  ?LET(Sock, elements(ack_sockets(S)),
       [Sock#socket.ip, Sock#socket.port,
        Sock#socket.rip,
        Sock#socket.rport,
        Sock#socket.rseq,
        Sock#socket.seq, Sock#socket.id]).

ack_pre(S, [Ip,  Port, RIp, RPort, Seq, Ack, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{} ->
      in_tcp_state(Sock, ack_states()) andalso
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
      ?SET(Id, tcp_state, established),
      P = Sock#socket.parent,
      case get_socket(S, P) of
        #socket{blocked = [Pid | Pids]} ->
          ?UNBLOCK({accept, Pid}, Id),
          ?SET(P, blocked, Pids);
        false -> ?EMPTY;
        _     -> ?UPD(P, accept_queue, Q, Q ++ [Id])
      end;
    fin_wait_1 ->
      ?SET(Id, tcp_state, fin_wait_2);
    closing ->
      ?APPLY(unblock_close, [Id]),
      ?SET(Id, tcp_state, time_wait);
    last_ack ->
      ?APPLY(unblock_close, [Id]),
      ?APPLY(reset, [Id])
  end.

%% --- fin ---

fin_states() ->
  [established, fin_wait_1, fin_wait_2].

fin_pre(S) ->
  [] /= sockets_in_state(S, fin_states()).

fin_args(S) ->
  ?LET(Sock, elements(sockets_in_state(S, fin_states())),
       [Sock#socket.ip, Sock#socket.port,
        Sock#socket.rip, Sock#socket.rport,
        Sock#socket.rseq, Sock#socket.rcvd, Sock#socket.id]).

fin_pre(S, Args = [_Ip, _Port, _RIp, _RPort, _Seq, _Ack, Id]) ->
  in_tcp_state(S, Id, fin_states()) andalso
  fin_adapt(S, Args) == Args.

fin_adapt(S, [_, _, _, _, _, _, Id]) ->
  case get_socket(S, Id) of
    Sock = #socket{} ->
      [Sock#socket.ip, Sock#socket.port,
       Sock#socket.rip, Sock#socket.rport,
       Sock#socket.rseq, Sock#socket.rcvd, Id];
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

fin_callouts(S, [_Ip, _Port, _RemoteIp, _RemotePort, _Seq, _, Id]) ->
  Sock = get_socket(S, Id),
  ?INC(Id, rseq),
  ?APPLY(sent_ack, [Id]),
  case Sock#socket.tcp_state of
    established ->
      ?SET(Id, tcp_state, close_wait);
    fin_wait_1 ->
      case Sock#socket.seq == Sock#socket.rcvd of %% FIN+ACK ?
        true ->
          ?APPLY(unblock_close, [Id]),
          ?SET(Id, tcp_state, time_wait);
        false ->
          ?SET(Id, tcp_state, closing)
      end;
    fin_wait_2  ->
      ?APPLY(unblock_close, [Id]),
      ?SET(Id, tcp_state, time_wait)
  end.

%% --- deliver ---

deliver_sockets(S) ->
  [ Sock || Sock <- S#state.sockets,
            Sock#socket.rcvd /= Sock#socket.seq ].

deliver_pre(S) ->
  [] /= deliver_sockets(S).

deliver_args(S) ->
  ?LET(Sock, elements(deliver_sockets(S)),
       [Sock#socket.id]).

deliver_pre(S, [Id]) ->
  lists:member(get_socket(S, Id), deliver_sockets(S)).

deliver(_) -> timer:sleep(1).

deliver_callouts(S, [Id]) ->
  Sock = get_socket(S, Id),
  ?SET(Id, rcvd, Sock#socket.seq).

%% --- timeout ---

timeout_pre(S) ->
  [] /= sockets_in_state(S, time_wait).

timeout_args(S) ->
  ?LET(Sock, elements(sockets_in_state(S, time_wait)),
    [Sock#socket.id]).

timeout_pre(S, [Id]) ->
  in_tcp_state(S, Id, time_wait).

timeout(_) -> timer:sleep(1).

%% TODO: Not sure if this is really ok. Check the spec to see how the TIME_WAIT
%% state really works.
timeout_callouts(_, [Id]) ->
  ?APPLY(reset, [Id]).

%% -- Local operations -------------------------------------------------------

spawn_socket_pre(S, _) ->
  length(S#state.sockets) < ?MAX_SOCKETS.

spawn_socket_next(S, _, [], Meta) ->
  Id = proplists:get_value(id, Meta),
  Sock = #socket{ id = Id, ip = S#state.ip },
  S#state{ sockets = S#state.sockets ++ [Sock] }.

spawn_socket_return(_, [], Meta) ->
  proplists:get_value(id, Meta).

reset_next(S, _, [Id]) ->
  S#state{sockets = lists:keydelete(Id, #socket.id, S#state.sockets)}.

reset_features(S, [Id], _) ->
  [ {(get_socket(S, Id))#socket.tcp_state, '->', closed} ].

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
  PortMatch = if Sock#socket.rport /= undefined -> Sock#socket.rport;
                 true -> ?WILDCARD
              end,
  ?MATCH({Packet, ok}, ?CALLOUT(ip, send_pkt, [?VAR, Sock#socket.rip, PortMatch], ok)),
  ?ASSERT(?MODULE, verify_checksum, [Sock#socket.ip, Sock#socket.rip, Packet]),
  ?ASSERT(?MODULE, check_ports,     [Sock#socket.port, Sock#socket.rport, Packet]),
  ?RET(Packet).

set_socket_callouts(_, [Id]) ->
  ?MATCH({Socket, ok}, ?CALLOUT(mock, set_socket, [?VAR], ok)),
  ?SET(Id, socket, Socket).

unblock_close_callouts(S, [Id]) ->
  Sock = get_socket(S, Id),
  ?PAR([ ?UNBLOCK({close, Pid}, ok) || Pid <- Sock#socket.blocked ]).

upd_next(S, _, [Id, Key, Fun]) ->
  Sock = get_socket(S, Id),
  set_socket(S, Id, setelement(Key, Sock, Fun(element(Key, Sock)))).

set_next(S, _, [Id, Key, Value]) ->
  Sock = get_socket(S, Id),
  set_socket(S, Id, setelement(Key, Sock, Value)).

set_features(S, [Id, Key, Value], _) ->
  [ {(get_socket(S, Id))#socket.tcp_state, '->', Value}
    || Key == #socket.tcp_state ].

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

take(N, Xs) -> lists:sublist(Xs, 1, N).

%% -- Property ---------------------------------------------------------------

invariant(S) ->
  [] /= command_list(S).

weight(_S, listen)  -> 1;
weight(_S, open)    -> 1;
weight(_S, close)   -> 2;
weight(_S, deliver) -> 10;
weight(_S, fin)     -> 1;
weight(_S, _Cmd)    -> 3.

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

sleep(N) ->
  timer:sleep(N).

-ifdef(PULSE).
run_test(Seed, Cmds) ->
  HSRFun = pulse:run(fun() ->
    ?MOCKING:start_mocking(api_spec()),
    error_logger:tty(false),
    cleanup(),
    checksum:start(),
    HSR = ?COMPONENT:run_commands(Cmds, [{command_timeout, 300000}]),
    cleanup(),
    ?MOCKING:stop_mocking(),
    fun() -> HSR end    %% return a function to make trace less verbose
  end, [{seed, Seed}, single_mailbox, {strategy, unfair}]),
  [ sleep(100) || Res /= ok ],  %% to avoid interleaving pulse trace and pretty_commands
  HSR = {H, _S, Res} = HSRFun(),
  check_command_names(Cmds,
    measure(length, commands_length(Cmds),
    aggregate(with_title(transitions), [ Tr || Tr = {_, '->', _} <- call_features(H) ],
    eqc_component:pretty_commands(?MODULE, Cmds, HSR,
      Res == ok)))).
-else.
run_test(_Seed, Cmds) ->
  ?MOCKING:start_mocking(api_spec()),
  error_logger:tty(false),
  cleanup(),
  checksum:start(),
  {H, S, Res} = ?COMPONENT:run_commands(Cmds),
  cleanup(),
  check_command_names(Cmds,
    measure(length, commands_length(Cmds),
    aggregate(with_title(transitions), [ Tr || Tr = {_, '->', _} <- call_features(H) ],
    eqc_component:pretty_commands(?MODULE, Cmds, {H, S, Res},
      Res == ok)))).
-endif.

prop_tcp() ->
  eqc_statem:show_states(
  eqc:dont_print_counterexample(
  with_parameter(default_process, worker,
  with_parameter(color, true,
  ?FORALL(Seed, ?LAZY(os:timestamp()),
  ?FORALL(Cmds, ?COMPONENT:commands(?MODULE),
    run_test(Seed, Cmds))))))).

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
     mocking = ?MOCKING,
     modules =
       [ #api_module{
            name = ip, fallback = ?MODULE,
            functions =
              [ #api_fun{ name = send_pkt, arity = 3 }] },
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
  DecodedData = #pkt{dport = DPort} =  tcp_pkt:decode(Data),
  ip:send_pkt(DecodedData, int2ip(DstIp), DPort).

