-module(etcpip_proc).

-behaviour(gen_server).

% API
-export([start_link/2, call/2, cast/2]).

% Callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-record(proc, {
    state,
    handle_call,
    handle_cast,
    handle_info
}).

%--- API -----------------------------------------------------------------------

start_link(Name, Spec) ->
    gen_server:start_link({local, Name}, ?MODULE, Spec, []).

call(Name, Call) -> gen_server:call(Name, Call).

cast(Name, Cast) -> gen_server:cast(Name, Cast).

%--- Callbacks -----------------------------------------------------------------

init(Spec) ->
    {ok, #proc{
        state = initialize(Spec),
        handle_call = maps:get(handle_call, Spec, fun default_handle_call/3),
        handle_cast = maps:get(handle_cast, Spec, fun default_handle_cast/2),
        handle_info = maps:get(handle_info, Spec, fun default_handle_info/2)
    }}.

handle_call(Call, From, #proc{handle_call = HandleCall} = Proc) ->
    {reply, Reply, State} = HandleCall(Call, From, Proc#proc.state),
    {reply, Reply, Proc#proc{state = State}}.

handle_cast(Cast, #proc{handle_cast = HandleCast} = Proc) ->
    {noreply, State} = HandleCast(Cast, Proc#proc.state),
    {noreply, Proc#proc{state = State}}.

handle_info(Info, #proc{handle_info = HandleInfo} = Proc) ->
    {noreply, State} = HandleInfo(Info, Proc#proc.state),
    {noreply, Proc#proc{state = State}}.

%--- Internal ------------------------------------------------------------------

initialize(#{init := Init}) -> Init();
initialize(Spec)            -> error({no_init, Spec}).

default_handle_call(_Call, _From, _State) -> error(not_implemented).

default_handle_cast(_Cast, _State) -> error(not_implemented).

default_handle_info(_Info, _State) -> error(not_implemented).
