%%%=============================================================================
%%% Copyright (c) 2017 Lindenbaum GmbH
%%%
%%% Permission to use, copy, modify, and/or distribute this software for any
%%% purpose with or without fee is hereby granted, provided that the above
%%% copyright notice and this permission notice appear in all copies.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%%%
%%% @doc
%%% An ITDM (Internal TDM) parser with optional channel payload extraction.
%%%
%%% @see https://www.picmg.org/product/internal-tdm-specification/
%%% @end
%%%=============================================================================

-module(pcap_itdm).

-behaviour(pcap).

-export([options/0,
         parser/1]).

-record(flow, {
          mode           :: 1 | 125,
          routings = #{} :: #{non_neg_integer() => non_neg_integer()}}).

-record(state, {
          channel     :: undefined | non_neg_integer(),
          flow        :: undefined | non_neg_integer(),
          flows = #{} :: #{{binary(), non_neg_integer()} => #flow{}}}).

-define(LOG(Fmt, Args), io:format(Fmt ++ "~n", Args)).

%%%=============================================================================
%%% API
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @doc
%% Returns the options applicable for the ITDM parser.
%% @end
%%------------------------------------------------------------------------------
-spec options() -> [getopt:option_spec()].
options() ->
    [{channel,
      undefined,
      "channel",
      {integer, undefined},
      atom_to_list(?MODULE) ++ " - ITDM channel to extract"},
     {flow,
      undefined,
      "flow",
      {integer, undefined},
      atom_to_list(?MODULE) ++ " - ITDM flow to examine"}].

%%------------------------------------------------------------------------------
%% @doc
%% Returns a new ITDM parser.
%%
%% Please note that the parser only works on complete traces, that means the
%% PCAP trace must contain the flow establishment (AFI_REQ/AFI_RSP) and for the
%% 125us mode also the connection setup phase.
%%
%% This parser can either be used to print interesting ITDM control messages
%% and/or to extract the payload of specific ITDM channel. If this is desired
%% the option `{channel, Channel}' must be given in the options list. The
%% channel to extract can be further specified, e.g. by examining only a certain
%% flow using the option `{flow, FlowUID}'.
%%
%% If packets for the specific `Channel' can be found in the trace, the parser
%% will extract the payload into files of the form
%% DEST_MAC-FLOW_UID-ITDM_MODE-CHANNEL_NUM.raw, e.g.
%% 00:40:42:26:40:00-16-125-1.raw.
%% @end
%%------------------------------------------------------------------------------
-spec parser(proplists:proplist()) -> pcap:parser(#state{}).
parser(Opts) ->
    Channel = proplists:get_value(channel, Opts),
    Flow = proplists:get_value(flow, Opts),
    {fun itdm_parser/6, #state{channel = Channel, flow = Flow}}.

%%%=============================================================================
%%% Internal Functions
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
-spec itdm_parser(any(), any(), any(), any(), binary(), #state{}) -> #state{}.
itdm_parser(_TsSec, _TsUSec, _InclLen, _OrigLen, Data, State) ->
    case Data of
        %% Only MPLS-switched ethernet traffic
        <<Dst:6/binary, Src:6/binary, 16#8847:16, Rest/binary>> ->
            parse_mpls(Rest, Dst, Src, State);
        _ ->
            State
    end.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
parse_mpls(<<_:32, Rest/binary>>, Dst, Src, State) ->
    parse_sfp(Rest, Dst, Src, State);
parse_mpls(_, _, _, State) ->
    State.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
parse_sfp(<<_:88, 0:24, Rest/binary>>, Dst, Src, State) ->
    parse_itdm_ctrl(Rest, Dst, Src, State);
parse_sfp(<<_:88, UID:24, Rest/binary>>, Dst, Src, State)
  when State#state.flow =:= undefined; State#state.flow =:= UID ->
    case maps:find({Dst, UID}, State#state.flows) of
        {ok, #flow{mode = 1}} ->
            parse_itdm_1ms(Rest, Dst, Src, UID, State);
        {ok, #flow{mode = 125}} ->
            parse_itdm_125us(Rest, Dst, Src, UID, State);
        error ->
            State
    end;
parse_sfp(_, _, _, State) ->
    State.

%%------------------------------------------------------------------------------
%% @private
%% Only inspect AFI_RSP for ITDM Mode.
%%------------------------------------------------------------------------------
parse_itdm_ctrl(<<_:32, 2:8, UID:24, 1:8, _/binary>>, _Dst, Src, State) ->
    ?LOG("NEW FLOW - Dst:~s UID:~w Mode:~s", [mac_address(Src), UID, "1ms"]),
    add_flow(Src, UID, 1, State);
parse_itdm_ctrl(<<_:32, 2:8, UID:24, 2:8, _/binary>>, _Dst, Src, State) ->
    ?LOG("NEW FLOW - Dst:~s UID:~w Mode:~s", [mac_address(Src), UID, "125us"]),
    add_flow(Src, UID, 125, State);
parse_itdm_ctrl(_, _, _, State) ->
    State.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
parse_itdm_1ms(_, _, _, _, State = #state{channel = undefined}) ->
    State;
parse_itdm_1ms(<<Ch:16, _:48, Samples:8/binary, _/binary>>,
               Dst, _, UID, State = #state{channel = Ch}) ->
    append_samples(Dst, UID, 1, Ch, Samples),
    State;
parse_itdm_1ms(<<_:16, Ch:16, _:32, _:64, Samples:8/binary, _/binary>>,
               Dst, _, UID, State = #state{channel = Ch}) ->
    append_samples(Dst, UID, 1, Ch, Samples),
    State;
parse_itdm_1ms(<<_:32, Ch:16, _:16, _:64, _:64, Samples:8/binary, _/binary>>,
               Dst, _, UID, State = #state{channel = Ch}) ->
    append_samples(Dst, UID, 1, Ch, Samples),
    State;
parse_itdm_1ms(<<_:48, Ch:16, _:64, _:64, _:64, Samples:8/binary, _/binary>>,
               Dst, _, UID, State = #state{channel = Ch}) ->
    append_samples(Dst, UID, 1, Ch, Samples),
    State;
parse_itdm_1ms(<<_:64, _:64, _:64, _:64, _:64, Rest/binary>>,
               Dst, Src, UID, State) ->
    parse_itdm_1ms(Rest, Dst, Src, UID, State);
parse_itdm_1ms(_, _, _, _, State) ->
    State.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
parse_itdm_125us(<<_:2, 0:1, _:1, 1:4, Ch:24, _:7,Loc:9, _:7, 1:9, Rest/binary>>,
                 Dst, _Src, UID, State) ->
    ?LOG("NEW CHANNEL - Dst:~s UID:~w Ch:~w Offset:~w",
         [mac_address(Dst), UID, Ch, Loc]),
    extract_samples(Rest, Dst, UID, add_route(Dst, UID, Ch, Loc, State));
parse_itdm_125us(<<_:2, 0:1, _:1, 2:4, Ch:24, _:7, Loc:9, _:7, 1:9, Rest/binary>>,
                 Dst, _Src, UID, State) ->
    ?LOG("CLOSE CHANNEL - Dst:~s UID:~w Ch:~w Offset:~w",
         [mac_address(Dst), UID, Ch, Loc]),
    del_route(Dst, UID, Ch, extract_samples(Rest, Dst, UID, State));
parse_itdm_125us(<<_:2, 0:1, _:1, 3:4, Ch:24, _:7,Loc:9, _:7, Old:9, Rest/binary>>,
                 Dst, _Src, UID, State) ->
    ?LOG("RELOCATE CHANNEL - Dst:~s UID:~w Ch:~w NewOffset:~w OldOffset:~w",
         [mac_address(Dst), UID, Ch, Loc, Old]),
    extract_samples(Rest, Dst, UID, relocate_route(Dst, UID, Ch, Loc, State));
parse_itdm_125us(<<_:2, 0:1, _:1, 4:4, Ch:24, _:7,Loc:9, _:7, 1:9, Rest/binary>>,
                 Dst, _Src, UID, State) ->
    ?LOG("CYCLIC REAFFIRMATION - Dst:~s UID:~w Ch:~w Offset:~w",
         [mac_address(Dst), UID, Ch, Loc]),
    extract_samples(Rest, Dst, UID, add_route(Dst, UID, Ch, Loc, State));
parse_itdm_125us(<<_:8, _:56, Rest/binary>>, Dst, _Src, UID, State) ->
    extract_samples(Rest, Dst, UID, State);
parse_itdm_125us(_, _, _, _, State) ->
    State.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
add_flow(Dst, UID, Mode, State = #state{flows = Fs}) ->
    Flow = case maps:find({Dst, UID}, Fs) of
               {ok, F} ->
                   F#flow{mode = Mode};
               error ->
                   #flow{mode = Mode}
           end,
    State#state{flows = Fs#{{Dst, UID} => Flow}}.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
add_route(Dst, UID, Ch, Loc, State = #state{flows = Fs}) ->
    case maps:find({Dst, UID}, Fs) of
        {ok, Flow = #flow{routings = Rs}} ->
            NewFlow = Flow#flow{routings = Rs#{Ch => Loc}},
            State#state{flows = Fs#{{Dst, UID} => NewFlow}};
        error ->
            State
    end.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
relocate_route(Dst, UID, Ch, Loc, State = #state{flows = Fs}) ->
    case maps:find({Dst, UID}, Fs) of
        {ok, Flow = #flow{routings = Rs}} ->
            NewRs = remove_by_value(Loc, Rs),
            NewFlow = Flow#flow{routings = NewRs#{Ch => Loc}},
            State#state{flows = Fs#{{Dst, UID} => NewFlow}};
        error ->
            State
    end.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
del_route(Dst, UID, Ch, State = #state{flows = Fs}) ->
    case maps:find({Dst, UID}, Fs) of
        {ok, Flow = #flow{routings = Rs}} ->
            NewFlow = Flow#flow{routings = maps:remove(Ch, Rs)},
            State#state{flows = Fs#{{Dst, UID} => NewFlow}};
        error ->
            State
    end.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
remove_by_value(Val, Map) ->
    maps:fold(
      fun(K, V, Acc) when V =:= Val ->
              maps:remove(K, Acc);
         (_, _, Acc) ->
              Acc
      end, Map, Map).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
extract_samples(_, _, _, State = #state{channel = undefined}) ->
    State;
extract_samples(Rest, Dst, UID, State = #state{channel = Ch, flows = Fs}) ->
    case maps:find({Dst, UID}, Fs) of
        {ok, #flow{routings = #{Ch := Loc}}} when size(Rest) > Loc ->
            append_samples(Dst, UID, 125, Ch, [binary:at(Rest, Loc)]);
        _ ->
            ok
    end,
    State.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
append_samples(Dst, UID, Mode, Ch, Samples) ->
    ok = file:write_file(filename(Dst, UID, Mode, Ch), Samples, [append]).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
filename(Dst, UID, Mode, Ch) ->
    MAC = mac_address(Dst),
    lists:flatten(io_lib:format("~s-~w-~w-~w.raw", [MAC, UID, Mode, Ch])).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
mac_address(<<M0:8,M1:8,M2:8,M3:8,M4:8,M5:8>>) ->
    io_lib:format(
      "~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b",
      [M0, M1, M2, M3, M4, M5]).
