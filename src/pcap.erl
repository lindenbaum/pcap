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
%%% Library application and utilities related to PCAP parsing.
%%%
%%% This module does also contain a behaviour that should be implemented by
%%% custom sub-parsers.
%%% @end
%%%=============================================================================

-module(pcap).

-export([parse/2]).

-type ts_sec()   :: non_neg_integer().
-type ts_usec()  :: non_neg_integer().
-type incl_len() :: non_neg_integer().
-type orig_len() :: non_neg_integer().

-type parser(State) :: {fun((ts_sec(),
                             ts_usec(),
                             incl_len(),
                             orig_len(),
                             Data :: binary(),
                             State) -> State),
                           State}.
%% @doc
%% A sub-parser is represented with a parser function and an initial state.
%% The function will be called subsequently with the data for a single packet.
%% The parser may return a new, modified state each time it gets invoked.
%% @end

-export_type([ts_sec/0,
              ts_usec/0,
              incl_len/0,
              orig_len/0,
              parser/1]).

-record(state, {
          endianess :: little | big,
          parser    :: parser(_)}).

-define(CHUNK_SIZE, 64 * 1024).

%%%=============================================================================
%%% Behaviour
%%%=============================================================================

-callback options() -> [getopt:option_spec()].
%% @doc
%% The option specifications that are suppored by the sub-parser.
%% @end

-callback parser(proplists:proplist()) -> pcap:parser(_).
%% @doc
%% A function callback that returns a sub-parser instance (including its
%% initial state).
%% @end

%%%=============================================================================
%%% API
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @doc
%% Main entry point for PCAP parsing.
%%
%% This function either parses a binary representing a PCAP trace, reads from a
%% single PCAP file or reads PCAP data from `stdin'.
%%
%% The second argument specifies the custom sub-parser to use, e.g. for the
%% ITDM protocol.
%% @end
%%------------------------------------------------------------------------------
-spec parse(string() | binary(), parser(_)) -> ok | {error, term()}.
parse(Binary, Parser) when is_binary(Binary) ->
    State = #state{parser = Parser},
    _ = parse_loop(Binary, fun pcap_parser/2, State),
    ok;
parse(String, Parser) when String =:= ""; String =:= "-" ->
    State = #state{parser = Parser},
    ReadFun = fun() -> case io:get_chars('', ?CHUNK_SIZE) of
                           L when is_list(L)   -> {ok, list_to_binary(L)};
                           B when is_binary(B) -> {ok, B};
                           Other               -> Other
                       end
              end,
    read_loop(ReadFun, <<>>, fun pcap_parser/2, State);
parse(FileName, Parser) ->
    State = #state{parser = Parser},
    {ok, IoDevice} = file:open(FileName, [read, raw, binary, read_ahead]),
    try
        ReadFun = fun() -> file:read(IoDevice, ?CHUNK_SIZE) end,
        read_loop(ReadFun, <<>>, fun pcap_parser/2, State)
    after
        file:close(IoDevice)
    end.

%%%=============================================================================
%%% Internal Functions
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @private
%% The data source read loop.
%%------------------------------------------------------------------------------
read_loop(ReadFun, Rest, Fun, State) ->
    case ReadFun() of
        {ok, Data} ->
            Binary = <<Rest/binary, Data/binary>>,
            {NewRest, NewState} = parse_loop(Binary, Fun, State),
            read_loop(ReadFun, NewRest, Fun, NewState);
        eof ->
            ok;
        Error ->
            Error
    end.

%%------------------------------------------------------------------------------
%% @private
%% The parse loop for a binary chunk.
%%------------------------------------------------------------------------------
parse_loop(Rest, Fun, State) ->
    case Fun(Rest, State) of
        {continue, NewRest, NewState} -> parse_loop(NewRest, Fun, NewState);
        {finished, NewRest, NewState} -> {NewRest, NewState}
    end.

%%------------------------------------------------------------------------------
%% @private
%% General PCAP parsing with endianess detection.
%%------------------------------------------------------------------------------
pcap_parser(<<16#a1b2c3d4:32/little,
              VersionMajor:16/little,
              VersionMinor:16/little,
              ThisZone:32/signed-little,
              _SigFigs:32/little,
              _SnapLen:32/little,
              Network:32/little,
              Rest/binary>>,
            State) ->
    io:format("Version:   ~w.~w~n", [VersionMajor, VersionMinor]),
    io:format("Endianess: Little~n", []),
    io:format("Timezone:  GMT~s~n", [timezone(ThisZone)]),
    io:format("Link Type: ~s~n", [link_type(Network)]),
    {continue, Rest, State#state{endianess = little}};
pcap_parser(<<16#a1b2c3d4:32/big,
              VersionMajor:16/big,
              VersionMinor:16/big,
              ThisZone:32/signed-big,
              _SigFigs:32/big,
              _SnapLen:32/big,
              Network:32/big,
              Rest/binary>>,
            State) ->
    io:format("Version:   ~w.~w~n", [VersionMajor, VersionMinor]),
    io:format("Endianess: Big~n", []),
    io:format("Timezone:  GMT~s~n", [timezone(ThisZone)]),
    io:format("Link Type: ~s~n", [link_type(Network)]),
    {continue, Rest, State#state{endianess = big}};
pcap_parser(Bin = <<TsSec:4/binary,
                    TsUsec:4/binary,
                    InclLen:4/binary,
                    OrigLen:4/binary,
                    Data/binary>>,
            State = #state{endianess = E, parser = {PFun, PState}})
  when E =/= undefined ->
    DataLen = correct_endianess(E, InclLen),
    case Data of
        <<PacketData:DataLen/binary, Rest/binary>> ->
            NewPState = PFun(correct_endianess(E, TsSec),
                             correct_endianess(E, TsUsec),
                             DataLen,
                             correct_endianess(E, OrigLen),
                             PacketData,
                             PState),
            {continue, Rest, State#state{parser = {PFun, NewPState}}};
        _ ->
            {finished, Bin, State}
    end;
pcap_parser(Rest, State) ->
    {finished, Rest, State}.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
timezone(I) when I >= 0 -> "+" ++ integer_to_list(I);
timezone(I)             -> integer_to_list(I).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
link_type(1) -> "Ethernet";
link_type(T) -> integer_to_list(T).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
correct_endianess(big, <<Value:8/big>>)        -> Value;
correct_endianess(big, <<Value:16/big>>)       -> Value;
correct_endianess(big, <<Value:32/big>>)       -> Value;
correct_endianess(big, <<Value:64/big>>)       -> Value;
correct_endianess(little, <<Value:8/little>>)  -> Value;
correct_endianess(little, <<Value:16/little>>) -> Value;
correct_endianess(little, <<Value:32/little>>) -> Value;
correct_endianess(little, <<Value:64/little>>) -> Value.
