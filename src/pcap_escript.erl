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
%%% Module implementing the scripting logic.
%%% @end
%%%=============================================================================

-module(pcap_escript).

-export([main/1]).

-define(PCAP_PLUGINS, "PCAP_PLUGINS").

%%%=============================================================================
%%% API
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @doc
%% Entry point for the pcap escript.
%% @end
%%------------------------------------------------------------------------------
main(Argv) ->
    ok = load_modules(),
    ok = load_plugins(extend_path()),
    Parsers = parser_modules(),
    OptSpecList = opt_spec_list(Parsers),
    case getopt:parse_and_check(OptSpecList, Argv) of
        {ok, {Opts, Files}} ->
            ok = run(OptSpecList, Opts, Files);
        {error, Reason} ->
            ok = io:format("Invalid invocation ~w~n", [Reason]),
            ok = usage(OptSpecList),
            halt(1)
    end.

%%%=============================================================================
%%% Internal Functions
%%%=============================================================================

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
load_modules() ->
    {ok, Apps} = application:ensure_all_started(pcap),
    lists:foreach(
      fun(App) ->
              lists:foreach(
                fun code:load_file/1,
                element(2, {ok, _} = application:get_key(App, modules)))
      end, Apps).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
extend_path() ->
    OrigPath = code:get_path(),
    Value = os:getenv(?PCAP_PLUGINS, ""),
    ok = code:add_paths(string:tokens(Value, ":")),
    case code:get_path() of
        OrigPath -> [];
        NewPath  -> NewPath -- OrigPath
    end.

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
load_plugins(Dirs) ->
    io:format("Using plugin paths ~p~n", [Dirs]),
    lists:foreach(
      fun code:load_file/1,
      lists:map(
        fun(F) -> list_to_atom(filename:basename(F, ".beam")) end,
        lists:usort(
          lists:append(
            [filelib:wildcard(filename:join([D, "*.beam"]))
             || D <- Dirs])))).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
parser_modules() ->
    AllLoaded = code:all_loaded(),
    lists:usort(
     lists:append(
       modules_with_behaviour(AllLoaded),
       modules_with_exports(AllLoaded))).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
modules_with_behaviour(Modules) ->
    [Module || {Module, _} <- Modules,
               {behaviour, Behaviours} <- Module:module_info(attributes),
               lists:member(pcap, Behaviours)].

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
modules_with_exports(Modules) ->
    Callbacks = pcap:behaviour_info(callbacks),
    [Module || {Module, _} <- Modules,
               Callbacks -- Module:module_info(exports) =:= []].

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
opt_spec_list(Parsers) ->
    Available = string:join([atom_to_list(P) || P <- Parsers], "|"),
    Descr = "Parser to use (available " ++ Available ++ ")",
    [{help, $h, "help", undefined, "Show this help text"},
     {parser, undefined, "parser", {atom, pcap_itdm}, Descr}
     | lists:append([P:options() || P <- Parsers])].

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
usage(OptSpecList) ->
    getopt:usage(
      OptSpecList,
      escript:script_name(),
      "[filename]",
      "Parse PCAP data using the specified parser.\n"
      "\n"
      "A parser is specified using the '--parser' flag. Please note that\n"
      "specific options are only applicable to specific parsers (see below).\n"
      "\n"
      "Additionally, it is possible to extend the program with custom parsers\n"
      "that do not need to be packaged with the script. Custom parsers can be\n"
      "used by extending the scripts code path using the " ++ ?PCAP_PLUGINS ++ "\n"
      "environment variable, e.g. export " ++ ?PCAP_PLUGINS ++ "=/tmp/plugins",
      [{"filename", "File to read from, no file or '-' reads from stdin"}],
      standard_error).

%%------------------------------------------------------------------------------
%% @private
%%------------------------------------------------------------------------------
run(OptSpecList, Opts, []) ->
    run(OptSpecList, Opts, ["-"]);
run(OptSpecList, Opts, Files) ->
    case {proplists:get_bool(help, Opts), Files} of
        {true, _} ->
            usage(OptSpecList);
        {false, [File]} ->
            Parser = proplists:get_value(parser, Opts),
            ParserOpts = lists:keydelete(parser, 1, Opts),
            ok = io:format("Using ~w:parser(~p)~n", [Parser, ParserOpts]),
            pcap:parse(File, Parser:parser(ParserOpts));
        {false, Files} ->
            ok = io:format("Parsing multiple files is unsupported~n", []),
            ok = usage(OptSpecList),
            halt(1)
    end.
