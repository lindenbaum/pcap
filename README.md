pcap
====

An extensible PCAP parser tool. `pcap` provides a tool to dissect PCAP traces
with the power of the awesome Erlang binary syntax. There's a basic PCAP parser
that extracts single packets from a trace and feeds them into sub-parsers which
can then do with the packet whatever they want.

Keep in mind that this is a tool specialized use cases. There's already plenty
of tools out there that can dissect PCAP traces, most famously
[WireShark](https://www.wireshark.org/).

Currently, the only supported sub-parser is the `pcap_itdm` parser which allows
dissecting of the [Internal TDM](https://www.picmg.org/product/internal-tdm-specification/)
protocol.

BUILD
-----

The project is built using `rebar3` (which is not packaged) with the project. To
create the `pcap` tool just use

```erlang
rebar3 do compile,escriptize
```

Usage
-----

To display help text of `pcap` use the following:

```erlang
pcap -h|--help
```

Extend
------

As mentioned before, `pcap` can easily be extended for new protocols. New
sub-parser must implement the `pcap` behaviour (use `pcap_itdm` as a starting
point). After that the code must be made available to `pcap`. This can be done
either by issuing a PR for your new parser or by dynamically extending the
`pcap` code path.

In the latter case you'll need to set the environment variable `PCAP_PLUGINS` to
the path to your compiled parser. `pcap` will automatically search this path
for `.beam` files and load them on startup. If successful, you should see your
parser in the list of available parsers.

Example:

A minimal sub-parser could look like this:
```erlang
-module(example).

-export([options/0, parser/1]).

-record(state, {}).

options() ->
    [{option, $o, "option", undefined, atom_to_list(?MODULE) ++ " - Option"}].

parser(_Opts) -> {fun parser_impl/6, #state{}}.

parser_impl(_TsSec, _TsUSec, InclLen, _OrigLen, _Data, State) ->
    ok = io:format("WHOA... packet with length ~wbytes~n", [InclLen]),
    State.
```

Comile it and use it with `pcap:`
```shell
> erlc -o /tmp/ /tmp/example.erl
> PCAP_PLUGINS=/tmp/ ./pcap -h
Using plugin paths ["/tmp"]
Usage: ./pcap [-h] [--parser [<parser>]] [-o] [-x [<extract>]] [filename]

Parse PCAP data using the specified parser.

A parser is specified using the '--parser' flag. Please note that
specific options are only applicable to specific parsers (see below).

Additionally, it is possible to extend the program with custom parsers
that do not need to be packaged with the script. Custom parsers can be
used by extending the scripts code path using the PCAP_PLUGINS
environment variable, e.g. export PCAP_PLUGINS=/tmp/plugins

  -h, --help     Show this help text
  --parser       Parser to use (available example|pcap_itdm) [default:
                 pcap_itdm]
  -o, --option   example - Option
  -x, --extract  pcap_itdm - ITDM channel to extract [default: undefined]
  filename       File to read from, no file or '-' reads from stdin

> PCAP_PLUGINS=/tmp/ ./pcap --parser example -o /tmp/example.pcap
Using plugin paths ["/tmp"]
Using example:parser([option])
Version:   2.4
Endianess: Little
Timezone:  GMT+0
Link Type: Ethernet
WHOA... packet with length 65bytes
WHOA... packet with length 74bytes
WHOA... packet with length 74bytes

```
