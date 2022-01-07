package main

import (
	"github.com/colinnewell/decode-nr/connections"
	"github.com/colinnewell/pcap-cli/cli"
	"github.com/colinnewell/pcap-cli/general"
	"github.com/spf13/pflag"
)

func main() {
	f := connections.NRConnectionBuilderFactory{}
	r := general.NewReader(&f)
	// FIXME: need a factory and to build using the constructor
	pflag.BoolVar(&r.Verbose, "verbose", false, "Verbose about things errors")
	cli.Main("", r, cli.SimpleJSONOutput)
}
