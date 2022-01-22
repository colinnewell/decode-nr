# decode-nr

This is a quick and dirty tool to decode the network traffic going between the
New Relic C SDK and the Daemon (https://github.com/newrelic/c-sdk).

## Building

This program requires libpcap to build and run.  On Linux you typically install
a development version of the library like this on Debian and Ubuntu variants:

	sudo apt install libpcap-dev

On Windows download and install npcap from https://nmap.org/npcap/.  The
regular installer is sufficient, you shouldn't need the SDK.

On Mac's/BSD the library bindings required should be there out of the box
(no further action required).

Note that it's assumed you have Go installed, and also make (without make look
at the commands in the Makefile, that is mostly being used for convenience
rather than because things are particularly complex).

	git clone https://github.com/colinnewell/decode-nr.git
	cd decode-nr
	make
	sudo make install

## Usage

	sudo tcpdump port 31339 -w nr-traffic.pcap
    decode-nr --server-ports 31339 nr-traffic.pcap

You can then decode the bits of the output you're intersested in using `jq`.

For example:

    decode-nr nr-traffic.pcap | \
        jq '.[] | select(.client_messages) | .client_messages[] | select(.type == 3) | .transaction_name'

## Quality

This is a really shoddy job.  No tests at the time of writing, and a deliberate
attempt to spend as little time on this as possible.

## More background

This is largely to try to figure out what is going on, and there probably are
far simpler ways to do it.  It isn't aiming to be a comprehensive tool, just a
quick scratch of a temporary itch.

My expecation is that this tool will become useless fairly quickly as New Relic
are aiming to move away from the current C sdk as Open Telemetry takes off.

The code borrows heavily from what I can see in the New Relic repo, but add
lots of slapdash to get some sort of minimal output out.
