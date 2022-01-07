module github.com/colinnewell/decode-nr

go 1.17

require github.com/google/flatbuffers v2.0.5+incompatible

require github.com/google/gopacket v1.1.19 // indirect

require (
	github.com/colinnewell/pcap-cli v0.0.4
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180228061459-e0a39a4cb421 // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/spf13/pflag v1.0.5
	golang.org/x/sys v0.0.0-20190412213103-97732733099d // indirect
)

// replace github.com/colinnewell/pcap-cli => ../pcap-cli
