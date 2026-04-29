// Command verify_msg1 cross-checks an NTCP2_DUMP_MSG1 log entry against the
// peer's RouterInfo .dat file.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
)

func main() {
	riPath := flag.String("ri", "", "path to routerInfo-*.dat file")
	aesKeyHex := flag.String("aes-key", "", "AES key (hex) from msg1 dump")
	aesIVHex := flag.String("aes-iv", "", "AES IV (hex) from msg1 dump")
	remoteSHex := flag.String("remote-s", "", "remote static key (hex) from msg1 dump")
	flag.Parse()

	if *riPath == "" {
		fmt.Fprintln(os.Stderr, "missing -ri")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*riPath)
	must(err, "read RI")

	// go-i2p netDb skiplist .dat files use a 3-byte wrapper:
	//   [type:1 = 0x01 RouterInfo] [length:2 BE] [RouterInfo bytes...]
	// See lib/netdb/entry.go::writeEntryData. Strip it if present so we
	// can hand the raw RouterInfo bytes to the common parser.
	if len(raw) >= 3 && raw[0] == 0x01 {
		declared := int(raw[1])<<8 | int(raw[2])
		if declared+3 == len(raw) {
			fmt.Printf("stripping 3-byte netDb file wrapper (type=1 RouterInfo, len=%d)\n", declared)
			raw = raw[3:]
		}
	}

	ri, _, err := router_info.ReadRouterInfo(raw)
	must(err, "parse RI")

	identHash, err := ri.IdentHash()
	must(err, "compute IdentHash")
	fmt.Printf("computed IdentHash: %s\n", hex.EncodeToString(identHash[:]))
	check("aes_key vs IdentHash", *aesKeyHex, hex.EncodeToString(identHash[:]))

	addrs := ri.RouterAddresses()
	found := false
	for i, addr := range addrs {
		styleStr, err := addr.TransportStyle().Data()
		if err != nil || !strings.EqualFold(styleStr, "ntcp2") {
			continue
		}
		found = true
		fmt.Printf("\n=== NTCP2 RouterAddress #%d ===\n", i)

		opts := addr.Options()
		vals := opts.Values()
		host := stringOf(vals.Get(mustI2PStr("host")))
		port := stringOf(vals.Get(mustI2PStr("port")))
		v := stringOf(vals.Get(mustI2PStr("v")))
		caps := stringOf(vals.Get(mustI2PStr("caps")))
		sB64 := stringOf(vals.Get(mustI2PStr("s")))
		iB64 := stringOf(vals.Get(mustI2PStr("i")))
		fmt.Printf("  host=%q port=%q v=%q caps=%q\n", host, port, v, caps)
		fmt.Printf("  s (b64): %s\n", sB64)
		fmt.Printf("  i (b64): %s\n", iB64)

		sBytes, err := addr.StaticKey()
		if err == nil {
			fmt.Printf("  s (32B hex): %s\n", hex.EncodeToString(sBytes[:]))
			check("remote_s vs s=", *remoteSHex, hex.EncodeToString(sBytes[:]))
		} else {
			fmt.Printf("  s decode error: %v\n", err)
		}

		ivBytes, err := addr.InitializationVector()
		if err == nil {
			fmt.Printf("  i (16B hex): %s\n", hex.EncodeToString(ivBytes[:]))
			check("aes_iv vs i=", *aesIVHex, hex.EncodeToString(ivBytes[:]))
		} else {
			fmt.Printf("  i decode error: %v\n", err)
		}
	}
	if !found {
		fmt.Println("WARNING: no NTCP2 RouterAddress found in this RouterInfo")
	}
}

func must(err error, ctx string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", ctx, err)
		os.Exit(1)
	}
}

func check(label, want, got string) {
	want = strings.ToLower(want)
	got = strings.ToLower(got)
	if want == "" {
		fmt.Printf("  %s: SKIP (no expected value)\n", label)
		return
	}
	if want == got {
		fmt.Printf("  %s: MATCH\n", label)
	} else {
		fmt.Printf("  %s: MISMATCH\n    want=%s\n    got =%s\n", label, want, got)
	}
}

func mustI2PStr(s string) data.I2PString {
	v, err := data.ToI2PString(s)
	if err != nil {
		panic(err)
	}
	return v
}

func stringOf(v data.I2PString) string {
	if len(v) == 0 {
		return ""
	}
	s, err := v.Data()
	if err != nil {
		return ""
	}
	return s
}
