// Command probe performs a real NTCP2 initiator handshake against a FRESH
// router (from a working reseed archive) using the exact same dial path the
// running go-i2p router uses. This is the decisive test to separate
// "stale NetDB / non-I2P peer" from "NTCP2 protocol bug in go-noise".
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/go-i2p/common/key_certificate"
	"github.com/go-i2p/common/keys_and_cert"
	"github.com/go-i2p/common/router_address"
	"github.com/go-i2p/common/router_identity"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/common/signature"
	"github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ed25519"
	i2prand "github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-noise/ntcp2"
	upstreamnoise "github.com/go-i2p/noise"

	ntcp2transport "github.com/go-i2p/go-i2p/lib/transport/ntcp2"
)

// buildLocalRouterInfo constructs a real, signed RouterInfo whose NTCP2
// RouterAddress advertises the given Curve25519 public key in the s= option.
// This mirrors the e2e test helper routerInfoAdvertisingKey.
func buildLocalRouterInfo(pub []byte) ([]byte, error) {
	ed25519Priv, err := ed25519.GenerateEd25519Key()
	if err != nil {
		return nil, err
	}
	signingPriv, ok := ed25519Priv.(ed25519.Ed25519PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ed25519 type assert failed")
	}
	signingPub, err := signingPriv.Public()
	if err != nil {
		return nil, err
	}

	cryptoPub, err := curve25519.NewCurve25519PublicKey(pub)
	if err != nil {
		return nil, err
	}

	cert, err := key_certificate.NewEd25519X25519KeyCertificate()
	if err != nil {
		return nil, err
	}

	padding := make([]byte, keys_and_cert.KEYS_AND_CERT_DATA_SIZE-cert.CryptoSize()-cert.SigningPublicKeySize())
	if _, err := i2prand.Read(padding); err != nil {
		return nil, err
	}

	identity, err := router_identity.NewRouterIdentity(cryptoPub, signingPub, &cert.Certificate, padding)
	if err != nil {
		return nil, err
	}

	published := time.Now()
	addr, err := router_address.NewRouterAddress(3, published.Add(24*time.Hour), "NTCP2", map[string]string{
		"host": "203.0.111.5",
		"port": "3333",
		"s":    i2pbase64.I2PEncoding.EncodeToString(pub),
		"v":    "2",
	})
	if err != nil {
		return nil, err
	}

	ri, err := router_info.NewRouterInfo(
		identity,
		published,
		[]*router_address.RouterAddress{addr},
		map[string]string{"netId": "2", "router.version": "0.9.64"},
		&signingPriv,
		signature.SIGNATURE_TYPE_EDDSA_SHA512_ED25519,
	)
	if err != nil {
		return nil, err
	}
	if err := ri.Validate(); err != nil {
		return nil, fmt.Errorf("local RI validate: %w", err)
	}
	return ri.Bytes()
}

func main() {
	dir := ".reseed_test/extract"
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Println("FATAL reading dir:", err)
		os.Exit(2)
	}

	// Generate a throwaway Curve25519 static key for the initiator.
	cs := upstreamnoise.NewCipherSuite(upstreamnoise.DH25519, upstreamnoise.CipherChaChaPoly, upstreamnoise.HashSHA256)
	kp, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		fmt.Println("FATAL keygen:", err)
		os.Exit(2)
	}
	localStatic := kp.Private

	localRIB, err := buildLocalRouterInfo(kp.Public)
	if err != nil {
		fmt.Println("FATAL building local RouterInfo:", err)
		os.Exit(2)
	}
	fmt.Printf("local RouterInfo built: %d bytes, static key pub=%x...\n", len(localRIB), kp.Public[:8])

	var tested, ok, fail int
	for _, e := range entries {
		if tested >= 8 {
			break
		}
		if e.IsDir() || filepath.Ext(e.Name()) != ".dat" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		riB, err := os.ReadFile(path)
		if err != nil || len(riB) == 0 {
			continue
		}
		ri, _, err := router_info.ReadRouterInfo(riB)
		if err != nil {
			continue
		}
		remoteHash, err := ri.IdentHash()
		if err != nil {
			continue
		}
		candidates, err := ntcp2transport.ExtractNTCP2DialCandidatesWithMetadata(ri)
		if err != nil || len(candidates) == 0 {
			continue
		}

		tested++
		fmt.Printf("\n=== [%d] %s  hash=%x  candidates=%d ===\n", tested, e.Name(), remoteHash[:8], len(candidates))

		success := false
		for ci, cand := range candidates {
			tcpAddr := cand.Addr.String()
			if wrapped, okk := cand.Addr.(*ntcp2.Addr); okk {
				tcpAddr = wrapped.UnderlyingAddr().String()
			}

			cfg, err := ntcp2.NewNTCP2Config(remoteHash, true)
			if err != nil {
				fmt.Printf("  cand[%d] config err: %v\n", ci, err)
				continue
			}
			cfg.WithStaticKey(localStatic)
			cfg = cfg.WithRemoteRouterHash(remoteHash)
			cfg.WithLocalRouterInfo(localRIB)
			if err := ntcp2transport.ConfigureDialConfigFromAddress(cfg, cand.RouterAddress); err != nil {
				fmt.Printf("  cand[%d] %s  config-from-addr err: %v\n", ci, tcpAddr, err)
				continue
			}

			start := time.Now()
			res := attemptHandshake(tcpAddr, cfg)
			dur := time.Since(start)
			fmt.Printf("  cand[%d] %s  -> %s  (%d ms)\n", ci, tcpAddr, res, dur.Milliseconds())
			if res == "OK" {
				ok++
				success = true
				break
			}
			fail++
		}
		_ = success
	}

	fmt.Printf("\n==== SUMMARY: routers_tested=%d handshakes_ok=%d handshakes_fail=%d ====\n", tested, ok, fail)
}

func attemptHandshake(tcpAddr string, cfg *ntcp2.Config) string {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	d := &net.Dialer{}
	tcpConn, err := d.DialContext(ctx, "tcp", tcpAddr)
	if err != nil {
		return "TCP-DIAL-FAIL: " + err.Error()
	}
	defer tcpConn.Close()

	conn, err := ntcp2.WrapNTCP2Conn(tcpConn, cfg)
	if err != nil {
		return "WRAP-FAIL: " + err.Error()
	}
	defer conn.Close()

	if err := conn.Handshake(ctx); err != nil {
		return "HS-FAIL: " + err.Error()
	}
	return "OK"
}