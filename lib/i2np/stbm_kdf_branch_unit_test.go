package i2np

import (
	"bytes"
	"testing"
)

// TestDeriveSTBMHopKeysOBEPBranchDiverges pins the spec rule that the IV key
// derivation differs between the outbound endpoint (OBEP) and every other hop.
//
// tunnel-creation-ecies.rst "Reply keys":
//
//	keydata = HKDF(ck, ZEROLEN, "SMTunnelLayerKey", 64)
//	  layerKey = keydata[32:63]
//	  non-OBEP: ivKey = keydata[0:31]              ("because it's last")
//	  OBEP:     ck = keydata[0:31]
//	            keydata = HKDF(ck, ZEROLEN, "TunnelLayerIVKey", 64)
//	            ivKey = keydata[32:63]
//
// "The KDF for the IV key at the OBEP is different from that for the other hops,
// even if the reply is not garlic encrypted."
//
// Before the fix, go-i2p ran the OBEP TunnelLayerIVKey step for every hop, so a
// transit hop installed an IV key the tunnel creator never used (and vice
// versa) and tunnel data could not be decrypted at the peer. The reply and layer
// keys are identical across the two branches; only the IV key (and the OBEP-only
// garlic key/tag) diverge.
func TestDeriveSTBMHopKeysOBEPBranchDiverges(t *testing.T) {
	var preReplyCK [32]byte
	for i := range preReplyCK {
		preReplyCK[i] = byte(i + 1)
	}

	nonOBEP, err := deriveSTBMHopKeys(preReplyCK, false)
	if err != nil {
		t.Fatalf("deriveSTBMHopKeys(non-OBEP): %v", err)
	}
	obep, err := deriveSTBMHopKeys(preReplyCK, true)
	if err != nil {
		t.Fatalf("deriveSTBMHopKeys(OBEP): %v", err)
	}

	// Reply and layer keys are shared across both branches.
	if nonOBEP.ReplyKey != obep.ReplyKey {
		t.Errorf("reply key must not depend on OBEP branch")
	}
	if nonOBEP.LayerKey != obep.LayerKey {
		t.Errorf("layer key must not depend on OBEP branch")
	}

	// The IV key MUST differ - this is the whole point of the branch.
	if bytes.Equal(nonOBEP.IVKey[:], obep.IVKey[:]) {
		t.Fatalf("non-OBEP and OBEP IV keys are identical; the OBEP branch is not applied")
	}

	// The OBEP branch produces a garlic reply key/tag; the non-OBEP branch must
	// leave them zero (they are only meaningful at the endpoint).
	var zero [32]byte
	if bytes.Equal(obep.GarlicReplyKey[:], zero[:]) {
		t.Errorf("OBEP garlic reply key is zero; endpoint branch did not run")
	}
	var zeroTag [8]byte
	if bytes.Equal(obep.GarlicReplyTag[:], zeroTag[:]) {
		t.Errorf("OBEP garlic reply tag is zero; endpoint branch did not run")
	}
	if !bytes.Equal(nonOBEP.GarlicReplyKey[:], zero[:]) {
		t.Errorf("non-OBEP garlic reply key should be zero")
	}
}
