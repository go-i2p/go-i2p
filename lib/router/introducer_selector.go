package router

import (
	"strings"
	"time"

	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/transport/ssu2"
	"github.com/go-i2p/logger"
)

// introducerRefreshInterval is how often the hidden-mode introducer selector
// re-evaluates its picks, drops disconnected peers, and registers fresh ones.
// 15 minutes per PLAN.md Track C2.
const introducerRefreshInterval = 15 * time.Minute

// startIntroducerSelector spawns a background goroutine that periodically
// selects up to 3 currently-connected SSU2 peers from the netdb whose
// `caps` advertise reachability ('R') and registers them as our introducers
// in the SSU2 transport's IntroducerRegistry. Disconnected peers are removed
// from the registry on each refresh.
//
// The goroutine is a no-op unless we are operating in hidden mode (Track A);
// non-hidden NATed routers rely on the SSU2 PeerTest path in
// startSSU2NATDetection to pick introducers. The goroutine exits when the
// router context is cancelled.
func (r *Router) startIntroducerSelector() {
	if r.cfg == nil || !r.cfg.Hidden {
		return
	}
	if r.getSSU2Transport() == nil {
		return
	}
	r.wg.Add(1)
	go r.runIntroducerSelector()
	log.WithFields(logger.Fields{"at": "startIntroducerSelector"}).Info("hidden-mode introducer selector started")
}

// runIntroducerSelector drives the introducer-selection loop. Performs an
// immediate refresh on entry, then ticks every introducerRefreshInterval.
func (r *Router) runIntroducerSelector() {
	defer r.wg.Done()
	r.refreshIntroducers()
	t := time.NewTicker(introducerRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.closeChnl:
			return
		case <-t.C:
			r.refreshIntroducers()
		}
	}
}

// refreshIntroducers reconciles the IntroducerRegistry with the current
// candidate set: registers up to 3 reachable+connected SSU2 peers and removes
// any previously-registered introducer whose UDP address is no longer in the
// candidate set. If the set changes, the RouterInfo is republished so peers
// learn of the new introducer fields.
func (r *Router) refreshIntroducers() {
	transport := r.getSSU2Transport()
	if transport == nil {
		log.Debug("refreshIntroducers: no SSU2 transport")
		return
	}
	candidates := r.collectIntroducerCandidates(introducerMaxCount)
	log.WithFields(logger.Fields{
		"at":              "refreshIntroducers",
		"candidate_count": len(candidates),
	}).Debug("introducer candidate collection complete")
	changed := r.applyIntroducerCandidates(transport, candidates)
	if changed && r.publisher != nil {
		log.WithFields(logger.Fields{
			"at":    "refreshIntroducers",
			"count": len(candidates),
		}).Info("introducer set changed; republishing RouterInfo")
		r.publisher.PublishOurRouterInfo()
	}
}

// introducerMaxCount mirrors ssu2noise.NewIntroducerRegistry(3) and the I2P
// SSU2 spec's hard limit of 3 introducers per router address.
const introducerMaxCount = 3

// collectIntroducerCandidates filters the netdb for RouterInfos suitable to
// act as our introducers: dialable SSU2 address, caps containing 'R'
// (reachable), and not ourselves. The result is capped at maxCount entries.
//
// NOTE: Unlike peer selection for tunnel building, introducer selection does
// NOT require an existing session. Java I2P sends RelayRequest messages via
// NTCP2 or tunnels to routers that will serve as introducers, allowing
// firewalled routers to bootstrap SSU2 connectivity without a chicken-egg
// problem. The introducer initiates RelayIntro containing a HolePunch that
// allows the firewalled router to establish its first SSU2 session.
func (r *Router) collectIntroducerCandidates(maxCount int) []router_info.RouterInfo {
	if r.netdb == nil {
		log.Debug("collectIntroducerCandidates: no netdb")
		return nil
	}

	all := r.netdb.GetAllRouterInfos()
	ourHash, ourHashErr := r.getOurRouterHash()

	log.WithFields(logger.Fields{
		"at":                "collectIntroducerCandidates",
		"total_routerinfos": len(all),
	}).Debug("starting introducer candidate search")

	out, stats := r.filterIntroducerCandidates(all, ourHash, ourHashErr, maxCount)

	r.logIntroducerCandidateStats(stats)

	return out
}

// introducerStats tracks statistics during introducer candidate filtering.
type introducerStats struct {
	checked int
	noSSU2  int
	noRCap  int
	found   int
}

// filterIntroducerCandidates filters RouterInfos to find suitable introducer candidates.
func (r *Router) filterIntroducerCandidates(all []router_info.RouterInfo, ourHash common.Hash, ourHashErr error, maxCount int) ([]router_info.RouterInfo, introducerStats) {
	out := make([]router_info.RouterInfo, 0, maxCount)
	stats := introducerStats{}

	for i := range all {
		ri := all[i]
		stats.checked++

		if !r.isValidIntroducerCandidate(ri, ourHash, ourHashErr, &stats) {
			continue
		}

		out = append(out, ri)
		if len(out) >= maxCount {
			break
		}
	}

	stats.found = len(out)
	return out, stats
}

// isValidIntroducerCandidate checks if a RouterInfo qualifies as an introducer candidate.
func (r *Router) isValidIntroducerCandidate(ri router_info.RouterInfo, ourHash common.Hash, ourHashErr error, stats *introducerStats) bool {
	h, err := ri.IdentHash()
	if err != nil {
		return false
	}
	if ourHashErr == nil && h == ourHash {
		return false
	}
	if !ssu2.HasDialableSSU2Address(&ri) {
		stats.noSSU2++
		return false
	}
	if !capsContainsReachable(ri.RouterCapabilities()) {
		stats.noRCap++
		return false
	}

	// BUG FIX: Removed the connected session requirement. Introducers can be
	// contacted via NTCP2 or tunnels; an SSU2 session is not required.
	// This allows firewalled routers to register introducers before having
	// any SSU2 connectivity (Java I2P behavior).

	return true
}

// logIntroducerCandidateStats logs statistics about the introducer candidate search.
func (r *Router) logIntroducerCandidateStats(stats introducerStats) {
	log.WithFields(logger.Fields{
		"at":                "collectIntroducerCandidates",
		"checked":           stats.checked,
		"found":             stats.found,
		"rejected_no_ssu2":  stats.noSSU2,
		"rejected_no_r_cap": stats.noRCap,
	}).Info("introducer candidate search complete")
}

// isIntroducerCandidate returns true when ri qualifies as one of our
// introducers under the C2 selection rules.
func (r *Router) isIntroducerCandidate(ri router_info.RouterInfo, ourHash common.Hash, ourHashErr error, connected map[common.Hash]struct{}) bool {
	h, err := ri.IdentHash()
	if err != nil {
		return false
	}
	if ourHashErr == nil && h == ourHash {
		return false
	}
	if !ssu2.HasDialableSSU2Address(&ri) {
		return false
	}
	if !capsContainsReachable(ri.RouterCapabilities()) {
		return false
	}
	if _, ok := connected[h]; !ok {
		return false
	}
	return true
}

// capsContainsReachable returns true when the caps string advertises 'R'.
// The caps field is a free-form string of single-character capability flags;
// I2P routers may prepend a length byte, so a substring check is used.
func capsContainsReachable(caps string) bool {
	return strings.ContainsRune(caps, 'R')
}

// snapshotConnectedHashes returns the set of peer hashes with an active
// transport session. Used to filter candidates by current connectivity.
func (r *Router) snapshotConnectedHashes() map[common.Hash]struct{} {
	r.sessionMutex.RLock()
	defer r.sessionMutex.RUnlock()
	out := make(map[common.Hash]struct{}, len(r.activeSessions))
	for h := range r.activeSessions {
		out[h] = struct{}{}
	}
	return out
}

// applyIntroducerCandidates registers each candidate with the SSU2 transport
// and removes any registered introducer not in the candidate set. Returns
// true if the registered set changed (additions or removals occurred).
func (r *Router) applyIntroducerCandidates(transport *ssu2.SSU2Transport, candidates []router_info.RouterInfo) bool {
	wantAddrs, added := r.addNewIntroducers(transport, candidates)
	removed := r.removeStaleIntroducers(transport, wantAddrs)
	return added > 0 || removed > 0
}

// addNewIntroducers registers new introducers from candidates.
// Returns a map of desired addresses and the count of newly added introducers.
func (r *Router) addNewIntroducers(transport *ssu2.SSU2Transport, candidates []router_info.RouterInfo) (map[string]struct{}, int) {
	wantAddrs := make(map[string]struct{}, len(candidates))
	added := 0

	for _, ri := range candidates {
		intro, err := transport.IntroducerFromRouterInfo(ri)
		if err != nil {
			log.WithError(err).Debug("introducer selector: skipping candidate")
			continue
		}
		wantAddrs[intro.Addr.String()] = struct{}{}
		if regErr := transport.RegisterIntroducer(intro); regErr == nil {
			added++
		}
	}

	return wantAddrs, added
}

// removeStaleIntroducers removes introducers not in the wantAddrs set.
// Returns the count of removed introducers.
func (r *Router) removeStaleIntroducers(transport *ssu2.SSU2Transport, wantAddrs map[string]struct{}) int {
	removed := 0

	for _, existing := range transport.GetIntroducers() {
		if existing.Addr == nil {
			continue
		}
		if _, keep := wantAddrs[existing.Addr.String()]; !keep {
			transport.RemoveIntroducerByAddr(existing.Addr)
			removed++
		}
	}

	return removed
}
