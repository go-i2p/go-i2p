package netdb

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/logger"

	"github.com/go-i2p/common/base32"
	"github.com/go-i2p/common/base64"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/encrypted_leaseset"
	"github.com/go-i2p/common/lease_set"
	"github.com/go-i2p/common/lease_set2"
	"github.com/go-i2p/common/meta_leaseset"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/netdb/reseed"
)

// standard network database implementation using local filesystem skiplist
type StdNetDB struct {
	DB          string
	RouterInfos map[common.Hash]Entry
	riMutex     sync.Mutex // mutex for RouterInfos
	LeaseSets   map[common.Hash]Entry
	lsMutex     sync.Mutex // mutex for LeaseSets

	// Expiration tracking for LeaseSets
	leaseSetExpiry map[common.Hash]time.Time // maps hash to expiration time
	expiryMutex    sync.RWMutex              // mutex for expiry tracking

	// Cleanup goroutine management
	ctx       context.Context
	cancel    context.CancelFunc
	cleanupWg sync.WaitGroup
}

func NewStdNetDB(db string) *StdNetDB {
	log.WithField("db_path", db).Debug("Creating new StdNetDB")
	ctx, cancel := context.WithCancel(context.Background())
	return &StdNetDB{
		DB:             db,
		RouterInfos:    make(map[common.Hash]Entry),
		riMutex:        sync.Mutex{},
		LeaseSets:      make(map[common.Hash]Entry),
		lsMutex:        sync.Mutex{},
		leaseSetExpiry: make(map[common.Hash]time.Time),
		expiryMutex:    sync.RWMutex{},
		ctx:            ctx,
		cancel:         cancel,
	}
}

func (db *StdNetDB) GetRouterInfo(hash common.Hash) (chnl chan router_info.RouterInfo) {
	log.WithField("hash", hash).Debug("Getting RouterInfo")

	// Check memory cache first
	db.riMutex.Lock()
	if ri, ok := db.RouterInfos[hash]; ok {
		db.riMutex.Unlock()
		log.Debug("RouterInfo found in memory cache")
		chnl = make(chan router_info.RouterInfo, 1)
		chnl <- *ri.RouterInfo
		close(chnl)
		return
	}
	db.riMutex.Unlock()

	// Load from file
	data, err := db.loadRouterInfoFromFile(hash)
	if err != nil {
		log.WithError(err).Error("Failed to load RouterInfo from file")
		return nil
	}

	chnl = make(chan router_info.RouterInfo, 1)
	ri, err := db.parseAndCacheRouterInfo(hash, data)
	if err != nil {
		log.WithError(err).Error("Failed to parse RouterInfo")
		close(chnl)
		return
	}

	chnl <- ri
	close(chnl)
	return
}

// loadRouterInfoFromFile loads RouterInfo data from the skiplist file.
func (db *StdNetDB) loadRouterInfoFromFile(hash common.Hash) ([]byte, error) {
	fname := db.SkiplistFile(hash)
	buff := new(bytes.Buffer)

	f, err := os.Open(fname)
	if err != nil {
		return nil, fmt.Errorf("failed to open RouterInfo file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(buff, f); err != nil {
		return nil, fmt.Errorf("failed to read RouterInfo file: %w", err)
	}

	return buff.Bytes(), nil
}

// parseAndCacheRouterInfo parses RouterInfo data and adds it to the memory cache.
func (db *StdNetDB) parseAndCacheRouterInfo(hash common.Hash, data []byte) (router_info.RouterInfo, error) {
	ri, _, err := router_info.ReadRouterInfo(data)
	if err != nil {
		return router_info.RouterInfo{}, fmt.Errorf("failed to parse RouterInfo: %w", err)
	}

	// Add to cache if not already present
	db.riMutex.Lock()
	if _, ok := db.RouterInfos[hash]; !ok {
		log.WithFields(logger.Fields{
			"at":     "StdNetDB.parseAndCacheRouterInfo",
			"reason": "new_entry",
		}).Debug("adding RouterInfo to memory cache")
		db.RouterInfos[hash] = Entry{
			RouterInfo: &ri,
		}
	}
	db.riMutex.Unlock()

	return ri, nil
}

func (db *StdNetDB) GetAllRouterInfos() (ri []router_info.RouterInfo) {
	log.WithFields(logger.Fields{
		"at":     "StdNetDB.GetAllRouterInfos",
		"reason": "bulk_retrieval",
	}).Debug("getting all RouterInfos")
	db.riMutex.Lock()
	ri = make([]router_info.RouterInfo, 0, len(db.RouterInfos))
	for _, e := range db.RouterInfos {
		if e.RouterInfo != nil {
			ri = append(ri, *e.RouterInfo)
		}
	}
	db.riMutex.Unlock()
	return
}

// buildExcludeMap creates a map for fast hash lookup during peer filtering
func (db *StdNetDB) buildExcludeMap(exclude []common.Hash) map[common.Hash]bool {
	excludeMap := make(map[common.Hash]bool)
	for _, hash := range exclude {
		excludeMap[hash] = true
	}
	return excludeMap
}

// filterAvailablePeers filters router infos excluding specified hashes and checking reachability
func (db *StdNetDB) filterAvailablePeers(allRouterInfos []router_info.RouterInfo, excludeMap map[common.Hash]bool) []router_info.RouterInfo {
	var available []router_info.RouterInfo
	for _, ri := range allRouterInfos {
		riHash, err := ri.IdentHash()
		if err != nil {
			log.WithError(err).Warn("Failed to get router hash, skipping router")
			continue
		}
		if !excludeMap[riHash] {
			// Basic reachability check - router should have valid addresses
			if len(ri.RouterAddresses()) > 0 {
				available = append(available, ri)
			}
		}
	}
	return available
}

// selectRandomPeers randomly selects the requested number of peers from available pool
func (db *StdNetDB) selectRandomPeers(available []router_info.RouterInfo, count int) []router_info.RouterInfo {
	selected := make([]router_info.RouterInfo, count)
	selectedIndices := make(map[int]bool)

	for i := 0; i < count; i++ {
		var idx int
		for {
			idx = rand.Intn(len(available))
			if !selectedIndices[idx] {
				selectedIndices[idx] = true
				break
			}
		}
		selected[i] = available[idx]
	}
	return selected
}

// SelectPeers selects a random subset of peers for tunnel building
// Filters out unreachable routers and excludes specified hashes
func (db *StdNetDB) SelectPeers(count int, exclude []common.Hash) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"count":   count,
		"exclude": len(exclude),
	}).Debug("Selecting peers for tunnel building")

	allRouterInfos := db.GetAllRouterInfos()
	if len(allRouterInfos) == 0 {
		return nil, fmt.Errorf("insufficient router infos available for peer selection")
	}

	excludeMap := db.buildExcludeMap(exclude)
	available := db.filterAvailablePeers(allRouterInfos, excludeMap)

	if len(available) == 0 {
		return nil, fmt.Errorf("insufficient suitable peers after filtering")
	}

	// If we have fewer available peers than requested, return all
	if len(available) <= count {
		log.WithFields(logger.Fields{
			"at":              "StdNetDB.SelectPeers",
			"reason":          "requested_exceeds_available",
			"available_peers": len(available),
		}).Debug("returning all available peers")
		return available, nil
	}

	selected := db.selectRandomPeers(available, count)
	log.WithFields(logger.Fields{
		"at":             "StdNetDB.SelectPeers",
		"reason":         "selection_complete",
		"selected_peers": count,
	}).Debug("peer selection completed")
	return selected, nil
}

// SelectFloodfillRouters selects the closest floodfill routers to a target hash
// using XOR distance metric (Kademlia-style selection).
//
// This method:
// 1. Filters all RouterInfos to find only floodfill routers (caps contains 'f')
// 2. Calculates XOR distance between target hash and each floodfill router
// 3. Returns up to 'count' closest floodfill routers sorted by distance
//
// Parameters:
//   - targetHash: The hash to find closest floodfill routers to (e.g., LeaseSet hash)
//   - count: Maximum number of floodfill routers to return
//
// Returns:
//   - Slice of RouterInfo for closest floodfill routers (may be less than count if insufficient floodfills available)
//   - Error if no floodfill routers are available in NetDB
func (db *StdNetDB) SelectFloodfillRouters(targetHash common.Hash, count int) ([]router_info.RouterInfo, error) {
	log.WithFields(logger.Fields{
		"target_hash": fmt.Sprintf("%x", targetHash[:8]),
		"count":       count,
	}).Debug("Selecting closest floodfill routers")

	// Get all router infos
	allRouterInfos := db.GetAllRouterInfos()
	if len(allRouterInfos) == 0 {
		return nil, fmt.Errorf("no router infos available in NetDB")
	}

	// Filter for floodfill routers
	floodfills := db.filterFloodfillRouters(allRouterInfos)
	if len(floodfills) == 0 {
		return nil, fmt.Errorf("no floodfill routers available in NetDB")
	}

	log.WithFields(logger.Fields{
		"at":              "StdNetDB.SelectFloodfillRouters",
		"reason":          "floodfill_selection_complete",
		"floodfill_count": len(floodfills),
	}).Debug("found floodfill routers")

	// Calculate XOR distances and select closest
	return db.selectClosestByXORDistance(floodfills, targetHash, count), nil
}

// filterFloodfillRouters filters RouterInfos to return only floodfill routers.
// A router is considered floodfill if its "caps" option contains the character 'f'.
func (db *StdNetDB) filterFloodfillRouters(routers []router_info.RouterInfo) []router_info.RouterInfo {
	var floodfills []router_info.RouterInfo

	for _, ri := range routers {
		if db.isFloodfillRouter(ri) {
			floodfills = append(floodfills, ri)
		}
	}

	return floodfills
}

// isFloodfillRouter checks if a RouterInfo represents a floodfill router.
// Returns true if the router's "caps" option contains 'f'.
func (db *StdNetDB) isFloodfillRouter(ri router_info.RouterInfo) bool {
	options := ri.Options()
	capsKey, _ := common.ToI2PString("caps")
	capsValue := options.Values().Get(capsKey)
	caps, _ := capsValue.Data()
	return strings.Contains(caps, "f")
}

// routerDistance represents a router with its calculated XOR distance from target.
type routerDistance struct {
	routerInfo router_info.RouterInfo
	distance   []byte // XOR distance as byte array for comparison
}

// selectClosestByXORDistance selects up to 'count' routers closest to targetHash
// using XOR distance metric (Kademlia).
func (db *StdNetDB) selectClosestByXORDistance(routers []router_info.RouterInfo, targetHash common.Hash, count int) []router_info.RouterInfo {
	// Calculate distances for all routers
	distances := make([]routerDistance, 0, len(routers))
	for _, ri := range routers {
		riHash, err := ri.IdentHash()
		if err != nil {
			log.WithError(err).Warn("Failed to get router hash for XOR distance calculation, skipping")
			continue
		}
		distance := db.calculateXORDistance(targetHash, riHash)
		distances = append(distances, routerDistance{
			routerInfo: ri,
			distance:   distance,
		})
	}

	// Sort by XOR distance (ascending)
	sort.Slice(distances, func(i, j int) bool {
		return db.compareXORDistances(distances[i].distance, distances[j].distance)
	})

	// Take up to count closest routers
	resultCount := count
	if len(distances) < count {
		resultCount = len(distances)
	}

	result := make([]router_info.RouterInfo, resultCount)
	for i := 0; i < resultCount; i++ {
		result[i] = distances[i].routerInfo
	}

	log.WithFields(logger.Fields{
		"requested": count,
		"available": len(distances),
		"selected":  resultCount,
	}).Debug("Selected closest floodfill routers by XOR distance")

	return result
}

// calculateXORDistance calculates the XOR distance between two hashes.
// XOR distance is the bitwise XOR of the two hashes, used in Kademlia DHT.
func (db *StdNetDB) calculateXORDistance(hash1, hash2 common.Hash) []byte {
	distance := make([]byte, len(hash1))
	for i := 0; i < len(hash1); i++ {
		distance[i] = hash1[i] ^ hash2[i]
	}
	return distance
}

// compareXORDistances compares two XOR distances using big-endian byte comparison.
// Returns true if dist1 < dist2 (dist1 is closer).
func (db *StdNetDB) compareXORDistances(dist1, dist2 []byte) bool {
	for i := 0; i < len(dist1); i++ {
		if dist1[i] < dist2[i] {
			return true
		}
		if dist1[i] > dist2[i] {
			return false
		}
	}
	return false // Equal distances
}

// get the skiplist file that a RouterInfo with this hash would go in
func (db *StdNetDB) SkiplistFile(hash common.Hash) (fpath string) {
	fname := base64.EncodeToString(hash[:])
	fpath = filepath.Join(db.Path(), fmt.Sprintf("r%c", fname[0]), fmt.Sprintf("routerInfo-%s.dat", fname))
	log.WithField("file_path", fpath).Debug("Generated skiplist file path")
	return
}

// get netdb path
func (db *StdNetDB) Path() string {
	return string(db.DB)
}

// Size returns the count of RouterInfos currently stored in the network database.
// This is a direct in-memory count and does not require filesystem access.
func (db *StdNetDB) Size() (routers int) {
	db.riMutex.Lock()
	routers = len(db.RouterInfos)
	db.riMutex.Unlock()

	log.WithField("count", routers).Debug("NetDB size calculated from in-memory RouterInfos")
	return routers
}

func (db *StdNetDB) CheckFilePathValid(fpath string) bool {
	if !db.validateFileExtension(fpath) {
		return false
	}

	cleanPath, err := db.resolveAndCleanPath(fpath)
	if err != nil {
		return false
	}

	if !db.verifyPathWithinNetDB(fpath, cleanPath) {
		return false
	}

	if !db.validatePathSecurity(cleanPath) {
		return false
	}

	log.WithFields(logger.Fields{
		"file_path": cleanPath,
		"is_valid":  true,
	}).Debug("File path validation successful")
	return true
}

// validateFileExtension checks if the file has the required .dat extension.
func (db *StdNetDB) validateFileExtension(fpath string) bool {
	if !strings.HasSuffix(fpath, ".dat") {
		log.WithField("file_path", fpath).Debug("Invalid file extension, expected .dat")
		return false
	}
	return true
}

// resolveAndCleanPath resolves the absolute path and cleans it to remove path traversal components.
func (db *StdNetDB) resolveAndCleanPath(fpath string) (string, error) {
	absPath, err := filepath.Abs(fpath)
	if err != nil {
		log.WithFields(logger.Fields{
			"file_path": fpath,
			"error":     err,
		}).Warn("Failed to resolve absolute path")
		return "", err
	}
	cleanPath := filepath.Clean(absPath)
	return cleanPath, nil
}

// verifyPathWithinNetDB ensures the file path is within the NetDB directory to prevent path traversal attacks.
func (db *StdNetDB) verifyPathWithinNetDB(originalPath, cleanPath string) bool {
	netdbPath, err := filepath.Abs(db.Path())
	if err != nil {
		log.WithFields(logger.Fields{
			"netdb_path": db.Path(),
			"error":      err,
		}).Error("Failed to resolve NetDB absolute path")
		return false
	}

	if !strings.HasPrefix(cleanPath, netdbPath+string(filepath.Separator)) &&
		cleanPath != netdbPath {
		log.WithFields(logger.Fields{
			"file_path":  originalPath,
			"clean_path": cleanPath,
			"netdb_path": netdbPath,
		}).Warn("Path traversal attempt detected, file outside NetDB directory")
		return false
	}
	return true
}

// validatePathSecurity checks for security issues including symlinks and file accessibility.
func (db *StdNetDB) validatePathSecurity(cleanPath string) bool {
	fileInfo, err := os.Lstat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.WithField("file_path", cleanPath).Debug("File path valid (file doesn't exist yet)")
			return true
		}
		log.WithFields(logger.Fields{
			"file_path": cleanPath,
			"error":     err,
		}).Debug("Failed to stat file")
		return false
	}

	if fileInfo.Mode()&os.ModeSymlink != 0 {
		log.WithField("file_path", cleanPath).Warn("Symlink detected, rejecting for security")
		return false
	}
	return true
}

// RecalculateSize is maintained for interface compatibility.
// Since Size() now operates directly on in-memory data, this is a no-op.
func (db *StdNetDB) RecalculateSize() error {
	log.Debug("RecalculateSize called - Size() now uses in-memory data")
	return nil
}

// countValidRouterInfos walks through the database directory and counts valid RouterInfo files.
func (db *StdNetDB) countValidRouterInfos() (int, error) {
	count := 0
	err := filepath.Walk(db.Path(), func(fname string, info os.FileInfo, err error) error {
		return db.processWalkEntry(fname, info, err, &count)
	})

	if err == nil {
		log.WithField("count", count).Debug("Finished counting RouterInfos")
	}

	return count, err
}

// processWalkEntry handles each entry encountered during the directory walk.
func (db *StdNetDB) processWalkEntry(fname string, info os.FileInfo, err error, count *int) error {
	if info.IsDir() {
		return db.handleDirectoryWalk(fname, err)
	}

	// Only process files with .dat extension (RouterInfo files)
	if db.CheckFilePathValid(fname) {
		if err := db.processRouterInfoFile(fname, count); err != nil {
			return err
		}
	}
	// Silently skip non-.dat files (no warning needed)
	return err
}

// handleDirectoryWalk processes directory entries during the walk.
func (db *StdNetDB) handleDirectoryWalk(fname string, err error) error {
	if !strings.HasPrefix(fname, db.Path()) {
		if db.Path() == fname {
			log.Debug("Reached end of NetDB directory")
			log.Debug("path==name time to exit")
			return nil
		}
		log.Debug("Outside of netDb dir time to exit", db.Path(), " ", fname)
		return err
	}
	return err
}

// processRouterInfoFile reads and validates a single RouterInfo file.
func (db *StdNetDB) processRouterInfoFile(fname string, count *int) error {
	log.WithField("file_name", fname).Debug("Reading RouterInfo file")
	log.Println("Reading in file:", fname)

	b, err := os.ReadFile(fname)
	if err != nil {
		log.WithError(err).Error("Failed to read RouterInfo file")
		return err
	}

	ri, _, err := router_info.ReadRouterInfo(b)
	if err != nil {
		log.WithError(err).Error("Failed to parse RouterInfo")
		return err
	}

	// Process the RouterInfo
	db.logRouterInfoDetails(ri)
	if err := db.cacheRouterInfo(ri, fname); err != nil {
		return fmt.Errorf("failed to cache router info: %w", err)
	}
	(*count)++

	return nil
}

// logRouterInfoDetails logs details about the RouterInfo for debugging.
func (db *StdNetDB) logRouterInfoDetails(ri router_info.RouterInfo) {
	ih, err := ri.IdentHash()
	if err != nil {
		log.WithError(err).Warn("Failed to get router hash for logging")
		return
	}
	ihBytes := ih.Bytes()
	log.Printf("Read in IdentHash: %s", base32.EncodeToString(ihBytes[:]))

	for _, addr := range ri.RouterAddresses() {
		log.Println(string(addr.Bytes()))
		log.WithField("address", string(addr.Bytes())).Debug("RouterInfo address")
	}
}

// cacheRouterInfo adds the RouterInfo to the in-memory cache if not already present.
func (db *StdNetDB) cacheRouterInfo(ri router_info.RouterInfo, fname string) error {
	ih, err := ri.IdentHash()
	if err != nil {
		return fmt.Errorf("failed to get router hash for caching: %w", err)
	}
	db.riMutex.Lock()
	if ent, ok := db.RouterInfos[ih]; !ok {
		log.Debug("Adding new RouterInfo to memory cache")
		db.RouterInfos[ih] = Entry{
			RouterInfo: &ri,
		}
	} else {
		log.Debug("RouterInfo already in memory cache")
		log.Println("entry previously found in table", ent, fname)
	}
	db.riMutex.Unlock()
	return nil
}

// return true if the network db directory exists and is writable
func (db *StdNetDB) Exists() bool {
	p := db.Path()
	// check root directory
	_, err := os.Stat(p)
	if err == nil {
		// check subdirectories for skiplist
		for _, c := range base64.I2PEncodeAlphabet {
			if _, err = os.Stat(filepath.Join(p, fmt.Sprintf("r%c", c))); err != nil {
				return false
			}
		}
	}
	return err == nil
}

func (db *StdNetDB) SaveEntry(e *Entry) (err error) {
	var f io.WriteCloser
	h, err := e.RouterInfo.IdentHash()
	if err != nil {
		return fmt.Errorf("failed to get router hash for saving: %w", err)
	}
	log.WithField("hash", h).Debug("Saving NetDB entry")
	// if err == nil {
	f, err = os.OpenFile(db.SkiplistFile(h), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err == nil {
		defer f.Close()
		err = e.WriteTo(f)
		if err == nil {
			log.Debug("Successfully saved NetDB entry")
		} else {
			log.WithError(err).Error("Failed to write NetDB entry")
		}
	} else {
		log.WithError(err).Error("Failed to open file for saving NetDB entry")
	}
	//}
	/*
		if err != nil {
			log.Errorf("failed to save netdb entry: %s", err.Error())
		}
	*/
	return
}

func (db *StdNetDB) Save() (err error) {
	log.Debug("Saving all NetDB entries")
	db.riMutex.Lock()
	for _, entry := range db.RouterInfos {
		if e := db.SaveEntry(&entry); e != nil {
			err = e
			log.WithError(e).Error("Failed to save NetDB entry")
		}
	}
	db.riMutex.Unlock()
	return
}

// reseed if we have less than minRouters known routers
// returns error if reseed failed
func (db *StdNetDB) Reseed(b bootstrap.Bootstrap, minRouters int) (err error) {
	if !db.isReseedRequired(minRouters) {
		return nil
	}

	peers, err := db.retrievePeersFromBootstrap(b)
	if err != nil {
		return err
	}

	count := db.addNewRouterInfos(peers)
	log.WithField("added_routers", count).Info("Reseed completed successfully")

	return db.updateCacheAfterReseed()
}

// isReseedRequired checks if reseed is necessary based on current database size.
func (db *StdNetDB) isReseedRequired(minRouters int) bool {
	log.WithField("min_routers", minRouters).Debug("Checking if reseed is necessary")
	if db.Size() > minRouters {
		log.Debug("Reseed not necessary")
		return false
	}
	log.Warn("NetDB size below minimum, reseed required")
	return true
}

// retrievePeersFromBootstrap gets peers from the bootstrap provider with timeout.
func (db *StdNetDB) retrievePeersFromBootstrap(b bootstrap.Bootstrap) ([]router_info.RouterInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), reseed.DefaultDialTimeout)
	defer cancel()

	peersChan, err := b.GetPeers(ctx, 0) // Get as many peers as possible
	if err != nil {
		log.WithError(err).Error("Failed to get peers from bootstrap provider")
		return nil, fmt.Errorf("bootstrap failed: %w", err)
	}

	return peersChan, nil
}

// addNewRouterInfos processes and adds new RouterInfos from peers to the database.
func (db *StdNetDB) addNewRouterInfos(peers []router_info.RouterInfo) int {
	count := 0
	db.riMutex.Lock()
	for _, ri := range peers {
		hash, err := ri.IdentHash()
		if err != nil {
			log.WithError(err).Warn("Failed to get router hash during reseed, skipping")
			continue
		}
		if _, exists := db.RouterInfos[hash]; !exists {
			log.WithField("hash", hash).Debug("Adding new RouterInfo from reseed")
			db.RouterInfos[hash] = Entry{
				RouterInfo: &ri,
			}
			count++
		}
	}
	db.riMutex.Unlock()
	return count
}

// updateCacheAfterReseed updates the size cache after successful reseed operation.
func (db *StdNetDB) updateCacheAfterReseed() error {
	err := db.RecalculateSize()
	if err != nil {
		log.WithError(err).Warn("Failed to update NetDB size cache after reseed")
	}
	return nil
}

// validateRouterInfoDataType checks if the data type is valid for RouterInfo storage.
func validateRouterInfoDataType(dataType byte) error {
	if dataType != 0 {
		log.WithField("type", dataType).Warn("Invalid data type for RouterInfo, expected 0")
		return fmt.Errorf("invalid data type for RouterInfo: expected 0, got %d", dataType)
	}
	return nil
}

// parseRouterInfoData parses RouterInfo from raw bytes.
func parseRouterInfoData(data []byte) (router_info.RouterInfo, error) {
	ri, _, err := router_info.ReadRouterInfo(data)
	if err != nil {
		log.WithError(err).Error("Failed to parse RouterInfo from DatabaseStore data")
		return router_info.RouterInfo{}, fmt.Errorf("failed to parse RouterInfo: %w", err)
	}
	return ri, nil
}

// verifyRouterInfoHash validates that the provided key matches the RouterInfo identity hash.
func verifyRouterInfoHash(key common.Hash, ri router_info.RouterInfo) error {
	expectedHash, err := ri.IdentHash()
	if err != nil {
		return fmt.Errorf("failed to get router hash for verification: %w", err)
	}
	if key != expectedHash {
		log.WithFields(logger.Fields{
			"expected_hash": expectedHash,
			"provided_key":  key,
		}).Error("RouterInfo hash mismatch")
		return fmt.Errorf("RouterInfo hash mismatch: expected %x, got %x", expectedHash, key)
	}
	return nil
}

// addRouterInfoToCache adds a RouterInfo entry to the in-memory cache if it doesn't exist.
// Returns true if the entry was added, false if it already existed.
func (db *StdNetDB) addRouterInfoToCache(key common.Hash, ri router_info.RouterInfo) bool {
	db.riMutex.Lock()
	defer db.riMutex.Unlock()

	if _, exists := db.RouterInfos[key]; exists {
		log.WithField("hash", key).Debug("RouterInfo already exists in memory, skipping")
		return false
	}

	db.RouterInfos[key] = Entry{
		RouterInfo: &ri,
	}
	return true
}

// persistRouterInfoToFilesystem saves a RouterInfo entry to the filesystem.
// If the save fails, it removes the entry from the in-memory cache.
func (db *StdNetDB) persistRouterInfoToFilesystem(key common.Hash, ri router_info.RouterInfo) error {
	entry := &Entry{
		RouterInfo: &ri,
	}

	if err := db.SaveEntry(entry); err != nil {
		log.WithError(err).Error("Failed to save RouterInfo to filesystem")
		db.riMutex.Lock()
		delete(db.RouterInfos, key)
		db.riMutex.Unlock()
		return fmt.Errorf("failed to save RouterInfo to filesystem: %w", err)
	}
	return nil
}

// StoreRouterInfo stores a RouterInfo entry in the database from I2NP DatabaseStore message.
func (db *StdNetDB) StoreRouterInfo(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("Storing RouterInfo from DatabaseStore message")

	if err := validateRouterInfoDataType(dataType); err != nil {
		return err
	}

	ri, err := parseRouterInfoData(data)
	if err != nil {
		return err
	}

	if err := verifyRouterInfoHash(key, ri); err != nil {
		return err
	}

	if !db.addRouterInfoToCache(key, ri) {
		return nil
	}

	if err := db.persistRouterInfoToFilesystem(key, ri); err != nil {
		return err
	}

	log.WithField("hash", key).Debug("Successfully stored RouterInfo")
	return nil
}

// ensure that the network database exists
func (db *StdNetDB) Ensure() (err error) {
	if !db.Exists() {
		log.Debug("NetDB directory does not exist, creating it")
		err = db.Create()
	} else {
		log.Debug("NetDB directory already exists")
	}
	return
}

// create base network database directory
func (db *StdNetDB) Create() (err error) {
	mode := os.FileMode(0o700)
	p := db.Path()
	log.WithField("path", p).Debug("Creating network database directory")
	// create root for skiplist
	err = os.MkdirAll(p, mode)
	if err == nil {
		// create all subdirectories for RouterInfo skiplist (r prefix)
		for _, c := range base64.I2PEncodeAlphabet {
			err = os.MkdirAll(filepath.Join(p, fmt.Sprintf("r%c", c)), mode)
			if err != nil {
				log.WithError(err).Error("Failed to create RouterInfo subdirectory")
				return
			}
		}
		// create all subdirectories for LeaseSet skiplist (l prefix)
		for _, c := range base64.I2PEncodeAlphabet {
			err = os.MkdirAll(filepath.Join(p, fmt.Sprintf("l%c", c)), mode)
			if err != nil {
				log.WithError(err).Error("Failed to create LeaseSet subdirectory")
				return
			}
		}
	} else {
		log.WithError(err).Error("Failed to create root network database directory")
	}
	return
}

// GetRouterInfoBytes retrieves RouterInfo data as bytes from the database
func (db *StdNetDB) GetRouterInfoBytes(hash common.Hash) ([]byte, error) {
	log.WithField("hash", hash).Debug("Getting RouterInfo bytes")

	// Check memory cache first
	db.riMutex.Lock()
	if ri, ok := db.RouterInfos[hash]; ok && ri.RouterInfo != nil {
		db.riMutex.Unlock()
		log.Debug("RouterInfo found in memory cache")

		// Serialize the RouterInfo to bytes
		data, err := ri.RouterInfo.Bytes()
		if err != nil {
			log.WithError(err).Error("Failed to serialize cached RouterInfo")
			return nil, fmt.Errorf("failed to serialize RouterInfo: %w", err)
		}
		return data, nil
	}
	db.riMutex.Unlock()

	// Load from file if not in memory
	data, err := db.loadRouterInfoFromFile(hash)
	if err != nil {
		log.WithError(err).Debug("RouterInfo not found in filesystem")
		return nil, fmt.Errorf("RouterInfo not found: %w", err)
	}

	// Parse and cache for future use
	_, err = db.parseAndCacheRouterInfo(hash, data)
	if err != nil {
		log.WithError(err).Error("Failed to parse RouterInfo from file")
		return nil, fmt.Errorf("failed to parse RouterInfo: %w", err)
	}

	return data, nil
}

// GetRouterInfoCount returns the total number of RouterInfo entries in the database
func (db *StdNetDB) GetRouterInfoCount() int {
	return db.Size()
}

// ======================================================================
// LeaseSet Storage and Retrieval Methods
// ======================================================================

// SkiplistFileForLeaseSet generates the skiplist file path for a LeaseSet
// LeaseSets use 'l' prefix instead of 'r' for router infos
func (db *StdNetDB) SkiplistFileForLeaseSet(hash common.Hash) string {
	fname := base64.EncodeToString(hash[:])
	fpath := filepath.Join(db.Path(), fmt.Sprintf("l%c", fname[0]), fmt.Sprintf("leaseSet-%s.dat", fname))
	log.WithField("file_path", fpath).Debug("Generated LeaseSet skiplist file path")
	return fpath
}

// StoreLeaseSet stores a LeaseSet entry in the database from I2NP DatabaseStore message.
// This method validates, parses, caches, and persists LeaseSet data.
// dataType should be 1 for standard LeaseSets (matching I2P protocol specification).
func (db *StdNetDB) StoreLeaseSet(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("Storing LeaseSet from DatabaseStore message")

	// Validate data type (1 = standard LeaseSet in I2P protocol)
	if err := validateLeaseSetDataType(dataType); err != nil {
		return err
	}

	// Parse LeaseSet from raw bytes
	ls, err := parseLeaseSetData(data)
	if err != nil {
		return err
	}

	// Verify hash matches the LeaseSet destination hash
	if err := verifyLeaseSetHash(key, ls); err != nil {
		return err
	}

	// Add to memory cache if not already present
	if !db.addLeaseSetToCache(key, ls) {
		return nil
	}

	// Persist to filesystem
	if err := db.persistLeaseSetToFilesystem(key, ls); err != nil {
		return err
	}

	log.WithField("hash", key).Debug("Successfully stored LeaseSet")
	return nil
}

// validateLeaseSetDataType checks if the data type is valid for LeaseSet storage.
func validateLeaseSetDataType(dataType byte) error {
	if dataType != 1 {
		log.WithField("type", dataType).Warn("Invalid data type for LeaseSet, expected 1")
		return fmt.Errorf("invalid data type for LeaseSet: expected 1, got %d", dataType)
	}
	return nil
}

// parseLeaseSetData parses LeaseSet from raw bytes using the common library.
func parseLeaseSetData(data []byte) (lease_set.LeaseSet, error) {
	ls, err := lease_set.ReadLeaseSet(data)
	if err != nil {
		log.WithError(err).Error("Failed to parse LeaseSet from DatabaseStore data")
		return lease_set.LeaseSet{}, fmt.Errorf("failed to parse LeaseSet: %w", err)
	}
	return ls, nil
}

// verifyLeaseSetHash validates that the provided key matches the LeaseSet destination hash.
func verifyLeaseSetHash(key common.Hash, ls lease_set.LeaseSet) error {
	dest, err := ls.Destination()
	if err != nil {
		return fmt.Errorf("failed to get LeaseSet destination: %w", err)
	}

	// Calculate hash from destination bytes
	destBytes, err := dest.Bytes()
	if err != nil {
		return fmt.Errorf("failed to get destination bytes: %w", err)
	}
	expectedHash := common.HashData(destBytes)
	if key != expectedHash {
		log.WithFields(logger.Fields{
			"expected_hash": expectedHash,
			"provided_key":  key,
		}).Error("LeaseSet hash mismatch")
		return fmt.Errorf("LeaseSet hash mismatch: expected %x, got %x", expectedHash, key)
	}
	return nil
}

// addLeaseSetToCache adds a LeaseSet entry to the in-memory cache if it doesn't exist.
// Returns true if the entry was added, false if it already existed.
// Also tracks the expiration time for automatic cleanup.
func (db *StdNetDB) addLeaseSetToCache(key common.Hash, ls lease_set.LeaseSet) bool {
	db.lsMutex.Lock()
	defer db.lsMutex.Unlock()

	if _, exists := db.LeaseSets[key]; exists {
		log.WithField("hash", key).Debug("LeaseSet already exists in memory, skipping")
		return false
	}

	db.LeaseSets[key] = Entry{
		LeaseSet: &ls,
	}

	// Track expiration time for cleanup
	db.trackLeaseSetExpiration(key, ls)

	return true
}

// persistLeaseSetToFilesystem saves a LeaseSet entry to the filesystem.
// If the save fails, it removes the entry from the in-memory cache to maintain consistency.
func (db *StdNetDB) persistLeaseSetToFilesystem(key common.Hash, ls lease_set.LeaseSet) error {
	entry := &Entry{
		LeaseSet: &ls,
	}

	fpath := db.SkiplistFileForLeaseSet(key)
	f, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		log.WithError(err).Error("Failed to open file for saving LeaseSet")
		db.lsMutex.Lock()
		delete(db.LeaseSets, key)
		db.lsMutex.Unlock()
		return fmt.Errorf("failed to open LeaseSet file: %w", err)
	}
	defer f.Close()

	if err := entry.WriteTo(f); err != nil {
		log.WithError(err).Error("Failed to write LeaseSet to filesystem")
		db.lsMutex.Lock()
		delete(db.LeaseSets, key)
		db.lsMutex.Unlock()
		return fmt.Errorf("failed to save LeaseSet to filesystem: %w", err)
	}

	return nil
}

// GetLeaseSet retrieves a LeaseSet from the database by its hash.
// Returns a channel that yields the LeaseSet or nil if not found.
// Checks memory cache first, then loads from filesystem if necessary.
func (db *StdNetDB) GetLeaseSet(hash common.Hash) (chnl chan lease_set.LeaseSet) {
	log.WithField("hash", hash).Debug("Getting LeaseSet")

	// Check memory cache first
	db.lsMutex.Lock()
	if ls, ok := db.LeaseSets[hash]; ok {
		db.lsMutex.Unlock()
		log.Debug("LeaseSet found in memory cache")
		chnl = make(chan lease_set.LeaseSet, 1)
		chnl <- *ls.LeaseSet
		close(chnl)
		return
	}
	db.lsMutex.Unlock()

	// Load from file
	data, err := db.loadLeaseSetFromFile(hash)
	if err != nil {
		log.WithError(err).Error("Failed to load LeaseSet from file")
		return nil
	}

	chnl = make(chan lease_set.LeaseSet, 1)
	ls, err := db.parseAndCacheLeaseSet(hash, data)
	if err != nil {
		log.WithError(err).Error("Failed to parse LeaseSet")
		close(chnl)
		return
	}

	chnl <- ls
	close(chnl)
	return
}

// loadLeaseSetFromFile loads LeaseSet data from the skiplist file.
func (db *StdNetDB) loadLeaseSetFromFile(hash common.Hash) ([]byte, error) {
	fname := db.SkiplistFileForLeaseSet(hash)
	buff := new(bytes.Buffer)

	f, err := os.Open(fname)
	if err != nil {
		return nil, fmt.Errorf("failed to open LeaseSet file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(buff, f); err != nil {
		return nil, fmt.Errorf("failed to read LeaseSet file: %w", err)
	}

	return buff.Bytes(), nil
}

// parseAndCacheLeaseSet parses LeaseSet data and adds it to the memory cache.
func (db *StdNetDB) parseAndCacheLeaseSet(hash common.Hash, data []byte) (lease_set.LeaseSet, error) {
	ls, err := lease_set.ReadLeaseSet(data)
	if err != nil {
		return lease_set.LeaseSet{}, fmt.Errorf("failed to parse LeaseSet: %w", err)
	}

	// Add to cache if not already present
	db.lsMutex.Lock()
	if _, ok := db.LeaseSets[hash]; !ok {
		log.Debug("Adding LeaseSet to memory cache")
		db.LeaseSets[hash] = Entry{
			LeaseSet: &ls,
		}
	}
	db.lsMutex.Unlock()

	return ls, nil
}

// GetLeaseSetBytes retrieves LeaseSet data as bytes from the database.
// Checks memory cache first, then loads from filesystem if necessary.
// Returns serialized LeaseSet bytes suitable for network transmission.
func (db *StdNetDB) GetLeaseSetBytes(hash common.Hash) ([]byte, error) {
	log.WithField("hash", hash).Debug("Getting LeaseSet bytes")

	// Check memory cache first
	db.lsMutex.Lock()
	if ls, ok := db.LeaseSets[hash]; ok && ls.LeaseSet != nil {
		db.lsMutex.Unlock()
		log.Debug("LeaseSet found in memory cache")

		// Serialize the LeaseSet to bytes
		data, err := ls.LeaseSet.Bytes()
		if err != nil {
			log.WithError(err).Error("Failed to serialize cached LeaseSet")
			return nil, fmt.Errorf("failed to serialize LeaseSet: %w", err)
		}
		return data, nil
	}
	db.lsMutex.Unlock()

	// Load from file if not in memory
	data, err := db.loadLeaseSetFromFile(hash)
	if err != nil {
		log.WithError(err).Debug("LeaseSet not found in filesystem")
		return nil, fmt.Errorf("LeaseSet not found: %w", err)
	}

	// Parse and cache for future use
	_, err = db.parseAndCacheLeaseSet(hash, data)
	if err != nil {
		log.WithError(err).Error("Failed to parse LeaseSet from file")
		return nil, fmt.Errorf("failed to parse LeaseSet: %w", err)
	}

	return data, nil
}

// GetLeaseSetCount returns the total number of LeaseSet entries in memory cache.
func (db *StdNetDB) GetLeaseSetCount() int {
	db.lsMutex.Lock()
	defer db.lsMutex.Unlock()
	return len(db.LeaseSets)
}

// ======================================================================
// LeaseSet2 Storage and Retrieval Methods
// ======================================================================

// StoreLeaseSet2 stores a LeaseSet2 entry in the database from I2NP DatabaseStore message.
// This method validates, parses, caches, and persists LeaseSet2 data.
// dataType should be 3 for LeaseSet2 (matching I2P protocol specification).
func (db *StdNetDB) StoreLeaseSet2(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("Storing LeaseSet2 from DatabaseStore message")

	// Validate data type (3 = LeaseSet2 in I2P protocol)
	if err := validateLeaseSet2DataType(dataType); err != nil {
		return err
	}

	// Parse LeaseSet2 from raw bytes
	ls2, err := parseLeaseSet2Data(data)
	if err != nil {
		return err
	}

	// Verify hash matches the LeaseSet2 destination hash
	if err := verifyLeaseSet2Hash(key, ls2); err != nil {
		return err
	}

	// Add to memory cache if not already present
	if !db.addLeaseSet2ToCache(key, ls2) {
		return nil
	}

	// Persist to filesystem
	if err := db.persistLeaseSet2ToFilesystem(key, ls2); err != nil {
		return err
	}

	log.WithField("hash", key).Debug("Successfully stored LeaseSet2")
	return nil
}

// validateLeaseSet2DataType checks if the data type is valid for LeaseSet2 storage.
func validateLeaseSet2DataType(dataType byte) error {
	if dataType != 3 {
		log.WithField("type", dataType).Warn("Invalid data type for LeaseSet2, expected 3")
		return fmt.Errorf("invalid data type for LeaseSet2: expected 3, got %d", dataType)
	}
	return nil
}

// parseLeaseSet2Data parses LeaseSet2 from raw bytes using the common library.
func parseLeaseSet2Data(data []byte) (lease_set2.LeaseSet2, error) {
	ls2, _, err := lease_set2.ReadLeaseSet2(data)
	if err != nil {
		log.WithError(err).Error("Failed to parse LeaseSet2 from DatabaseStore data")
		return lease_set2.LeaseSet2{}, fmt.Errorf("failed to parse LeaseSet2: %w", err)
	}
	return ls2, nil
}

// verifyLeaseSet2Hash validates that the provided key matches the LeaseSet2 destination hash.
func verifyLeaseSet2Hash(key common.Hash, ls2 lease_set2.LeaseSet2) error {
	dest := ls2.Destination()

	// Calculate hash from destination bytes
	destBytes, err := dest.Bytes()
	if err != nil {
		return fmt.Errorf("failed to get destination bytes: %w", err)
	}
	expectedHash := common.HashData(destBytes)
	if key != expectedHash {
		log.WithFields(logger.Fields{
			"expected_hash": expectedHash,
			"provided_key":  key,
		}).Error("LeaseSet2 hash mismatch")
		return fmt.Errorf("LeaseSet2 hash mismatch: expected %x, got %x", expectedHash, key)
	}
	return nil
}

// addLeaseSet2ToCache adds a LeaseSet2 entry to the in-memory cache if it doesn't exist.
// Returns true if the entry was added, false if it already existed.
func (db *StdNetDB) addLeaseSet2ToCache(key common.Hash, ls2 lease_set2.LeaseSet2) bool {
	db.lsMutex.Lock()
	defer db.lsMutex.Unlock()

	if _, exists := db.LeaseSets[key]; exists {
		log.WithField("hash", key).Debug("LeaseSet2 already exists in memory (as LeaseSet entry), skipping")
		return false
	}

	db.LeaseSets[key] = Entry{
		LeaseSet2: &ls2,
	}

	// Track expiration time for cleanup
	db.trackLeaseSet2Expiration(key, ls2)

	return true
}

// persistLeaseSet2ToFilesystem saves a LeaseSet2 entry to the filesystem.
// If the save fails, it removes the entry from the in-memory cache to maintain consistency.
func (db *StdNetDB) persistLeaseSet2ToFilesystem(key common.Hash, ls2 lease_set2.LeaseSet2) error {
	entry := &Entry{
		LeaseSet2: &ls2,
	}

	fpath := db.SkiplistFileForLeaseSet(key)
	f, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		log.WithError(err).Error("Failed to open file for saving LeaseSet2")
		db.lsMutex.Lock()
		delete(db.LeaseSets, key)
		db.lsMutex.Unlock()
		return fmt.Errorf("failed to open LeaseSet2 file: %w", err)
	}
	defer f.Close()

	if err := entry.WriteTo(f); err != nil {
		log.WithError(err).Error("Failed to write LeaseSet2 to filesystem")
		db.lsMutex.Lock()
		delete(db.LeaseSets, key)
		db.lsMutex.Unlock()
		return fmt.Errorf("failed to save LeaseSet2 to filesystem: %w", err)
	}

	return nil
}

// GetLeaseSet2 retrieves a LeaseSet2 from the database by its hash.
// Returns a channel that yields the LeaseSet2 or nil if not found.
// Checks memory cache first, then loads from filesystem if necessary.
func (db *StdNetDB) GetLeaseSet2(hash common.Hash) (chnl chan lease_set2.LeaseSet2) {
	log.WithField("hash", hash).Debug("Getting LeaseSet2")

	// Check memory cache first
	db.lsMutex.Lock()
	if ls, ok := db.LeaseSets[hash]; ok && ls.LeaseSet2 != nil {
		db.lsMutex.Unlock()
		log.Debug("LeaseSet2 found in memory cache")
		chnl = make(chan lease_set2.LeaseSet2, 1)
		chnl <- *ls.LeaseSet2
		close(chnl)
		return
	}
	db.lsMutex.Unlock()

	// Load from file
	data, err := db.loadLeaseSetFromFile(hash)
	if err != nil {
		log.WithError(err).Error("Failed to load LeaseSet2 from file")
		return nil
	}

	chnl = make(chan lease_set2.LeaseSet2, 1)
	ls2, err := db.parseAndCacheLeaseSet2(hash, data)
	if err != nil {
		log.WithError(err).Error("Failed to parse LeaseSet2")
		close(chnl)
		return
	}

	chnl <- ls2
	close(chnl)
	return
}

// parseAndCacheLeaseSet2 parses LeaseSet2 data and adds it to the memory cache.
func (db *StdNetDB) parseAndCacheLeaseSet2(hash common.Hash, data []byte) (lease_set2.LeaseSet2, error) {
	ls2, _, err := lease_set2.ReadLeaseSet2(data)
	if err != nil {
		return lease_set2.LeaseSet2{}, fmt.Errorf("failed to parse LeaseSet2: %w", err)
	}

	// Add to cache if not already present
	db.lsMutex.Lock()
	if _, ok := db.LeaseSets[hash]; !ok {
		log.Debug("Adding LeaseSet2 to memory cache")
		db.LeaseSets[hash] = Entry{
			LeaseSet2: &ls2,
		}
	}
	db.lsMutex.Unlock()

	return ls2, nil
}

// GetLeaseSet2Bytes retrieves LeaseSet2 data as bytes from the database.
// Checks memory cache first, then loads from filesystem if necessary.
// Returns serialized LeaseSet2 bytes suitable for network transmission.
func (db *StdNetDB) GetLeaseSet2Bytes(hash common.Hash) ([]byte, error) {
	log.WithField("hash", hash).Debug("Getting LeaseSet2 bytes")

	// Check memory cache first
	db.lsMutex.Lock()
	if ls, ok := db.LeaseSets[hash]; ok && ls.LeaseSet2 != nil {
		db.lsMutex.Unlock()
		log.Debug("LeaseSet2 found in memory cache")

		// Serialize the LeaseSet2 to bytes
		data, err := ls.LeaseSet2.Bytes()
		if err != nil {
			log.WithError(err).Error("Failed to serialize cached LeaseSet2")
			return nil, fmt.Errorf("failed to serialize LeaseSet2: %w", err)
		}
		return data, nil
	}
	db.lsMutex.Unlock()

	// Load from file if not in memory
	data, err := db.loadLeaseSetFromFile(hash)
	if err != nil {
		log.WithError(err).Debug("LeaseSet2 not found in filesystem")
		return nil, fmt.Errorf("LeaseSet2 not found: %w", err)
	}

	// Parse and cache for future use
	_, err = db.parseAndCacheLeaseSet2(hash, data)
	if err != nil {
		log.WithError(err).Error("Failed to parse LeaseSet2 from file")
		return nil, fmt.Errorf("failed to parse LeaseSet2: %w", err)
	}

	return data, nil
}

// ======================================================================
// EncryptedLeaseSet Storage and Retrieval Methods
// ======================================================================

// StoreEncryptedLeaseSet stores an EncryptedLeaseSet entry in the database from I2NP DatabaseStore message.
// This method validates, parses, caches, and persists EncryptedLeaseSet data.
// dataType should be 5 for EncryptedLeaseSet (matching I2P protocol specification).
func (db *StdNetDB) StoreEncryptedLeaseSet(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("Storing EncryptedLeaseSet from DatabaseStore message")

	// Validate data type (5 = EncryptedLeaseSet in I2P protocol)
	if err := validateEncryptedLeaseSetDataType(dataType); err != nil {
		return err
	}

	// Parse EncryptedLeaseSet from raw bytes
	els, err := parseEncryptedLeaseSetData(data)
	if err != nil {
		return err
	}

	// Verify hash matches the EncryptedLeaseSet blinded destination hash
	if err := verifyEncryptedLeaseSetHash(key, els); err != nil {
		return err
	}

	// Add to memory cache if not already present
	if !db.addEncryptedLeaseSetToCache(key, els) {
		return nil
	}

	// Persist to filesystem
	if err := db.persistEncryptedLeaseSetToFilesystem(key, els); err != nil {
		return err
	}

	log.WithField("hash", key).Debug("Successfully stored EncryptedLeaseSet")
	return nil
}

// validateEncryptedLeaseSetDataType checks if the data type is valid for EncryptedLeaseSet storage.
func validateEncryptedLeaseSetDataType(dataType byte) error {
	if dataType != 5 {
		log.WithField("type", dataType).Warn("Invalid data type for EncryptedLeaseSet, expected 5")
		return fmt.Errorf("invalid data type for EncryptedLeaseSet: expected 5, got %d", dataType)
	}
	return nil
}

// parseEncryptedLeaseSetData parses EncryptedLeaseSet from raw bytes using the common library.
func parseEncryptedLeaseSetData(data []byte) (encrypted_leaseset.EncryptedLeaseSet, error) {
	els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(data)
	if err != nil {
		log.WithError(err).Error("Failed to parse EncryptedLeaseSet from DatabaseStore data")
		return encrypted_leaseset.EncryptedLeaseSet{}, fmt.Errorf("failed to parse EncryptedLeaseSet: %w", err)
	}
	return els, nil
}

// verifyEncryptedLeaseSetHash validates that the provided key matches the EncryptedLeaseSet blinded destination hash.
func verifyEncryptedLeaseSetHash(key common.Hash, els encrypted_leaseset.EncryptedLeaseSet) error {
	dest := els.BlindedDestination()

	// Calculate hash from blinded destination bytes
	destBytes, err := dest.Bytes()
	if err != nil {
		return fmt.Errorf("failed to get blinded destination bytes: %w", err)
	}
	expectedHash := common.HashData(destBytes)
	if key != expectedHash {
		log.WithFields(logger.Fields{
			"expected_hash": expectedHash,
			"provided_key":  key,
		}).Error("EncryptedLeaseSet hash mismatch")
		return fmt.Errorf("EncryptedLeaseSet hash mismatch: expected %x, got %x", expectedHash, key)
	}
	return nil
}

// addEncryptedLeaseSetToCache adds an EncryptedLeaseSet entry to the in-memory cache if it doesn't exist.
// Returns true if the entry was added, false if it already existed.
func (db *StdNetDB) addEncryptedLeaseSetToCache(key common.Hash, els encrypted_leaseset.EncryptedLeaseSet) bool {
	db.lsMutex.Lock()
	defer db.lsMutex.Unlock()

	if _, exists := db.LeaseSets[key]; exists {
		log.WithField("hash", key).Debug("EncryptedLeaseSet already exists in memory, skipping")
		return false
	}

	db.LeaseSets[key] = Entry{
		EncryptedLeaseSet: &els,
	}

	// Track expiration time for cleanup
	db.trackEncryptedLeaseSetExpiration(key, els)

	return true
}

// persistEncryptedLeaseSetToFilesystem saves an EncryptedLeaseSet entry to the filesystem.
// If the save fails, it removes the entry from the in-memory cache to maintain consistency.
func (db *StdNetDB) persistEncryptedLeaseSetToFilesystem(key common.Hash, els encrypted_leaseset.EncryptedLeaseSet) error {
	entry := &Entry{
		EncryptedLeaseSet: &els,
	}

	fpath := db.SkiplistFileForLeaseSet(key)
	f, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		log.WithError(err).Error("Failed to open file for saving EncryptedLeaseSet")
		db.lsMutex.Lock()
		delete(db.LeaseSets, key)
		db.lsMutex.Unlock()
		return fmt.Errorf("failed to open EncryptedLeaseSet file: %w", err)
	}
	defer f.Close()

	if err := entry.WriteTo(f); err != nil {
		log.WithError(err).Error("Failed to write EncryptedLeaseSet to filesystem")
		db.lsMutex.Lock()
		delete(db.LeaseSets, key)
		db.lsMutex.Unlock()
		return fmt.Errorf("failed to save EncryptedLeaseSet to filesystem: %w", err)
	}

	return nil
}

// GetEncryptedLeaseSet retrieves an EncryptedLeaseSet from the database by its hash.
// Returns a channel that yields the EncryptedLeaseSet or nil if not found.
// Checks memory cache first, then loads from filesystem if necessary.
func (db *StdNetDB) GetEncryptedLeaseSet(hash common.Hash) (chnl chan encrypted_leaseset.EncryptedLeaseSet) {
	log.WithField("hash", hash).Debug("Getting EncryptedLeaseSet")

	// Check memory cache first
	db.lsMutex.Lock()
	if ls, ok := db.LeaseSets[hash]; ok && ls.EncryptedLeaseSet != nil {
		db.lsMutex.Unlock()
		log.Debug("EncryptedLeaseSet found in memory cache")
		chnl = make(chan encrypted_leaseset.EncryptedLeaseSet, 1)
		chnl <- *ls.EncryptedLeaseSet
		close(chnl)
		return
	}
	db.lsMutex.Unlock()

	// Load from file
	data, err := db.loadLeaseSetFromFile(hash)
	if err != nil {
		log.WithError(err).Error("Failed to load EncryptedLeaseSet from file")
		return nil
	}

	chnl = make(chan encrypted_leaseset.EncryptedLeaseSet, 1)
	els, err := db.parseAndCacheEncryptedLeaseSet(hash, data)
	if err != nil {
		log.WithError(err).Error("Failed to parse EncryptedLeaseSet")
		close(chnl)
		return
	}

	chnl <- els
	close(chnl)
	return
}

// parseAndCacheEncryptedLeaseSet parses EncryptedLeaseSet data and adds it to the memory cache.
func (db *StdNetDB) parseAndCacheEncryptedLeaseSet(hash common.Hash, data []byte) (encrypted_leaseset.EncryptedLeaseSet, error) {
	els, _, err := encrypted_leaseset.ReadEncryptedLeaseSet(data)
	if err != nil {
		return encrypted_leaseset.EncryptedLeaseSet{}, fmt.Errorf("failed to parse EncryptedLeaseSet: %w", err)
	}

	// Add to cache if not already present
	db.lsMutex.Lock()
	if _, ok := db.LeaseSets[hash]; !ok {
		log.Debug("Adding EncryptedLeaseSet to memory cache")
		db.LeaseSets[hash] = Entry{
			EncryptedLeaseSet: &els,
		}
	}
	db.lsMutex.Unlock()

	return els, nil
}

// GetEncryptedLeaseSetBytes retrieves EncryptedLeaseSet data as bytes from the database.
// Checks memory cache first, then loads from filesystem if necessary.
// Returns serialized EncryptedLeaseSet bytes suitable for network transmission.
func (db *StdNetDB) GetEncryptedLeaseSetBytes(hash common.Hash) ([]byte, error) {
	log.WithField("hash", hash).Debug("Getting EncryptedLeaseSet bytes")

	// Check memory cache first
	db.lsMutex.Lock()
	if ls, ok := db.LeaseSets[hash]; ok && ls.EncryptedLeaseSet != nil {
		db.lsMutex.Unlock()
		log.Debug("EncryptedLeaseSet found in memory cache")

		// Serialize the EncryptedLeaseSet to bytes
		data, err := ls.EncryptedLeaseSet.Bytes()
		if err != nil {
			log.WithError(err).Error("Failed to serialize cached EncryptedLeaseSet")
			return nil, fmt.Errorf("failed to serialize EncryptedLeaseSet: %w", err)
		}
		return data, nil
	}
	db.lsMutex.Unlock()

	// Load from file if not in memory
	data, err := db.loadLeaseSetFromFile(hash)
	if err != nil {
		log.WithError(err).Debug("EncryptedLeaseSet not found in filesystem")
		return nil, fmt.Errorf("EncryptedLeaseSet not found: %w", err)
	}

	// Parse and cache for future use
	_, err = db.parseAndCacheEncryptedLeaseSet(hash, data)
	if err != nil {
		log.WithError(err).Error("Failed to parse EncryptedLeaseSet from file")
		return nil, fmt.Errorf("failed to parse EncryptedLeaseSet: %w", err)
	}

	return data, nil
}

// ======================================================================
// MetaLeaseSet Storage and Retrieval Methods
// ======================================================================

// StoreMetaLeaseSet stores a MetaLeaseSet entry in the database from I2NP DatabaseStore message.
// This method validates, parses, caches, and persists MetaLeaseSet data.
// dataType should be 7 for MetaLeaseSet (matching I2P protocol specification).
func (db *StdNetDB) StoreMetaLeaseSet(key common.Hash, data []byte, dataType byte) error {
	log.WithField("hash", key).Debug("Storing MetaLeaseSet from DatabaseStore message")

	// Validate data type (7 = MetaLeaseSet in I2P protocol)
	if err := validateMetaLeaseSetDataType(dataType); err != nil {
		return err
	}

	// Parse MetaLeaseSet from raw bytes
	mls, err := parseMetaLeaseSetData(data)
	if err != nil {
		return err
	}

	// Verify hash matches the MetaLeaseSet destination hash
	if err := verifyMetaLeaseSetHash(key, mls); err != nil {
		return err
	}

	// Add to memory cache if not already present
	if !db.addMetaLeaseSetToCache(key, mls) {
		return nil
	}

	// Persist to filesystem
	if err := db.persistMetaLeaseSetToFilesystem(key, mls); err != nil {
		return err
	}

	log.WithField("hash", key).Debug("Successfully stored MetaLeaseSet")
	return nil
}

// validateMetaLeaseSetDataType checks if the data type is valid for MetaLeaseSet storage.
func validateMetaLeaseSetDataType(dataType byte) error {
	if dataType != 7 {
		log.WithField("type", dataType).Warn("Invalid data type for MetaLeaseSet, expected 7")
		return fmt.Errorf("invalid data type for MetaLeaseSet: expected 7, got %d", dataType)
	}
	return nil
}

// parseMetaLeaseSetData parses MetaLeaseSet from raw bytes using the common library.
func parseMetaLeaseSetData(data []byte) (meta_leaseset.MetaLeaseSet, error) {
	mls, _, err := meta_leaseset.ReadMetaLeaseSet(data)
	if err != nil {
		log.WithError(err).Error("Failed to parse MetaLeaseSet from DatabaseStore data")
		return meta_leaseset.MetaLeaseSet{}, fmt.Errorf("failed to parse MetaLeaseSet: %w", err)
	}
	return mls, nil
}

// verifyMetaLeaseSetHash validates that the provided key matches the MetaLeaseSet destination hash.
func verifyMetaLeaseSetHash(key common.Hash, mls meta_leaseset.MetaLeaseSet) error {
	dest := mls.Destination()

	// Calculate hash from destination bytes
	destBytes, err := dest.Bytes()
	if err != nil {
		return fmt.Errorf("failed to get destination bytes: %w", err)
	}
	expectedHash := common.HashData(destBytes)
	if key != expectedHash {
		log.WithFields(logger.Fields{
			"expected_hash": expectedHash,
			"provided_key":  key,
		}).Error("MetaLeaseSet hash mismatch")
		return fmt.Errorf("MetaLeaseSet hash mismatch: expected %x, got %x", expectedHash, key)
	}
	return nil
}

// addMetaLeaseSetToCache adds a MetaLeaseSet entry to the in-memory cache if it doesn't exist.
// Returns true if the entry was added, false if it already existed.
func (db *StdNetDB) addMetaLeaseSetToCache(key common.Hash, mls meta_leaseset.MetaLeaseSet) bool {
	db.lsMutex.Lock()
	defer db.lsMutex.Unlock()

	if _, exists := db.LeaseSets[key]; exists {
		log.WithField("hash", key).Debug("MetaLeaseSet already exists in memory, skipping")
		return false
	}

	db.LeaseSets[key] = Entry{
		MetaLeaseSet: &mls,
	}

	// Track expiration time for cleanup
	db.trackMetaLeaseSetExpiration(key, mls)

	return true
}

// persistMetaLeaseSetToFilesystem saves a MetaLeaseSet entry to the filesystem.
// If the save fails, it removes the entry from the in-memory cache to maintain consistency.
func (db *StdNetDB) persistMetaLeaseSetToFilesystem(key common.Hash, mls meta_leaseset.MetaLeaseSet) error {
	entry := &Entry{
		MetaLeaseSet: &mls,
	}

	fpath := db.SkiplistFileForLeaseSet(key)
	f, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		log.WithError(err).Error("Failed to open file for saving MetaLeaseSet")
		db.lsMutex.Lock()
		delete(db.LeaseSets, key)
		db.lsMutex.Unlock()
		return fmt.Errorf("failed to open MetaLeaseSet file: %w", err)
	}
	defer f.Close()

	if err := entry.WriteTo(f); err != nil {
		log.WithError(err).Error("Failed to write MetaLeaseSet to filesystem")
		db.lsMutex.Lock()
		delete(db.LeaseSets, key)
		db.lsMutex.Unlock()
		return fmt.Errorf("failed to save MetaLeaseSet to filesystem: %w", err)
	}

	return nil
}

// GetMetaLeaseSet retrieves a MetaLeaseSet from the database by its hash.
// Returns a channel that yields the MetaLeaseSet or nil if not found.
// Checks memory cache first, then loads from filesystem if necessary.
func (db *StdNetDB) GetMetaLeaseSet(hash common.Hash) (chnl chan meta_leaseset.MetaLeaseSet) {
	log.WithField("hash", hash).Debug("Getting MetaLeaseSet")

	// Check memory cache first
	db.lsMutex.Lock()
	if ls, ok := db.LeaseSets[hash]; ok && ls.MetaLeaseSet != nil {
		db.lsMutex.Unlock()
		log.Debug("MetaLeaseSet found in memory cache")
		chnl = make(chan meta_leaseset.MetaLeaseSet, 1)
		chnl <- *ls.MetaLeaseSet
		close(chnl)
		return
	}
	db.lsMutex.Unlock()

	// Load from file
	data, err := db.loadLeaseSetFromFile(hash)
	if err != nil {
		log.WithError(err).Error("Failed to load MetaLeaseSet from file")
		return nil
	}

	chnl = make(chan meta_leaseset.MetaLeaseSet, 1)
	mls, err := db.parseAndCacheMetaLeaseSet(hash, data)
	if err != nil {
		log.WithError(err).Error("Failed to parse MetaLeaseSet")
		close(chnl)
		return
	}

	chnl <- mls
	close(chnl)
	return
}

// parseAndCacheMetaLeaseSet parses MetaLeaseSet data and adds it to the memory cache.
func (db *StdNetDB) parseAndCacheMetaLeaseSet(hash common.Hash, data []byte) (meta_leaseset.MetaLeaseSet, error) {
	mls, _, err := meta_leaseset.ReadMetaLeaseSet(data)
	if err != nil {
		return meta_leaseset.MetaLeaseSet{}, fmt.Errorf("failed to parse MetaLeaseSet: %w", err)
	}

	// Add to cache if not already present
	db.lsMutex.Lock()
	if _, ok := db.LeaseSets[hash]; !ok {
		log.Debug("Adding MetaLeaseSet to memory cache")
		db.LeaseSets[hash] = Entry{
			MetaLeaseSet: &mls,
		}
	}
	db.lsMutex.Unlock()

	return mls, nil
}

// GetMetaLeaseSetBytes retrieves MetaLeaseSet data as bytes from the database.
// Checks memory cache first, then loads from filesystem if necessary.
// Returns serialized MetaLeaseSet bytes suitable for network transmission.
func (db *StdNetDB) GetMetaLeaseSetBytes(hash common.Hash) ([]byte, error) {
	log.WithField("hash", hash).Debug("Getting MetaLeaseSet bytes")

	// Check memory cache first
	db.lsMutex.Lock()
	if ls, ok := db.LeaseSets[hash]; ok && ls.MetaLeaseSet != nil {
		db.lsMutex.Unlock()
		log.Debug("MetaLeaseSet found in memory cache")

		// Serialize the MetaLeaseSet to bytes
		data, err := ls.MetaLeaseSet.Bytes()
		if err != nil {
			log.WithError(err).Error("Failed to serialize cached MetaLeaseSet")
			return nil, fmt.Errorf("failed to serialize MetaLeaseSet: %w", err)
		}
		return data, nil
	}
	db.lsMutex.Unlock()

	// Load from file if not in memory
	data, err := db.loadLeaseSetFromFile(hash)
	if err != nil {
		log.WithError(err).Debug("MetaLeaseSet not found in filesystem")
		return nil, fmt.Errorf("MetaLeaseSet not found: %w", err)
	}

	// Parse and cache for future use
	_, err = db.parseAndCacheMetaLeaseSet(hash, data)
	if err != nil {
		log.WithError(err).Error("Failed to parse MetaLeaseSet from file")
		return nil, fmt.Errorf("failed to parse MetaLeaseSet: %w", err)
	}

	return data, nil
}

// ======================================================================
// LeaseSet Expiration Tracking and Cleanup
// ======================================================================

// trackLeaseSetExpiration extracts the expiration time from a LeaseSet and records it.
// Uses the NewestExpiration() method to find the latest expiration time among all leases.
func (db *StdNetDB) trackLeaseSetExpiration(key common.Hash, ls lease_set.LeaseSet) {
	// Get the newest expiration time from all leases in the LeaseSet
	expiration, err := ls.NewestExpiration()
	if err != nil {
		log.WithError(err).WithField("hash", key).Warn("Failed to get LeaseSet expiration, using default 10 minutes")
		// Default to 10 minutes from now if we can't determine expiration
		db.expiryMutex.Lock()
		db.leaseSetExpiry[key] = time.Now().Add(10 * time.Minute)
		db.expiryMutex.Unlock()
		return
	}

	expiryTime := expiration.Time()
	db.expiryMutex.Lock()
	db.leaseSetExpiry[key] = expiryTime
	db.expiryMutex.Unlock()

	log.WithFields(logger.Fields{
		"hash":       fmt.Sprintf("%x", key[:8]),
		"expiration": expiryTime,
		"ttl":        time.Until(expiryTime).Round(time.Second),
	}).Debug("Tracked LeaseSet expiration")
}

// trackLeaseSet2Expiration extracts the expiration time from a LeaseSet2 and records it.
// Uses the ExpirationTime() method to get the expiration timestamp.
func (db *StdNetDB) trackLeaseSet2Expiration(key common.Hash, ls2 lease_set2.LeaseSet2) {
	expiryTime := ls2.ExpirationTime()
	db.expiryMutex.Lock()
	db.leaseSetExpiry[key] = expiryTime
	db.expiryMutex.Unlock()

	log.WithFields(logger.Fields{
		"hash":       fmt.Sprintf("%x", key[:8]),
		"expiration": expiryTime,
		"ttl":        time.Until(expiryTime).Round(time.Second),
	}).Debug("Tracked LeaseSet2 expiration")
}

// trackEncryptedLeaseSetExpiration extracts the expiration time from an EncryptedLeaseSet and records it.
// Uses the ExpirationTime() method to get the expiration timestamp.
func (db *StdNetDB) trackEncryptedLeaseSetExpiration(key common.Hash, els encrypted_leaseset.EncryptedLeaseSet) {
	expiryTime := els.ExpirationTime()
	db.expiryMutex.Lock()
	db.leaseSetExpiry[key] = expiryTime
	db.expiryMutex.Unlock()

	log.WithFields(logger.Fields{
		"hash":       fmt.Sprintf("%x", key[:8]),
		"expiration": expiryTime,
		"ttl":        time.Until(expiryTime).Round(time.Second),
	}).Debug("Tracked EncryptedLeaseSet expiration")
}

// trackMetaLeaseSetExpiration extracts the expiration time from a MetaLeaseSet and records it.
// Uses the ExpirationTime() method to get the expiration timestamp.
func (db *StdNetDB) trackMetaLeaseSetExpiration(key common.Hash, mls meta_leaseset.MetaLeaseSet) {
	expiryTime := mls.ExpirationTime()
	db.expiryMutex.Lock()
	db.leaseSetExpiry[key] = expiryTime
	db.expiryMutex.Unlock()

	log.WithFields(logger.Fields{
		"hash":       fmt.Sprintf("%x", key[:8]),
		"expiration": expiryTime,
		"ttl":        time.Until(expiryTime).Round(time.Second),
	}).Debug("Tracked MetaLeaseSet expiration")
}

// StartExpirationCleaner starts a background goroutine that periodically removes expired LeaseSets.
// The cleanup runs every minute and removes any LeaseSets whose expiration time has passed.
// This method should be called once during NetDB initialization.
// Use Stop() to gracefully shut down the cleanup goroutine.
func (db *StdNetDB) StartExpirationCleaner() {
	log.Info("Starting LeaseSet expiration cleaner (runs every 1 minute)")

	db.cleanupWg.Add(1)
	go func() {
		defer db.cleanupWg.Done()

		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				db.cleanExpiredLeaseSets()
			case <-db.ctx.Done():
				log.Info("Stopping LeaseSet expiration cleaner")
				return
			}
		}
	}()
}

// Stop gracefully shuts down the expiration cleaner goroutine.
// Blocks until the cleanup goroutine has exited.
func (db *StdNetDB) Stop() {
	if db.cancel != nil {
		log.Info("Stopping StdNetDB")
		db.cancel()
		db.cleanupWg.Wait()
		log.Info("StdNetDB stopped")
	}
}

// cleanExpiredLeaseSets removes LeaseSets that have passed their expiration time.
// This method is called periodically by the expiration cleaner goroutine.
// It removes entries from both the in-memory cache and the filesystem.
func (db *StdNetDB) cleanExpiredLeaseSets() {
	now := time.Now()

	// Find all expired LeaseSets
	db.expiryMutex.RLock()
	expired := make([]common.Hash, 0)
	for hash, expiryTime := range db.leaseSetExpiry {
		if now.After(expiryTime) {
			expired = append(expired, hash)
		}
	}
	db.expiryMutex.RUnlock()

	if len(expired) == 0 {
		return
	}

	// Remove expired entries
	for _, hash := range expired {
		db.removeExpiredLeaseSet(hash)
	}

	log.WithFields(logger.Fields{
		"count": len(expired),
		"time":  now.Format(time.RFC3339),
	}).Info("Cleaned expired LeaseSets from NetDB")
}

// removeExpiredLeaseSet removes a single expired LeaseSet from cache and filesystem.
func (db *StdNetDB) removeExpiredLeaseSet(hash common.Hash) {
	// Remove from expiry tracking
	db.expiryMutex.Lock()
	delete(db.leaseSetExpiry, hash)
	db.expiryMutex.Unlock()

	// Remove from memory cache
	db.lsMutex.Lock()
	delete(db.LeaseSets, hash)
	db.lsMutex.Unlock()

	// Remove from filesystem
	db.removeLeaseSetFromDisk(hash)

	log.WithField("hash", fmt.Sprintf("%x", hash[:8])).Debug("Removed expired LeaseSet")
}

// removeLeaseSetFromDisk deletes the LeaseSet file from the filesystem.
func (db *StdNetDB) removeLeaseSetFromDisk(hash common.Hash) {
	fpath := db.SkiplistFileForLeaseSet(hash)
	if err := os.Remove(fpath); err != nil {
		if !os.IsNotExist(err) {
			log.WithError(err).WithField("path", fpath).Warn("Failed to remove LeaseSet file")
		}
	}
}

// GetLeaseSetExpirationStats returns statistics about LeaseSet expiration tracking.
// Returns total count, expired count, and time until next expiration.
func (db *StdNetDB) GetLeaseSetExpirationStats() (total, expired int, nextExpiry time.Duration) {
	now := time.Now()
	var earliest time.Time

	db.expiryMutex.RLock()
	defer db.expiryMutex.RUnlock()

	total = len(db.leaseSetExpiry)
	for _, expiryTime := range db.leaseSetExpiry {
		if now.After(expiryTime) {
			expired++
		} else if earliest.IsZero() || expiryTime.Before(earliest) {
			earliest = expiryTime
		}
	}

	if !earliest.IsZero() {
		nextExpiry = time.Until(earliest)
	}

	return
}

// GetAllLeaseSets returns all LeaseSets currently stored in the database.
// This includes all types: LeaseSet, LeaseSet2, EncryptedLeaseSet, and MetaLeaseSet.
// The method returns a slice of LeaseSetEntry containing the hash and Entry data.
// This is primarily used for publishing all LeaseSets to floodfill routers.
func (db *StdNetDB) GetAllLeaseSets() []LeaseSetEntry {
	log.Debug("Getting all LeaseSets from database")

	db.lsMutex.Lock()
	defer db.lsMutex.Unlock()

	// Pre-allocate slice with capacity to avoid reallocation
	result := make([]LeaseSetEntry, 0, len(db.LeaseSets))

	// Iterate through all cached LeaseSets
	for hash, entry := range db.LeaseSets {
		result = append(result, LeaseSetEntry{
			Hash:  hash,
			Entry: entry,
		})
	}

	log.WithField("count", len(result)).Debug("Retrieved all LeaseSets")
	return result
}
