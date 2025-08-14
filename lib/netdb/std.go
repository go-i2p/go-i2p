package netdb

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/go-i2p/logger"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/common/base32"
	"github.com/go-i2p/common/base64"
	common "github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/netdb/reseed"
	"github.com/go-i2p/go-i2p/lib/util"
)

var log = logger.GetGoI2PLogger()

// standard network database implementation using local filesystem skiplist
type StdNetDB struct {
	DB          string
	RouterInfos map[common.Hash]Entry
	riMutex     sync.Mutex // mutex for RouterInfos
	LeaseSets   map[common.Hash]Entry
	lsMutex     sync.Mutex // mutex for LeaseSets
}

func NewStdNetDB(db string) *StdNetDB {
	log.WithField("db_path", db).Debug("Creating new StdNetDB")
	return &StdNetDB{
		DB:          db,
		RouterInfos: make(map[common.Hash]Entry),
		riMutex:     sync.Mutex{},
		LeaseSets:   make(map[common.Hash]Entry),
		lsMutex:     sync.Mutex{},
	}
}

func (db *StdNetDB) GetRouterInfo(hash common.Hash) (chnl chan router_info.RouterInfo) {
	log.WithField("hash", hash).Debug("Getting RouterInfo")
	if ri, ok := db.RouterInfos[hash]; ok {
		log.Debug("RouterInfo found in memory cache")
		chnl <- *ri.RouterInfo
		return
	}
	fname := db.SkiplistFile(hash)
	buff := new(bytes.Buffer)
	if f, err := os.Open(fname); err != nil {
		log.WithError(err).Error("Failed to open RouterInfo file")
		return nil
	} else {
		if _, err := io.Copy(buff, f); err != nil {
			log.WithError(err).Error("Failed to read RouterInfo file")
			return nil
		}
		defer f.Close()
	}
	chnl = make(chan router_info.RouterInfo)
	ri, _, err := router_info.ReadRouterInfo(buff.Bytes())
	if err == nil {
		if _, ok := db.RouterInfos[hash]; !ok {
			log.Debug("Adding RouterInfo to memory cache")
			db.RouterInfos[hash] = Entry{
				RouterInfo: &ri,
			}
		}
		chnl <- ri
	} else {
		log.WithError(err).Error("Failed to parse RouterInfo")
	}
	return
}

func (db *StdNetDB) GetAllRouterInfos() (ri []router_info.RouterInfo) {
	log.Debug("Getting all RouterInfos")
	ri = make([]router_info.RouterInfo, 0, len(db.RouterInfos))
	for _, e := range db.RouterInfos {
		if e.RouterInfo != nil {
			ri = append(ri, *e.RouterInfo)
		}
	}
	return
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

// return how many routers we know about in our network database
func (db *StdNetDB) Size() (routers int) {
	// TODO: implement this
	log.Debug("Calculating NetDB size")
	var err error
	var data []byte
	if !util.CheckFileExists(db.cacheFilePath()) || util.CheckFileAge(db.cacheFilePath(), 2) || len(db.RouterInfos) == 0 {
		// regenerate
		log.Debug("Recalculating NetDB size")
		err = db.RecalculateSize()
		if err != nil {
			// TODO : what now? let's panic for now
			// util.Panicf("could not recalculate netdb size: %s", err)
			log.WithError(err).Panic("Failed to recalculate NetDB size")
		}
	}
	data, err = os.ReadFile(db.cacheFilePath())
	if err == nil {
		routers, err = strconv.Atoi(string(data))
		if err != nil {
			log.WithError(err).Error("Failed to parse NetDB size from cache")
		}
	} else {
		log.WithError(err).Error("Failed to read NetDB size cache file")
	}
	return
}

// name of file to hold precomputed size of netdb
const CacheFileName = "sizecache.txt"

// get filepath for storing netdb info cache
func (db *StdNetDB) cacheFilePath() string {
	return filepath.Join(db.Path(), CacheFileName)
}

func (db *StdNetDB) CheckFilePathValid(fpath string) bool {
	// TODO: make this better
	// return strings.HasSuffix(fpath, ".dat")
	isValid := strings.HasSuffix(fpath, ".dat")
	log.WithFields(logrus.Fields{
		"file_path": fpath,
		"is_valid":  isValid,
	}).Debug("Checking file path validity")
	return isValid
}

// recalculateSize recalculates cached size of netdb
func (db *StdNetDB) RecalculateSize() (err error) {
	log.Debug("Recalculating NetDB size")
	count := 0

	// Walk through all files and count valid RouterInfos
	count, err = db.countValidRouterInfos()
	if err != nil {
		log.WithError(err).Error("Failed to count RouterInfos")
		return err
	}

	// Update the cache file with the count
	err = db.updateSizeCache(count)
	if err != nil {
		log.WithError(err).Error("Failed to update NetDB size cache file")
	}

	return err
}

// countValidRouterInfos walks through the database directory and counts valid RouterInfo files.
func (db *StdNetDB) countValidRouterInfos() (int, error) {
	count := 0
	err := filepath.Walk(db.Path(), func(fname string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return db.handleDirectoryWalk(fname, err)
		}

		if db.CheckFilePathValid(fname) {
			if err := db.processRouterInfoFile(fname, &count); err != nil {
				return err
			}
		} else {
			log.WithField("file_path", fname).Warn("Invalid file path")
			log.Println("Invalid path error")
		}
		return err
	})

	if err == nil {
		log.WithField("count", count).Debug("Finished counting RouterInfos")
	}

	return count, err
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
	db.cacheRouterInfo(ri, fname)
	(*count)++

	return nil
}

// logRouterInfoDetails logs details about the RouterInfo for debugging.
func (db *StdNetDB) logRouterInfoDetails(ri router_info.RouterInfo) {
	ih := ri.IdentHash().Bytes()
	log.Printf("Read in IdentHash: %s", base32.EncodeToString(ih[:]))

	for _, addr := range ri.RouterAddresses() {
		log.Println(string(addr.Bytes()))
		log.WithField("address", string(addr.Bytes())).Debug("RouterInfo address")
	}
}

// cacheRouterInfo adds the RouterInfo to the in-memory cache if not already present.
func (db *StdNetDB) cacheRouterInfo(ri router_info.RouterInfo, fname string) {
	ih := ri.IdentHash()
	if ent, ok := db.RouterInfos[ih]; !ok {
		log.Debug("Adding new RouterInfo to memory cache")
		db.RouterInfos[ri.IdentHash()] = Entry{
			RouterInfo: &ri,
		}
	} else {
		log.Debug("RouterInfo already in memory cache")
		log.Println("entry previously found in table", ent, fname)
	}
}

// updateSizeCache writes the count to the cache file.
func (db *StdNetDB) updateSizeCache(count int) error {
	str := fmt.Sprintf("%d", count)
	f, err := os.OpenFile(db.cacheFilePath(), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.WriteString(f, str)
	if err == nil {
		log.Debug("Updated NetDB size cache file")
	}

	return err
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
	h := e.RouterInfo.IdentHash()
	log.WithField("hash", h).Debug("Saving NetDB entry")
	// if err == nil {
	f, err = os.OpenFile(db.SkiplistFile(h), os.O_WRONLY|os.O_CREATE, 0o700)
	if err == nil {
		err = e.WriteTo(f)
		f.Close()
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
	for _, dbe := range db.RouterInfos {
		if e := db.SaveEntry(&dbe); e != nil {
			err = e
			log.WithError(e).Error("Failed to save NetDB entry")
		}
	}
	return
}

// reseed if we have less than minRouters known routers
// returns error if reseed failed
func (db *StdNetDB) Reseed(b bootstrap.Bootstrap, minRouters int) (err error) {
	log.WithField("min_routers", minRouters).Debug("Checking if reseed is necessary")
	if db.Size() > minRouters {
		log.Debug("Reseed not necessary")
		return nil
	}
	log.Warn("NetDB size below minimum, reseed required")

	ctx, cancel := context.WithTimeout(context.Background(), reseed.DefaultDialTimeout)
	defer cancel()

	// Get peers from the bootstrap provider
	peersChan, err := b.GetPeers(ctx, 0) // Get as many peers as possible
	if err != nil {
		log.WithError(err).Error("Failed to get peers from bootstrap provider")
		return fmt.Errorf("bootstrap failed: %w", err)
	}

	// Process the received peers
	count := 0
	for _, ri := range peersChan {
		hash := ri.IdentHash()
		if _, exists := db.RouterInfos[hash]; !exists {
			log.WithField("hash", hash).Debug("Adding new RouterInfo from reseed")
			db.RouterInfos[hash] = Entry{
				RouterInfo: &ri,
			}
			count++
		}
	}

	log.WithField("added_routers", count).Info("Reseed completed successfully")

	// Update the size cache
	err = db.RecalculateSize()
	if err != nil {
		log.WithError(err).Warn("Failed to update NetDB size cache after reseed")
	}

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
		// create all subdirectories for skiplist
		for _, c := range base64.I2PEncodeAlphabet {
			err = os.MkdirAll(filepath.Join(p, fmt.Sprintf("r%c", c)), mode)
			if err != nil {
				log.WithError(err).Error("Failed to create subdirectory")
				return
			}
		}
	} else {
		log.WithError(err).Error("Failed to create root network database directory")
	}
	return
}
