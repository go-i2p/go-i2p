package netdb

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-i2p/go-i2p/lib/util/logger"
	"github.com/sirupsen/logrus"

	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/common/base32"
	"github.com/go-i2p/go-i2p/lib/common/base64"
	common "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/util"
)

var log = logger.GetLogger()

// standard network database implementation using local filesystem skiplist
type StdNetDB struct {
	DB          string
	RouterInfos map[common.Hash]Entry
	LeaseSets   map[common.Hash]Entry
}

func NewStdNetDB(db string) StdNetDB {
	log.WithField("db_path", db).Info("Creating new StdNetDB")
	return StdNetDB{
		DB:          db,
		RouterInfos: make(map[common.Hash]Entry),
		LeaseSets:   make(map[common.Hash]Entry),
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
	data, err = ioutil.ReadFile(db.cacheFilePath())
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
	err = filepath.Walk(db.Path(), func(fname string, info os.FileInfo, err error) error {
		if info.IsDir() {
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
		if db.CheckFilePathValid(fname) {
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
			ih := ri.IdentHash().Bytes()
			log.WithError(err).Error("Failed to parse RouterInfo")
			log.Printf("Read in IdentHash: %s", base32.EncodeToString(ih[:]))
			for _, addr := range ri.RouterAddresses() {
				log.Println(string(addr.Bytes()))
				log.WithField("address", string(addr.Bytes())).Debug("RouterInfo address")
			}
			if ent, ok := db.RouterInfos[ih]; !ok {
				log.Debug("Adding new RouterInfo to memory cache")
				db.RouterInfos[ri.IdentHash()] = Entry{
					RouterInfo: &ri,
				}
			} else {
				log.Debug("RouterInfo already in memory cache")
				log.Println("entry previously found in table", ent, fname)
			}
			ri = router_info.RouterInfo{}
			count++
		} else {
			log.WithField("file_path", fname).Warn("Invalid file path")
			log.Println("Invalid path error")
		}
		return err
	})
	if err == nil {
		log.WithField("count", count).Info("Finished recalculating NetDB size")
		str := fmt.Sprintf("%d", count)
		var f *os.File
		f, err = os.OpenFile(db.cacheFilePath(), os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			_, err = io.WriteString(f, str)
			f.Close()
			log.Debug("Updated NetDB size cache file")
		} else {
			log.WithError(err).Error("Failed to update NetDB size cache file")
		}
	} else {
		log.WithError(err).Error("Failed to update NetDB size cache file")
	}
	return
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
	return
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
	// log.Infof("Create network database in %s", p)
	log.WithField("path", p).Debug("Creating network database directory")
	// create root for skiplist
	err = os.Mkdir(p, mode)
	if err == nil {
		// create all subdirectories for skiplist
		for _, c := range base64.I2PEncodeAlphabet {
			err = os.Mkdir(filepath.Join(p, fmt.Sprintf("r%c", c)), mode)
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
