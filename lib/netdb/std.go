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

	"github.com/go-i2p/go-i2p/lib/bootstrap"
	"github.com/go-i2p/go-i2p/lib/common/base64"
	common "github.com/go-i2p/go-i2p/lib/common/data"
	"github.com/go-i2p/go-i2p/lib/common/router_info"
	"github.com/go-i2p/go-i2p/lib/util"
	log "github.com/sirupsen/logrus"
)

// standard network database implementation using local filesystem skiplist
type StdNetDB string

func (db StdNetDB) GetRouterInfo(hash common.Hash) (chnl chan router_info.RouterInfo) {
	fname := db.SkiplistFile(hash)
	f, err := os.Open(fname)
	if err != nil {
		return nil
	}
	buff := new(bytes.Buffer)
	_, err = io.Copy(buff, f)
	f.Close()
	chnl = make(chan router_info.RouterInfo)
	ri, _, err := router_info.ReadRouterInfo(buff.Bytes())
	if err == nil {
		chnl <- ri
	}
	return
}

// get the skiplist file that a RouterInfo with this hash would go in
func (db StdNetDB) SkiplistFile(hash common.Hash) (fpath string) {
	fname := base64.EncodeToString(hash[:])
	fpath = filepath.Join(db.Path(), fmt.Sprintf("r%c", fname[0]), fmt.Sprintf("routerInfo-%s.dat", fname))
	return
}

// get netdb path
func (db StdNetDB) Path() string {
	return string(db)
}

//
// return how many routers we know about in our network database
//
func (db StdNetDB) Size() (routers int) {
	// TODO: implement this
	var err error
	var data []byte
	if !util.CheckFileExists(db.cacheFilePath()) {
		// regenerate
		err = db.RecalculateSize()
		if err != nil {
			// TODO : what now? let's panic for now
			util.Panicf("could not recalculate netdb size: %s", err)
		}
	}
	data, err = ioutil.ReadFile(db.cacheFilePath())
	if err == nil {
		routers, err = strconv.Atoi(string(data))
	}
	return
}

// name of file to hold precomputed size of netdb
const CacheFileName = "sizecache.txt"

// get filepath for storing netdb info cache
func (db StdNetDB) cacheFilePath() string {
	return filepath.Join(db.Path(), CacheFileName)
}

func (db StdNetDB) CheckFilePathValid(fpath string) bool {
	// TODO: make this better
	return strings.HasSuffix(fpath, ".dat")
}

// recalculateSize recalculates cached size of netdb
func (db StdNetDB) RecalculateSize() (err error) {
	fpath := db.cacheFilePath()
	count := 0
	err = filepath.Walk(fpath, func(fname string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return err
		}
		if db.CheckFilePathValid(fname) {
			// TODO: make sure it's in a skiplist directory
			count++
		}
		return err
	})
	if err == nil {
		str := fmt.Sprintf("%d", count)
		var f *os.File
		f, err = os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			_, err = io.WriteString(f, str)
			f.Close()
		}
	}
	return
}

// return true if the network db directory exists and is writable
func (db StdNetDB) Exists() bool {
	p := db.Path()
	// check root directory
	_, err := os.Stat(p)
	if err == nil {
		// check subdirectories for skiplist
		for _, c := range base64.Alphabet {
			if _, err = os.Stat(filepath.Join(p, fmt.Sprintf("r%c", c))); err != nil {
				return false
			}
		}
	}
	return err == nil
}

func (db StdNetDB) SaveEntry(e *Entry) (err error) {
	var f io.WriteCloser
	var h common.Hash
	h = e.ri.IdentHash()
	//if err == nil {
	f, err = os.OpenFile(db.SkiplistFile(h), os.O_WRONLY|os.O_CREATE, 0700)
	if err == nil {
		err = e.WriteTo(f)
		f.Close()
	}
	//}
	if err != nil {
		log.Errorf("failed to save netdb entry: %s", err.Error())
	}
	return
}

// reseed if we have less than minRouters known routers
// returns error if reseed failed
func (db StdNetDB) Reseed(b bootstrap.Bootstrap, minRouters int) (err error) {
	return
}

// ensure that the network database exists
func (db StdNetDB) Ensure() (err error) {
	if !db.Exists() {
		err = db.Create()
	}
	return
}

// create base network database directory
func (db StdNetDB) Create() (err error) {
	mode := os.FileMode(0700)
	p := db.Path()
	log.Infof("Create network database in %s", p)

	// create root for skiplist
	err = os.Mkdir(p, mode)
	if err == nil {
		// create all subdirectories for skiplist
		for _, c := range base64.Alphabet {
			err = os.Mkdir(filepath.Join(p, fmt.Sprintf("r%c", c)), mode)
			if err != nil {
				return
			}
		}
	}
	return
}
