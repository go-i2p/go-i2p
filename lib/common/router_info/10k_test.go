package router_info

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func consolidateNetDb(sourcePath string, destPath string) error {
	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %v", err)
	}

	// Walk through all subdirectories
	return filepath.Walk(sourcePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing path %q: %v", path, err)
		}

		// Skip if it's a directory
		if info.IsDir() {
			return nil
		}

		// Check if this is a routerInfo file
		if strings.HasPrefix(info.Name(), "routerInfo-") && strings.HasSuffix(info.Name(), ".dat") {
			// Create source file path
			srcFile := path

			// Create destination file path
			dstFile := filepath.Join(destPath, info.Name())

			// Copy the file
			if err := copyFile(srcFile, dstFile); err != nil {
				return fmt.Errorf("failed to copy %s: %v", info.Name(), err)
			}
		}

		return nil
	})
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func consolidateAllNetDbs(tempDir string) error {
	// Common paths for I2P and I2Pd netDb
	i2pPath := filepath.Join(os.Getenv("HOME"), ".i2p/netDb")
	i2pdPath := filepath.Join(os.Getenv("HOME"), ".i2pd/netDb")

	// Create the temp directory
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}

	// Try to consolidate I2P netDb
	if _, err := os.Stat(i2pPath); err == nil {
		if err := consolidateNetDb(i2pPath, tempDir); err != nil {
			fmt.Printf("Warning: Error processing I2P netDb: %v\n", err)
		}
	}

	// Try to consolidate I2Pd netDb
	if _, err := os.Stat(i2pdPath); err == nil {
		if err := consolidateNetDb(i2pdPath, tempDir); err != nil {
			fmt.Printf("Warning: Error processing I2Pd netDb: %v\n", err)
		}
	}

	return nil
}
func cleanupTempDir(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("failed to cleanup temporary directory %s: %v", path, err)
	}
	return nil
}
func createTempNetDbDir() (string, error) {
	// Get system's temp directory in a platform-independent way
	baseDir := os.TempDir()

	// Create unique directory name with timestamp
	timestamp := time.Now().Unix()
	dirName := fmt.Sprintf("go-i2p-testfiles-%d", timestamp)

	// Join paths in a platform-independent way
	tempDir := filepath.Join(baseDir, dirName)

	// Create the directory with appropriate permissions
	err := os.MkdirAll(tempDir, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary directory: %v", err)
	}

	return tempDir, nil
}
func Test10K(t *testing.T) {
	i2pPath := filepath.Join(os.Getenv("HOME"), ".i2p/netDb")
	i2pdPath := filepath.Join(os.Getenv("HOME"), ".i2pd/netDb")

	// Skip if neither directory exists
	if _, err := os.Stat(i2pPath); os.IsNotExist(err) {
		if _, err := os.Stat(i2pdPath); os.IsNotExist(err) {
			t.Skip("Neither .i2p nor .i2pd netDb directories exist, so we will skip.")
		}
	}

	tempDir, err := createTempNetDbDir()
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	//defer cleanupTempDir(tempDir)

	if err := consolidateAllNetDbs(tempDir); err != nil {
		t.Fatalf("Failed to consolidate netDbs: %v", err)
	}
	time.Sleep(1 * time.Second)
	targetDir, err := createTempNetDbDir()
	if err != nil {
		panic(err)
	}

	// Read and process all router info files
	files, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read temp directory: %v", err)
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), "routerInfo-") {
			// Read the router info file
			data, err := os.ReadFile(filepath.Join(tempDir, file.Name()))
			if err != nil {
				t.Logf("Failed to read file %s: %v", file.Name(), err)
				continue
			}

			// Parse the router info
			//fmt.Printf("data: %s\n", string(data))
			routerInfo, _, err := ReadRouterInfo(data)
			if err != nil {
				t.Logf("Failed to parse router info from %s: %v", file.Name(), err)
				continue
			}

			/*
				log.WithFields(logrus.Fields{
					"peer_size":       routerInfo.peer_size,
					"addresses":       routerInfo.addresses,
					"published":       routerInfo.published,
					"router_identity": routerInfo.router_identity,
					"options":         routerInfo.options,
					"signature":       routerInfo.signature,
					"size":            routerInfo.size,
				}).Debug("routerInfo") // For some reason, this freezes when attempting to print
			*/
			fmt.Printf("peer_size: %v\n", routerInfo.peer_size)
			fmt.Printf("addresses: %v\n", routerInfo.addresses)
			fmt.Printf("published: %v\n", routerInfo.published)
			fmt.Printf("router_identity: %v\n", routerInfo.router_identity)
			fmt.Printf("options: %v\n", routerInfo.options)
			fmt.Printf("signature: %v\n", routerInfo.signature)
			fmt.Printf("size: %v\n", routerInfo.size)
			// Write the router info to the target directory
			routerBytes, err := routerInfo.Bytes()
			if err != nil {
				t.Logf("Failed to serialize router info %s: %v", file.Name(), err)
				continue
			}

			err = os.WriteFile(filepath.Join(targetDir, file.Name()), routerBytes, 0644)
			if err != nil {
				t.Logf("Failed to write router info %s: %v", file.Name(), err)
				continue
			}
		}
	}
}
