package util

import (
	"log"
	"os"
)

func UserHome() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Unable to get current user's home directory. $HOME environment variable issue? %s", err)
	}

	return homeDir
}
