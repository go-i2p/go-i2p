package util

import (
	"os"
)

func UserHome() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.WithError(err).Fatal("Unable to get current user's home directory - $HOME environment variable issue")
	}

	return homeDir
}
