package sntp

import (
	"bufio"
	"embed"
	"io"
	"log"
	"strings"
)

//go:embed continents.txt
var continentsFS embed.FS

type Zones struct {
	countryToZone   map[string]string
	continentToZone map[string]string
}

func NewZones() *Zones {
	z := &Zones{
		countryToZone:   make(map[string]string),
		continentToZone: make(map[string]string),
	}
	z.initialize()
	return z
}

func (z *Zones) GetZone(countryCode string) string {
	countryCode = strings.ToLower(countryCode)
	if zone, ok := z.countryToZone[countryCode]; ok {
		return zone
	}
	return ""
}

func (z *Zones) initialize() {
	zones := []string{
		"AF", "africa",
		"AN", "antarctica", // Who is living here?
		"AS", "asia",
		"EU", "europe",
		"NA", "north-america",
		"OC", "oceania",
		"SA", "south-america",
	}

	for i := 0; i < len(zones); i += 2 {
		z.continentToZone[zones[i]] = zones[i+1]
	}

	z.readContinentFile()
}

func (z *Zones) readContinentFile() {
	file, err := continentsFS.Open("continents.txt")
	if err != nil {
		log.Printf("Error opening continents.txt: %v\n", err)
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			log.Printf("Error reading continents.txt: %v\n", err)
			break
		}
		if err == io.EOF && line == "" {
			break
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}

		countryCode := strings.ToLower(strings.TrimSpace(parts[0]))
		continentCode := strings.ToUpper(strings.TrimSpace(parts[1]))

		if zone, ok := z.continentToZone[continentCode]; ok {
			z.countryToZone[countryCode] = zone
		}
	}
}
