package sntp

import (
	"bufio"
	"embed"
	"io"
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

// readContinentFile loads country-to-continent mappings from the embedded continents.txt file.
// It parses each line in the format "country_code,continent_code" and populates the countryToZone map.
func (z *Zones) readContinentFile() {
	file, err := z.openContinentFile()
	if err != nil {
		log.WithError(err).Warn("Failed to open continents.txt for zone mapping")
		return
	}
	defer file.Close()

	z.parseContinentMappings(file)
}

// openContinentFile opens and returns the embedded continents.txt file.
func (z *Zones) openContinentFile() (io.ReadCloser, error) {
	return continentsFS.Open("continents.txt")
}

// parseContinentMappings reads and processes lines from the continent file reader.
// Each valid line maps a country code to its continent zone.
func (z *Zones) parseContinentMappings(file io.Reader) {
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			log.WithError(err).Warn("Failed to read line from continents.txt")
			break
		}
		if err == io.EOF && line == "" {
			break
		}

		z.processLine(line)
	}
}

// processLine parses a single line from the continent file and updates the country-to-zone mapping.
// Lines starting with '#' or empty lines are skipped. Valid lines must contain at least two comma-separated values.
func (z *Zones) processLine(line string) {
	line = strings.TrimSpace(line)
	if len(line) == 0 || strings.HasPrefix(line, "#") {
		return
	}

	parts := strings.Split(line, ",")
	if len(parts) < 2 {
		return
	}

	z.mapCountryToZone(parts[0], parts[1])
}

// mapCountryToZone associates a country code with its corresponding continent zone.
// Both the country code and continent code are normalized before mapping.
func (z *Zones) mapCountryToZone(countryCode, continentCode string) {
	countryCode = strings.ToLower(strings.TrimSpace(countryCode))
	continentCode = strings.ToUpper(strings.TrimSpace(continentCode))

	if zone, ok := z.continentToZone[continentCode]; ok {
		z.countryToZone[countryCode] = zone
	}
}
