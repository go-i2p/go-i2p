package embedded

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

// CertificatesFS embeds all certificates at compile time.
// This eliminates runtime file dependencies for certificate access.
//
//go:embed all:certificates
var CertificatesFS embed.FS

// GetReseedCertificates returns the embedded reseed certificates as a filesystem.
// The returned fs.FS is rooted at the certificates/reseed directory.
func GetReseedCertificates() (fs.FS, error) {
	return fs.Sub(CertificatesFS, "certificates/reseed")
}

// GetFamilyCertificates returns the embedded family certificates as a filesystem.
// The returned fs.FS is rooted at the certificates/family directory.
func GetFamilyCertificates() (fs.FS, error) {
	return fs.Sub(CertificatesFS, "certificates/family")
}

// GetSSLCertificates returns the embedded SSL certificates as a filesystem.
// The returned fs.FS is rooted at the certificates/ssl directory.
func GetSSLCertificates() (fs.FS, error) {
	return fs.Sub(CertificatesFS, "certificates/ssl")
}

// GetCertificateByPath returns the PEM content for a certificate at the given path.
// The path should be relative to the certificates directory (e.g., "reseed/admin_at_stormycloud.org.crt").
func GetCertificateByPath(certPath string) ([]byte, error) {
	return CertificatesFS.ReadFile("certificates/" + certPath)
}

// GetReseedCertificateByName returns the PEM content for a specific reseed certificate.
// The certFileName should be just the filename (e.g., "admin_at_stormycloud.org.crt").
func GetReseedCertificateByName(certFileName string) ([]byte, error) {
	return CertificatesFS.ReadFile("certificates/reseed/" + certFileName)
}

// ListReseedCertificates returns a list of all embedded reseed certificate filenames.
func ListReseedCertificates() ([]string, error) {
	reseedFS, err := GetReseedCertificates()
	if err != nil {
		return nil, err
	}

	entries, err := fs.ReadDir(reseedFS, ".")
	if err != nil {
		return nil, err
	}

	var certs []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".crt" {
			certs = append(certs, entry.Name())
		}
	}
	return certs, nil
}

// ExtractCertificates extracts embedded certificates to the specified directory.
// This is useful for first-run setup or when external tools need file-based access.
// The directory structure under destDir will mirror the embedded structure.
func ExtractCertificates(destDir string) error {
	return fs.WalkDir(CertificatesFS, "certificates", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Calculate destination path (strip "certificates/" prefix, prepend destDir)
		relPath, err := filepath.Rel("certificates", path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(destDir, relPath)

		if d.IsDir() {
			return os.MkdirAll(destPath, 0755)
		}

		data, err := CertificatesFS.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destPath, data, 0644)
	})
}

// ExtractReseedCertificates extracts only the reseed certificates to the specified directory.
// Unlike ExtractCertificates, this places files directly in destDir without subdirectories.
func ExtractReseedCertificates(destDir string) error {
	reseedFS, err := GetReseedCertificates()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	return fs.WalkDir(reseedFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		data, err := fs.ReadFile(reseedFS, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(destDir, path)
		return os.WriteFile(destPath, data, 0644)
	})
}
