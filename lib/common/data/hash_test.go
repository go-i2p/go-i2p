package data

import (
	"io"
	"strings"
	"testing"
)

func TestHash(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want Hash
	}{
		{
			name: "Empty input",
			data: []byte{},
			want: HashData([]byte{}),
		},
		{
			name: "Nil input",
			data: nil,
			want: HashData([]byte{}),
		},
		// Add more test cases
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashData(tt.data)
			if !got.Equal(tt.want) {
				t.Errorf("HashData() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHashReader(t *testing.T) {
	tests := []struct {
		name    string
		reader  io.Reader
		wantErr bool
	}{
		{
			name:    "Nil reader",
			reader:  nil,
			wantErr: true,
		},
		{
			name:    "Empty reader",
			reader:  strings.NewReader(""),
			wantErr: false,
		},
		// Add more test cases
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HashReader(tt.reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashReader() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}