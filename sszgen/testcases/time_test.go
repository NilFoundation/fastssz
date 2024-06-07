package testcases

import (
	"bytes"
	"testing"
	"time"
)

func TestTimeRoot(t *testing.T) {
	tests := []struct {
		name      string
		timestamp int64
		root      []byte
	}{
		{
			name:      "Zero",
			timestamp: 0,
			root:      []byte{0xf, 0x63, 0xcd, 0xc, 0x9f, 0xbe, 0x67, 0x9a, 0x56, 0x24, 0x69, 0x83, 0x1d, 0x8e, 0x81, 0xc, 0x9d, 0x33, 0xcc, 0x24, 0x9, 0x69, 0x5b, 0x8e, 0x6a, 0x89, 0x3e, 0x62, 0x7e, 0xa9, 0x52, 0xd1},
		},
		{
			name:      "Max",
			timestamp: 0x7fffffffffffffff,
			root:      []byte{0x24, 0xb, 0xd2, 0x0, 0xf7, 0x2, 0x9, 0x2e, 0x69, 0x7, 0xfd, 0xae, 0x47, 0xf0, 0xd7, 0xd6, 0x5f, 0x6a, 0x9, 0xf8, 0xf6, 0x67, 0x4f, 0x62, 0xfd, 0x3c, 0x2e, 0xcf, 0x23, 0xe3, 0xc5, 0x1d},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			timeStruct := TimeType{Timestamp: time.Unix(test.timestamp, 0)}
			timeRoot, err := timeStruct.HashTreeRoot()
			if err != nil {
				t.Fatalf("unexpected error: %v\n", err)
			}
			// Expect the root to match the expectation.
			if !bytes.Equal(test.root, timeRoot[:]) {
				t.Fatalf("root mismatch with time type")
			}

			rawStruct := TimeRawType{Timestamp: uint64(test.timestamp)}
			rawRoot, err := rawStruct.HashTreeRoot()
			if err != nil {
				t.Fatalf("unexpected error: %v\n", err)
			}
			// Expect the root to match the expectation.
			if !bytes.Equal(test.root, rawRoot[:]) {
				t.Fatalf("root mismatch with raw type")
			}
		})
	}
}

func TestTimeEncode(t *testing.T) {
	tests := []struct {
		name       string
		timestamp  int64
		marshalled []byte
	}{
		{
			name:       "Zero",
			timestamp:  0,
			marshalled: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:       "Real",
			timestamp:  0x62e8e1b1,
			marshalled: []byte{0xb1, 0xe1, 0xe8, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:       "Max",
			timestamp:  0x7fffffffffffffff,
			marshalled: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			timeStruct := TimeType{Timestamp: time.Unix(test.timestamp, 0)}
			timeMarshalled, err := timeStruct.MarshalSSZ()
			if err != nil {
				t.Fatalf("unexpected error: %v\n", err)
			}
			if !bytes.Equal(test.marshalled, timeMarshalled) {
				t.Fatalf("marshal mismatch with time type (%v != %v)", test.marshalled, timeMarshalled)
			}

			rawStruct := TimeRawType{Timestamp: uint64(test.timestamp)}
			rawMarshalled, err := rawStruct.MarshalSSZ()
			if err != nil {
				t.Fatalf("unexpected error: %v\n", err)
			}
			if !bytes.Equal(test.marshalled, rawMarshalled) {
				t.Fatalf("marshal mismatch with raw type")
			}
		})
	}
}

func TestTimeDecode(t *testing.T) {
	tests := []struct {
		name       string
		marshalled []byte
		timeStruct *TimeType
		rawStruct  *TimeRawType
	}{
		{
			name:       "Zero",
			marshalled: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			timeStruct: &TimeType{
				Timestamp: time.Unix(0, 0),
			},
			rawStruct: &TimeRawType{},
		},
		{
			name:       "Real",
			marshalled: []byte{0xb1, 0xe1, 0xe8, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			timeStruct: &TimeType{
				Timestamp: time.Unix(0x62e8e1b1, 0),
			},
			rawStruct: &TimeRawType{
				Timestamp: 0x62e8e1b1,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			timeStruct := TimeType{}
			if err := timeStruct.UnmarshalSSZ(test.marshalled); err != nil {
				t.Fatalf("unexpected error: %v\n", err)
			}
			if !test.timeStruct.Timestamp.Equal(timeStruct.Timestamp) {
				t.Fatalf("unmarshal mismatch with time type (%v != %v)", test.timeStruct.Timestamp, timeStruct.Timestamp)
			}

			rawStruct := TimeRawType{}
			if err := rawStruct.UnmarshalSSZ(test.marshalled); err != nil {
				t.Fatalf("unexpected error: %v\n", err)
			}
			if test.rawStruct.Timestamp != rawStruct.Timestamp {
				t.Fatalf("unmarshal mismatch with time type")
			}
		})
	}
}
