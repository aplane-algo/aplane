package algo

import (
	"testing"
)

func TestConvertTokenAmountToBaseUnits_Precision(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		decimals  uint64
		expected  uint64
		shouldErr bool
	}{
		{
			name:     "Large Integer (ASA 0 decimals)",
			input:    "1234567890123456789",
			decimals: 0,
			expected: 1234567890123456789,
		},
		{
			name:     "Large ALGO Amount (9B + fraction)",
			input:    "9000000000.123456",
			decimals: 6,
			expected: 9000000000123456,
		},
		{
			name:     "Small Value",
			input:    "0.000001",
			decimals: 6,
			expected: 1,
		},
		{
			name:     "Exact Integer",
			input:    "5",
			decimals: 6,
			expected: 5000000,
		},
		{
			name:     "Leading Zeros",
			input:    "005.5",
			decimals: 6,
			expected: 5500000,
		},
		{
			name:     "No Integer Part",
			input:    ".5",
			decimals: 6,
			expected: 500000,
		},
		{
			name:      "Too Many Decimals",
			input:     "1.123",
			decimals:  2,
			shouldErr: true,
		},
		{
			name:      "Overflow",
			input:     "18446744073709551616", // MaxUint64 + 1
			decimals:  0,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertTokenAmountToBaseUnits(tt.input, tt.decimals)
			if tt.shouldErr {
				if err == nil {
					t.Errorf("ConvertTokenAmountToBaseUnits(%s) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ConvertTokenAmountToBaseUnits(%s) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.expected {
				t.Errorf("ConvertTokenAmountToBaseUnits(%s) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}
