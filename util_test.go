package snmpclient

import (
	"testing"
)

func TestNormalizeAddress(t *testing.T) {

	addr := NormalizeAddress("12")
	if "12:161" != addr {
		t.Errorf("assert '%s' != '%s'", "12", "12")
	}
	addr = NormalizeAddress("12_12_12_12")
	if "12.12.12.12:161" != addr {
		t.Errorf("assert '%s' != '%s'", "12.12.12.12", "12_12_12_12")
	}
	addr = NormalizeAddress("12_12_12_12:12")
	if "12.12.12.12:12" != addr {
		t.Errorf("assert '%s' != '%s'", "12.12.12.12:12", "12_12_12_12:12")
	}

	addr = NormalizeAddress("12_1a2_12_12")
	if "12_1a2_12_12:161" != addr {
		t.Errorf("assert '%s' != '%s'", "12_1a2_12_12", "12_1a2_12_12")
	}
	addr = NormalizeAddress("12_1a2_12_12:12")
	if "12_1a2_12_12:12" != addr {
		t.Errorf("assert '%s' != '%s'", "12_1a2_12_12:12", "12_1a2_12_12:12")
	}

	addr = NormalizeAddress("12_12_12_12,12")
	if "12.12.12.12:12" != addr {
		t.Errorf("assert '%s' != '%s'", "12.12.12.12:12", "12_12_12_12,12")
	}

	addr = NormalizeAddress("12_1a2_12_12,12")
	if "12_1a2_12_12:12" != addr {
		t.Errorf("assert '%s' != '%s'", "12_1a2_12_12:12", "12_1a2_12_12,12")
	}
}
