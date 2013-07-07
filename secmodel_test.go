package snmpclient

import (
	"crypto"
	"encoding/hex"
	"testing"
)

// ----------------md5 keys-----------------

// pass=mfk1234, engine=01234567890123456789012345678901234567890123456789
const md5_s_keys string = "81f88e44916dd2b22e2593fc8157969f"
const md5_s_local_keys string = "7d3d689307ccf5dc76933bdf86578151"

// pass=mfk12345678, engine=test1234567890
const md5_keys string = "1b9b43d3068c326e2720d891d17f5f33"
const md5_local_keys string = "74ebdba5135ec59610f8130c9036b105"

// ----------------sha keys-----------------
// pass=mfk12345678, engine=test1234567890
const sha1_keys string = "46d6c5db15af91e470e81c771582b895e4d0d2c4"
const sha1_local_keys string = "5c5efda5d88c6b76e0ea9fce63afb327ff2c14cc"

func TestGenerateKeys(t *testing.T) {
	bytes, _ := generate_keys(crypto.MD5, "mfk1234")
	if hex.EncodeToString(bytes) != md5_s_keys {
		t.Log(hex.EncodeToString(bytes))
		t.Error("generate s md5 keys failed.")
	} else {
		bytes, _ = generate_localization_keys(crypto.MD5, bytes, []byte("01234567890123456789012345678901"))
		if hex.EncodeToString(bytes) != md5_s_local_keys {
			t.Error("generate s md5 local keys failed.")
		}
	}

	bytes, _ = generate_keys(crypto.MD5, "mfk12345678")
	if hex.EncodeToString(bytes) != md5_keys {
		t.Log(hex.EncodeToString(bytes))
		t.Error("generate md5 keys failed.")
	} else {
		bytes, _ = generate_localization_keys(crypto.MD5, bytes, []byte("test1234567890"))
		if hex.EncodeToString(bytes) != md5_local_keys {
			t.Error("generate md5 local keys failed.")
		}
	}

	bytes, _ = generate_keys(crypto.SHA1, "mfk12345678")
	if hex.EncodeToString(bytes) != sha1_keys {
		t.Log(hex.EncodeToString(bytes))
		t.Error("generate sha1 keys failed.")
	} else {
		bytes, _ = generate_localization_keys(crypto.SHA1, bytes, []byte("test1234567890"))
		if hex.EncodeToString(bytes) != sha1_local_keys {
			t.Error("generate sha1 local keys failed.")
		}
	}
}

// ---------------- md5 digest -----------------
// pass=1234567890123456789012345678901234567890, data=test1234567890
const md5_digest string = "f8fb15bfa133d3ae6a3ca12d"

// ---------------- sha1 digest -----------------
// pass=1234567890123456789012345678901234567890, data=test1234567890
const sha1_digest string = "3b3d1d3da34a707d0b945e3a"

func TestGenerateDigest(t *testing.T) {

	keys := []byte("1234567890123456789012345678901234567890")
	data := []byte("test1234567890")

	bytes, _ := generate_digest(crypto.MD5, keys[0:SNMP_AUTH_HMACMD5_KEY_SIZ], data[:])
	if hex.EncodeToString(bytes) != md5_digest {
		t.Log("excepted is", md5_digest)
		t.Log("actual is", hex.EncodeToString(bytes))
		t.Error("generate md5 digest failed.")
	} else {
		t.Log("generate md5 digest ok")
	}

	bytes, _ = generate_digest(crypto.SHA1, keys[0:SNMP_AUTH_HMACSHA_KEY_SIZ], data[:])
	if hex.EncodeToString(bytes) != sha1_digest {
		t.Log("excepted is", sha1_digest)
		t.Log("actual is", hex.EncodeToString(bytes))
		t.Error("generate sha1 digest failed.")
	} else {
		t.Log("generate sha1 digest ok")
	}
}
func TestGenerateDigest2(t *testing.T) {

	keys := []byte("1234567890123456789012345678901234567890")
	data := []byte("test1234567890")

	bytes, _ := generate_digest2(crypto.MD5, keys[0:SNMP_AUTH_HMACMD5_KEY_SIZ], data[:])
	if hex.EncodeToString(bytes) != md5_digest {
		t.Log("excepted is", md5_digest)
		t.Log("actual is", hex.EncodeToString(bytes))
		t.Error("generate md5 digest failed.")
	} else {
		t.Log("generate md5 digest ok")
	}

	bytes, _ = generate_digest2(crypto.SHA1, keys[0:SNMP_AUTH_HMACSHA_KEY_SIZ], data[:])
	if hex.EncodeToString(bytes) != sha1_digest {
		t.Log("excepted is", sha1_digest)
		t.Log("actual is", hex.EncodeToString(bytes))
		t.Error("generate sha1 digest failed.")
	} else {
		t.Log("generate sha1 digest ok")
	}
}

// ---------------- des encrypt -----------------
// pass=123456789012345678901234567890123456789000, data=test1234567890, msg_digest=01234567, engine_boots=3, engine_time=3
const des_encrypt_txt string = "bf4a4b77db191195"

// ---------------- aes encrypt -----------------
// pass=123456789012345678901234567890123456789000, data=test1234567890, msg_digest=01234567, engine_boots=3, engine_time=3
const aes_encrypt_txt string = "f2da558f7b538861"

func TestEncryto(t *testing.T) {

	keys := []byte("1234567890123456789012345678901234567890")
	data := []byte("test1234567890")
	salt := []byte("01234567")

	bytes := make([]byte, (len(data)/8)*8)
	copy(bytes, data)
	e := sc_des_encrypt(salt[:], keys[0:16], bytes)
	if nil != e {
		t.Error("test des encrpyto failed." + e.Error())
	} else {
		if hex.EncodeToString(bytes) != des_encrypt_txt {
			t.Log(hex.EncodeToString(bytes))
			t.Error("test des encrpyto failed.")
		} else {
			t.Log("test des encrpyto ok")
		}
	}

	bytes2 := make([]byte, (len(data)/8)*8)
	copy(bytes2, data)

	t.Log(hex.EncodeToString(bytes2))
	e = sc_aes_encrypt(3, 3, salt[:], keys[0:16], bytes2)
	if nil != e {
		t.Error("test aes encrpyto failed." + e.Error())
	} else {
		if hex.EncodeToString(bytes2) != aes_encrypt_txt {
			t.Log(bytes)
			t.Log(hex.EncodeToString(bytes2))
			t.Error("test aes encrpyto failed.")
		} else {
			t.Log("test aes encrpyto ok")
		}
	}
}

func TestDecryto(t *testing.T) {

	keys := []byte("1234567890123456789012345678901234567890")
	data := []byte("test1234")
	salt := []byte("01234567")

	bytes, _ := hex.DecodeString(des_encrypt_txt)
	e := sc_des_decrypt(salt[:], keys[0:16], bytes)
	if nil != e {
		t.Error("test des decrpyto failed." + e.Error())
	} else {
		if hex.EncodeToString(bytes) != hex.EncodeToString(data) {
			t.Log(hex.EncodeToString(bytes))
			t.Error("test des decrpyto failed.")
		} else {
			t.Log("test des decrpyto ok")
		}
	}

	bytes, _ = hex.DecodeString(aes_encrypt_txt)
	e = sc_aes_decrypt(3, 3, salt[:], keys[0:16], bytes)
	if nil != e {
		t.Error("test aes decrpyto failed." + e.Error())
	} else {
		if hex.EncodeToString(bytes) != hex.EncodeToString(data) {
			t.Log(hex.EncodeToString(bytes))
			t.Error("test aes decrpyto failed.")
		} else {
			t.Log("test aes decrpyto ok")
		}
	}
}

func TestEncrytoNative(t *testing.T) {

	//func fill_pdu_for_test_crypt(is_encrypt bool, pt C.enum_snmp_privacy, salt, key, data []byte) ([]byte, error)

	keys := []byte("1234567890123456789012345678901234567890")
	data := []byte("test1234567890")
	salt := []byte("01234567")

	bytes := make([]byte, (len(data)/8)*8)
	copy(bytes, data)
	bytes, e := fill_pdu_for_test_crypt(true, 1, salt[:], keys[0:16], bytes)
	if nil != e {
		t.Error("test des encrpyto failed." + e.Error())
	} else {
		if hex.EncodeToString(bytes) != des_encrypt_txt {
			t.Log(hex.EncodeToString(bytes))
			t.Error("test des encrpyto failed.")
		} else {
			t.Log("test des encrpyto ok")
		}
	}

	bytes2 := make([]byte, (len(data)/8)*8)
	copy(bytes2, data)

	t.Log(hex.EncodeToString(bytes2))
	bytes2, e = fill_pdu_for_test_crypt(true, 2, salt[:], keys[0:16], bytes2)
	if nil != e {
		t.Error("test aes encrpyto failed." + e.Error())
	} else {
		if hex.EncodeToString(bytes2) != aes_encrypt_txt {
			t.Log(bytes)
			t.Log(hex.EncodeToString(bytes2))
			t.Error("test aes encrpyto failed.")
		} else {
			t.Log("test aes encrpyto ok")
		}
	}

}

func TestDecrytoNative(t *testing.T) {

	keys := []byte("1234567890123456789012345678901234567890")
	data := []byte("test1234")
	salt := []byte("01234567")

	bytes, _ := hex.DecodeString(des_encrypt_txt)
	bytes, e := fill_pdu_for_test_crypt(false, 1, salt[:], keys[0:16], bytes)
	if nil != e {
		t.Error("test des decrpyto failed." + e.Error())
	} else {
		if hex.EncodeToString(bytes) != hex.EncodeToString(data) {
			t.Log(hex.EncodeToString(bytes))
			t.Error("test des decrpyto failed.")
		} else {
			t.Log("test des decrpyto ok")
		}
	}

	bytes, _ = hex.DecodeString(aes_encrypt_txt)
	bytes, e = fill_pdu_for_test_crypt(false, 2, salt[:], keys[0:16], bytes)
	if nil != e {
		t.Error("test aes decrpyto failed." + e.Error())
	} else {
		if hex.EncodeToString(bytes) != hex.EncodeToString(data) {
			t.Log(hex.EncodeToString(bytes))
			t.Error("test aes decrpyto failed.")
		} else {
			t.Log("test aes decrpyto ok")
		}
	}
}
