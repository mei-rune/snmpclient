package snmpclient

// #include "bsnmp/config.h"
// #include "bsnmp/asn1.h"
// #include "bsnmp/snmp.h"
// #include "priv.h"
import "C"

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	//"encoding/hex"
	"crypto/hmac"
	"errors"
	"fmt"
	"unsafe"
)

func init() {
	md5.New()
	sha1.New()
}

const (
	SNMP_AUTH_KEY_LOOPCNT int = 1048576
	SNMP_AUTH_BUF_SIZE    int = 72
	SNMP_EXTENDED_KEY_SIZ int = 64
	SNMP_USM_AUTH_SIZE    int = 12

	SNMP_PRIV_KEY_SIZ int = C.SNMP_PRIV_KEY_SIZ

	SNMP_AUTH_HMACMD5_KEY_SIZ int = 16
	SNMP_AUTH_HMACSHA_KEY_SIZ int = 20
)

func sc_des_crypt(isEncrypt bool, msg_salt, key, data []byte) error {

	if 0 == len(data) {
		return fmt.Errorf("len(input_data) != 0, actual len is 0")
	}

	if 0 != (len(data) % 8) {
		return fmt.Errorf("len(input_data)%%8 != 0,  actual len is %d", len(data))
	}

	if 16 != len(key) {
		return fmt.Errorf("len(key) != 16, actual len is %d", len(key))
	}

	if 8 != len(msg_salt) {
		return fmt.Errorf("len(msg_salt) != 8, actual len is %d", len(msg_salt))
	}

	initVec := make([]byte, 8)
	copy(initVec, msg_salt)

	for i := 0; i < 8; i++ {
		initVec[i] ^= key[8+i]
	}

	block, err := des.NewCipher(key[0:8])
	if nil != err {
		return err
	}

	if isEncrypt {
		cipher.NewCBCEncrypter(block, initVec).CryptBlocks(data, data)
	} else {
		cipher.NewCBCDecrypter(block, initVec).CryptBlocks(data, data)
	}
	return nil
}

//export SC_DES_Crypt
func SC_DES_Crypt(is_encrypt int, salt *C.uint8_t, salt_len C.uint32_t,
	key *C.uint8_t, key_len C.uint32_t,
	scoped_ptr *C.uint8_t, scoped_len C.uint32_t,
	err_msg *C.char, err_len int) C.enum_snmp_code {
	msg_salt := readGoBytes(salt, salt_len)
	priv_key := readGoBytes(key, key_len)
	scoped := readGoBytes(scoped_ptr, scoped_len)

	// bytes := make([]byte, len(scoped))
	// copy(bytes, scoped)

	var err error
	if is_encrypt == 0 {
		err = sc_des_crypt(false, msg_salt, priv_key, scoped)
	} else {
		err = sc_des_crypt(true, msg_salt, priv_key, scoped)
	}

	if nil == err {
		memcpy(scoped_ptr, int(scoped_len), scoped)

		// if 0 == is_encrypt {
		//	fmt.Println("priv_key=" + hex.EncodeToString(priv_key))
		//	fmt.Println("data=" + hex.EncodeToString(bytes))
		//	fmt.Println("encryptoed=" + hex.EncodeToString(scoped))
		// }

		return C.SNMP_CODE_OK
	}
	strcpy(err_msg, err_len, err.Error())
	return C.SNMP_CODE_ERR_GOFUNCTION
}

func sc_des_encrypt(msg_salt, key, data []byte) error {
	return sc_des_crypt(true, msg_salt, key, data)
}

func sc_des_decrypt(msg_salt, key, data []byte) error {
	return sc_des_crypt(false, msg_salt, key, data)
}

func sc_aes_crypt(isEncrypt bool, engine_boots, engine_time int, msg_salt, key, data []byte) error {

	if 0 == len(data) {
		return fmt.Errorf("len(input_data) != 0, actual len is 0")
	}

	if 8 != len(msg_salt) {
		return fmt.Errorf("len(msg_salt) != 8, actual len is %d", len(msg_salt))
	}
	initVec := make([]byte, 8+len(msg_salt))

	binary.BigEndian.PutUint32(initVec, uint32(engine_boots))
	binary.BigEndian.PutUint32(initVec[4:], uint32(engine_time))
	copy(initVec[8:], msg_salt)

	block, err := aes.NewCipher(key)
	if nil != err {
		return err
	}
	if isEncrypt {
		cipher.NewCFBEncrypter(block, initVec).
			XORKeyStream(data, data)
	} else {
		cipher.NewCFBDecrypter(block, initVec).
			XORKeyStream(data, data)
	}
	return nil
}

//export SC_AES_Crypt
func SC_AES_Crypt(is_encrypt int, engine_boots, engine_time int,
	salt *C.uint8_t, salt_len C.uint32_t,
	key *C.uint8_t, key_len C.uint32_t,
	scoped_ptr *C.uint8_t, scoped_len C.uint32_t,
	err_msg *C.char, err_len int) C.enum_snmp_code {
	msg_salt := readGoBytes(salt, salt_len)
	priv_key := readGoBytes(key, key_len)
	scoped := readGoBytes(scoped_ptr, scoped_len)

	//bytes := make([]byte, len(scoped))
	//copy(bytes, scoped)

	var err error
	if is_encrypt == 0 {
		err = sc_aes_crypt(false, engine_boots, engine_time, msg_salt, priv_key, scoped)
	} else {
		err = sc_aes_crypt(true, engine_boots, engine_time, msg_salt, priv_key, scoped)
	}

	if nil == err {
		// if 0 == is_encrypt {
		//	fmt.Println("priv_key=" + hex.EncodeToString(priv_key))
		//	fmt.Println("data=" + hex.EncodeToString(bytes))
		//	fmt.Println("encryptoed=" + hex.EncodeToString(scoped))
		// }

		memcpy(scoped_ptr, int(scoped_len), scoped)
		return C.SNMP_CODE_OK
	}
	strcpy(err_msg, err_len, err.Error())
	return C.SNMP_CODE_ERR_GOFUNCTION
}

func sc_aes_encrypt(engine_boots, engine_time int, msg_salt, key, data []byte) error {
	return sc_aes_crypt(true, engine_boots, engine_time, msg_salt, key, data)
}

func sc_aes_decrypt(engine_boots, engine_time int, msg_salt, key, data []byte) error {
	return sc_aes_crypt(false, engine_boots, engine_time, msg_salt, key, data)
}

//export SCGenerateDigest
func SCGenerateDigest(hash_type int, key *C.uint8_t, key_len C.uint32_t,
	scoped_ptr *C.uint8_t, scoped_len C.uint32_t,
	out_ptr *C.uint8_t, out_len C.uint32_t, err_msg *C.char, err_len int) C.enum_snmp_code {

	priv_key := readGoBytes(key, key_len)
	scoped := readGoBytes(scoped_ptr, scoped_len)
	var err error
	var bytes []byte

	switch hash_type {
	case C.SNMP_AUTH_HMAC_MD5:
		bytes, err = generate_digest(crypto.MD5, priv_key, scoped)
	case C.SNMP_AUTH_HMAC_SHA:
		bytes, err = generate_digest(crypto.SHA1, priv_key, scoped)
	default:
		err = fmt.Errorf("unsupport auth type - '%d'", hash_type)
	}

	if nil == err {
		err = memcpy(out_ptr, int(out_len), bytes)
		if nil == err {
			//fmt.Println("digest_key=" + hex.EncodeToString(priv_key))
			//fmt.Println("digest_data=" + hex.EncodeToString(scoped))
			//fmt.Println("digest=" + hex.EncodeToString(bytes))
			//fmt.Println("digest_mem=" + hex.EncodeToString(readGoBytes(out_ptr, out_len)))
			return C.SNMP_CODE_OK
		}
	}
	strcpy(err_msg, err_len, err.Error())
	return C.SNMP_CODE_ERR_GOFUNCTION
}

func generate_digest(hash crypto.Hash, key, src []byte) ([]byte, error) {
	hmacHash := hmac.New(hash.New, key)
	_, e := hmacHash.Write(src)
	if nil != e {
		return nil, e
	}

	return hmacHash.Sum(nil)[0:SNMP_USM_AUTH_SIZE], nil
}

func generate_digest2(hash crypto.Hash, key, src []byte) ([]byte, error) {
	key1 := make([]byte, SNMP_EXTENDED_KEY_SIZ)
	key2 := make([]byte, SNMP_EXTENDED_KEY_SIZ)
	extkey := make([]byte, SNMP_EXTENDED_KEY_SIZ)
	copy(extkey, key)

	for i := 0; i < SNMP_EXTENDED_KEY_SIZ; i++ {
		key1[i] = extkey[i] ^ 0x36
		key2[i] = extkey[i] ^ 0x5c
	}

	calc := hash.New()
	_, err := calc.Write(key1)
	if nil != err {
		return nil, err
	}
	_, err = calc.Write(src)
	if nil != err {
		return nil, err
	}
	internal := calc.Sum(nil)

	calc = hash.New()
	_, err = calc.Write(key2)
	if nil != err {
		return nil, err
	}
	_, err = calc.Write(internal)
	if nil != err {
		return nil, err
	}
	return calc.Sum(nil)[0:SNMP_USM_AUTH_SIZE], nil
}

func generate_keys(hash crypto.Hash, passphrase string) ([]byte, SnmpError) {
	bytes := []byte(passphrase)
	passphrase_len := len(bytes)
	if 0 == passphrase_len {
		return nil, Error(SNMP_CODE_FAILED, "passphrase is empty.")
	}

	var buf [SNMP_EXTENDED_KEY_SIZ]byte

	calc := hash.New()

	for loop := 0; loop < SNMP_AUTH_KEY_LOOPCNT; loop += SNMP_EXTENDED_KEY_SIZ {
		for i := 0; i < SNMP_EXTENDED_KEY_SIZ; i++ {
			buf[i] = bytes[(loop+i)%passphrase_len]
		}
		_, err := calc.Write(buf[:])
		if nil != err {
			return nil, newError(SNMP_CODE_FAILED, err, "encryto data failed")
		}
	}

	return calc.Sum(nil), nil
}

func generate_localization_keys(hash crypto.Hash, b1, b2 []byte) ([]byte, SnmpError) {
	if C.SNMP_ENGINE_ID_SIZ < len(b2) {
		return nil, Error(SNMP_CODE_BADLEN, "'b2' is too long.")
	}
	calc := hash.New()
	_, err := calc.Write(b1)
	if nil != err {
		return nil, newError(SNMP_CODE_FAILED, err, "")
	}
	_, err = calc.Write(b2)
	if nil != err {
		return nil, newError(SNMP_CODE_FAILED, err, "")
	}
	_, err = calc.Write(b1)
	if nil != err {
		return nil, newError(SNMP_CODE_FAILED, err, "")
	}
	return calc.Sum(nil), nil
}

func fill_pdu_for_test_crypt(is_encrypt bool, pt C.enum_snmp_privacy, salt, key, data []byte) ([]byte, error) {
	var digest [100000]byte
	var pdu C.snmp_pdu_t

	C.snmp_pdu_init(&pdu)

	pdu.user.priv_proto = pt

	C.memcpy(unsafe.Pointer(&pdu.user.priv_key[0]), unsafe.Pointer(&key[0]), C.size_t(C.SNMP_PRIV_KEY_SIZ))
	pdu.user.priv_len = C.size_t(16) //C.size_t(C.SNMP_PRIV_KEY_SIZ) //(au == SNMP_PRIV_DES ) ? SNMP_AUTH_HMACMD5_KEY_SIZ : SNMP_AUTH_HMACSHA_KEY_SIZ;

	pdu.engine.engine_boots = 3
	pdu.engine.engine_time = 3
	C.memcpy(unsafe.Pointer(&pdu.msg_salt[0]), unsafe.Pointer(&salt[0]), 8)

	copy(digest[:], data)
	pdu.scoped_ptr = (*C.u_char)(unsafe.Pointer(&digest[0]))
	pdu.scoped_len = C.size_t((len(data) / 8) * 8)
	var ret_code C.enum_snmp_code
	if is_encrypt {
		ret_code = C.snmp_pdu_encrypt(&pdu)
	} else {
		ret_code = C.snmp_pdu_decrypt(&pdu)
	}
	if 0 != ret_code {
		err := errors.New(C.GoString(C.snmp_pdu_get_error(&pdu, ret_code)))
		return nil, err
	}

	return readGoBytes((*C.uint8_t)(pdu.scoped_ptr), C.uint32_t(pdu.scoped_len)), nil
}
