/*-
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Shteryana Sotirova Shopova under
 * sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */
#include "bsnmp/config.h"
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#endif
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "bsnmp/asn1.h"
#include "bsnmp/snmp.h"
#include "support.h"
#include "priv.h"
#include "_cgo_export.h"

#define	SNMP_PRIV_AES_IV_SIZ 		16
#define	SNMP_EXTENDED_KEY_SIZ		64
#define	SNMP_AUTH_KEY_LOOPCNT		1048576
#define	SNMP_AUTH_BUF_SIZE   		72



enum snmp_code snmp_pdu_calc_digest(const snmp_pdu_t *pdu, uint8_t *digest) {
	if  (pdu->user.auth_proto == SNMP_AUTH_NOAUTH)
		return (SNMP_CODE_OK);
  memset(digest, 0, SNMP_USM_AUTH_SIZE);
  return SCGenerateDigest((GoInt)pdu->user.auth_proto, 
	  (uint8_t *)pdu->user.auth_key, (uint32_t)pdu->user.auth_len, 
	  (uint8_t *)pdu->outer_ptr, (uint32_t)pdu->outer_len,
	  (uint8_t *)digest, (uint32_t)SNMP_USM_AUTH_SIZE,
		(char *)pdu->error_message, (GoInt)1023);
}

// extern enum snmp_code SC_DES_Crypt(int is_encrypt,
//				 uint8_t* salt, GoInt salt_len,
//				 uint8_t* priv_key, GoInt priv_len, 
//				 uint8_t* scoped_ptr, GoInt scoped_len);
// extern enum snmp_code SC_AES_Crypt(int is_encrypt,
//				 GoInt engine_boots, GoInt engine_time,
//				 uint8_t* salt, GoInt salt_len,
//				 uint8_t* priv_key, GoInt priv_len, 
//				 uint8_t* scoped_ptr, GoInt scoped_len);

// func sc_aes_crypt(isEncrypt bool, engine_boots, engine_time int, msg_salt, key, data []byte) error {
enum snmp_code snmp_pdu_crypt(int is_encrypt, const snmp_pdu_t *pdu) {
	switch (pdu->user.priv_proto) {
		case SNMP_PRIV_NOPRIV:
			return SNMP_CODE_OK;
		case SNMP_PRIV_DES:
			return SC_DES_Crypt((GoInt)is_encrypt,
				 (uint8_t*)pdu->msg_salt, (uint32_t)8,
				 (uint8_t*)pdu->user.priv_key, pdu->user.priv_len, 
				 (uint8_t*)pdu->scoped_ptr, (uint32_t)pdu->scoped_len,
				 (char *)pdu->error_message, (GoInt)1023);

		case SNMP_PRIV_AES:
			return SC_AES_Crypt((GoInt)is_encrypt, 
				 (GoInt)pdu->engine.engine_boots, (GoInt)pdu->engine.engine_time,
				 (uint8_t*)pdu->msg_salt, (uint32_t)8,
				 (uint8_t*)pdu->user.priv_key, (uint32_t)16,
				 (uint8_t*)pdu->scoped_ptr, (uint32_t)pdu->scoped_len,
				 (char *)pdu->error_message, (GoInt)1023);
	}
	return (SNMP_CODE_BADSECLEVEL);
}

enum snmp_code snmp_pdu_encrypt(const snmp_pdu_t *pdu) {
	return snmp_pdu_crypt(1, pdu);
}

enum snmp_code snmp_pdu_decrypt(const snmp_pdu_t *pdu) {
	return snmp_pdu_crypt(0, pdu);
}