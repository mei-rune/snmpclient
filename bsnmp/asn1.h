/*
 * Copyright (c) 2001-2003
 *	Fraunhofer Institute for Open Communication Systems (FhG Fokus).
 *	All rights reserved.
 *
 * Author: Harti Brandt <harti@freebsd.org>
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Begemot: bsnmp/lib/asn1.h,v 1.20 2005/10/05 16:43:11 brandt_h Exp $
 *
 * ASN.1 for SNMP
 */
#ifndef asn1_h_
#define asn1_h_

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include <stdint.h>
#include <sys/types.h>
#include <string.h>

typedef union asn_u_s {
 	u_char	*ptr;
 	const u_char *cptr;
} asn_u_t;

typedef struct asn_buf {
	asn_u_t	asn_u;
	size_t 	asn_len;
} asn_buf_t;
#define asn_cptr	asn_u.cptr
#define asn_ptr 	asn_u.ptr

/* these restrictions are in the SMI */
#define ASN_MAXID	0xffffffff
#define ASN_MAXOIDLEN	128

/* the string needed for this (with trailing zero) */
#define ASN_OIDSTRLEN	(ASN_MAXOIDLEN * (10 + 1) - 1 + 1)

/* type of subidentifiers */
typedef uint32_t asn_subid_t;

typedef struct asn_oid {
	u_int	len;
	asn_subid_t subs[ASN_MAXOIDLEN];
} asn_oid_t;

enum asn_err {
	/* conversion was ok */
	ASN_ERR_OK	= 0,
	/* conversion failed and stopped */
	ASN_ERR_FAILED	= 1 | 0x1000,
	/* length field bad, value skipped */
	ASN_ERR_BADLEN	= 2,
	/* out of buffer, stopped */
	ASN_ERR_EOBUF	= 3 | 0x1000,
	/* length ok, but value is out of range */
	ASN_ERR_RANGE	= 4,
	/* not the expected tag, stopped */
	ASN_ERR_TAG	= 5 | 0x1000,
};
#define ASN_ERR_STOPPED(E) (((E) & 0x1000) != 0)

/* type for the length field of encoded values. The length is restricted
 * to 65535, but using uint16_t would give conversion warnings on gcc */
typedef size_t asn_len_t;	/* could be also uint16_t */

/* maximal length of a long length field without the length of the length */
#define ASN_MAXLEN	65535
#define ASN_MAXLENLEN	2	/* number of bytes in a length */

/* maximum size of an octet string as per SMIv2 */
#define ASN_MAXOCTETSTRING 65535

extern void (*asn_error)(const asn_buf_t *, const char *, ...);

enum asn_err asn_get_header(asn_buf_t *, u_char *, asn_len_t *);
enum asn_err asn_put_header(asn_buf_t *, u_char, asn_len_t);

enum asn_err asn_put_temp_header(asn_buf_t *, u_char, u_char **);
enum asn_err asn_commit_header(asn_buf_t *, u_char *, size_t *);

enum asn_err asn_get_integer_raw(asn_buf_t *, asn_len_t, int32_t *);
enum asn_err asn_get_integer(asn_buf_t *, int32_t *);
enum asn_err asn_put_integer(asn_buf_t *, int32_t);

enum asn_err asn_get_octetstring_raw(asn_buf_t *, asn_len_t, u_char *, asn_len_t *);
enum asn_err asn_get_octetstring(asn_buf_t *, u_char *, asn_len_t *);
enum asn_err asn_put_octetstring(asn_buf_t *, const u_char *, asn_len_t);

enum asn_err asn_get_null_raw(asn_buf_t *b, asn_len_t);
enum asn_err asn_get_null(asn_buf_t *);
enum asn_err asn_put_null(asn_buf_t *);

enum asn_err asn_put_exception(asn_buf_t *, u_int);

enum asn_err asn_get_objid_raw(asn_buf_t *, asn_len_t, asn_oid_t *);
enum asn_err asn_get_objid(asn_buf_t *, asn_oid_t *);
enum asn_err asn_put_objid(asn_buf_t *, const asn_oid_t *);

enum asn_err asn_get_sequence(asn_buf_t *, asn_len_t *);

enum asn_err asn_get_ipaddress_raw(asn_buf_t *, asn_len_t, u_char *);
enum asn_err asn_get_ipaddress(asn_buf_t *, u_char *);
enum asn_err asn_put_ipaddress(asn_buf_t *, const u_char *);

enum asn_err asn_get_uint32_raw(asn_buf_t *, asn_len_t, uint32_t *);
enum asn_err asn_put_uint32(asn_buf_t *, u_char, uint32_t);

enum asn_err asn_get_counter64_raw(asn_buf_t *, asn_len_t, uint64_t *);
enum asn_err asn_put_counter64(asn_buf_t *, uint64_t);

enum asn_err asn_get_timeticks(asn_buf_t *, uint32_t *);
enum asn_err asn_put_timeticks(asn_buf_t *, uint32_t);

enum asn_err asn_skip(asn_buf_t *, asn_len_t);
enum asn_err asn_pad(asn_buf_t *, asn_len_t);

/*
 * Utility functions for OIDs
 */
/* get a sub-OID from the middle of another OID */
void asn_slice_oid(asn_oid_t *, const asn_oid_t *, u_int, u_int);

/* append an OID to another one */
void asn_append_oid(asn_oid_t *, const asn_oid_t *);

/* compare two OIDs */
int asn_compare_oid(const asn_oid_t *, const asn_oid_t *);

/* check whether the first is a suboid of the second one */
int asn_is_suboid(const asn_oid_t *, const asn_oid_t *);

/* format an OID into a user buffer of size ASN_OIDSTRLEN */
char *asn_oid2str_r(const asn_oid_t *, char *);

/* format an OID into a private static buffer */
char *asn_oid2str(const asn_oid_t *);

enum {
	ASN_TYPE_BOOLEAN	= 0x01,
	ASN_TYPE_INTEGER	= 0x02,
	ASN_TYPE_BITSTRING	= 0x03,
	ASN_TYPE_OCTETSTRING	= 0x04,
	ASN_TYPE_NULL		= 0x05,
	ASN_TYPE_OBJID		= 0x06,
	ASN_TYPE_SEQUENCE	= 0x10,

	ASN_TYPE_CONSTRUCTED	= 0x20,
	ASN_CLASS_UNIVERSAL	= 0x00,
	ASN_CLASS_APPLICATION	= 0x40,
	ASN_CLASS_CONTEXT	= 0x80,
	ASN_CLASS_PRIVATE	= 0xc0,
	ASN_TYPE_MASK		= 0x1f,

	ASN_APP_IPADDRESS	= 0x00,
	ASN_APP_COUNTER		= 0x01,
	ASN_APP_GAUGE		= 0x02,
	ASN_APP_TIMETICKS	= 0x03,
	ASN_APP_OPAQUE		= 0x04,	/* not implemented */
	ASN_APP_COUNTER64	= 0x06,

  ASN_APP_FLOAT     = 0x8,
  ASN_APP_DOUBLE    = 0x9,
  ASN_APP_I64       = 0xa,
  ASN_APP_U64       = 0xb,

	ASN_EXCEPT_NOSUCHOBJECT	= 0x00,
	ASN_EXCEPT_NOSUCHINSTANCE = 0x01,
	ASN_EXCEPT_ENDOFMIBVIEW	= 0x02,
};

#endif
