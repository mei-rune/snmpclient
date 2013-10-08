/*
* Copyright (c) 2001-2003
*	Fraunhofer Institute for Open Communication Systems (FhG Fokus).
*	All rights reserved.
*
* Author: Harti Brandt <harti@freebsd.org>
* 
* Copyright (c) 2010 The FreeBSD Foundation
* All rights reserved.
*
* Portions of this software were developed by Shteryana Sotirova Shopova
* under sponsorship from the FreeBSD Foundation.
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
* $Begemot: bsnmp/lib/snmp.c,v 1.40 2005/10/04 14:32:42 brandt_h Exp $
*
* SNMP
*/
#include "bsnmp/config.h"
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <assert.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#endif
#include <string.h>
#include <ctype.h>
#ifndef _WIN32
#include <netdb.h>
#endif
#include <errno.h>

#include "bsnmp/asn1.h"
#include "bsnmp/snmp.h"
#include "support.h"
#include "priv.h"

#include "_cgo_export.h"

static void snmp_error_func(const char *, ...);
static void snmp_printf_func(const char *, ...);

void (*snmp_error)(const char *, ...) = snmp_error_func;
void (*snmp_printf)(const char *, ...) = snmp_printf_func;



static __inline void dump_hex(const char* s, const u_char* octets, u_int len) {
    u_int i = 0;
    if (500 < len) {
        snmp_printf("%s overflow %lu:", s, len);
        return;
    }
    
    snmp_printf("%s %lu:", s, len);
    for (i = 0; i < len; i++)
       snmp_printf(" %02x", octets[i]);
    snmp_printf("\n");
}

/*
* An array of error strings corresponding to error definitions from libbsnmp.
*/
static const struct {
    const char *str;
    enum snmp_code code;
} error_strings[] = {
    { "ok", SNMP_CODE_OK },
	{ "failed", SNMP_CODE_FAILED },
	{ "bad version", SNMP_CODE_BADVERS },
	{ "bad len", SNMP_CODE_BADLEN },
	{ "bad encode", SNMP_CODE_BADENC },
	{ "oorange", SNMP_CODE_OORANGE },
	{ "bad security level", SNMP_CODE_BADSECLEVEL },
	{ "not in time window", SNMP_CODE_NOTINTIME },
	{ "bad user", SNMP_CODE_BADUSER },
	{ "bad engine", SNMP_CODE_BADENGINE },
	{ "bad digest", SNMP_CODE_BADDIGEST },
	{ "error decrypt ", SNMP_CODE_EDECRYPT },
	{ "bad number of bindings ", SNMP_CODE_BADBINDINGNUMBER },
	{ "bad result", SNMP_CODE_BADRESULT },
	{ "bad oid", SNMP_CODE_BADOID },

	{ "bad syntax", SNMP_CODE_SYNTAX_MISMATCH },
	
	{ "no such object", SNMP_CODE_SYNTAX_NOSUCHOBJECT },	/* exception */
	{ "no such instance ", SNMP_CODE_SYNTAX_NOSUCHINSTANCE },	/* exception */
	{ "end of mib view ", SNMP_CODE_SYNTAX_ENDOFMIBVIEW },	/* exception */
    { "Too big ", SNMP_CODE_ERR_TOOBIG },
    { "No such Name", SNMP_CODE_ERR_NOSUCHNAME },
    { "Bad Value", SNMP_CODE_ERR_BADVALUE },
    { "Readonly", SNMP_CODE_ERR_READONLY },
    { "General error", SNMP_CODE_ERR_GENERR },
    { "No access", SNMP_CODE_ERR_NO_ACCESS },
    { "Wrong type", SNMP_CODE_ERR_WRONG_TYPE },
    { "Wrong lenght", SNMP_CODE_ERR_WRONG_LENGTH },
    { "Wrong encoding", SNMP_CODE_ERR_WRONG_ENCODING },
    { "Wrong value", SNMP_CODE_ERR_WRONG_VALUE },
    { "No creation", SNMP_CODE_ERR_NO_CREATION },
    { "Inconsistent value", SNMP_CODE_ERR_INCONS_VALUE },
    { "Resource unavailable", SNMP_CODE_ERR_RES_UNAVAIL },
    { "Commit failed", SNMP_CODE_ERR_COMMIT_FAILED },
    { "Undo failed", SNMP_CODE_ERR_UNDO_FAILED },
    { "Authorization error", SNMP_CODE_ERR_AUTH_ERR },
    { "Not writable", SNMP_CODE_ERR_NOT_WRITEABLE },
    { "Inconsistent name", SNMP_CODE_ERR_INCONS_NAME },
    { "go function error", SNMP_CODE_ERR_GOFUNCTION },


    { NULL, 0 }
};

const char* snmp_get_error(enum snmp_code code) {
	if(code != error_strings[code].code) {
            printf("%s\n", "sssssssssssssssssssssssssssssssssssssss - snmp_get_error");
        return NULL;
    }
	return error_strings[code].str;
}
const char* snmp_pdu_get_error(snmp_pdu_t *pdu, enum snmp_code code) {
    if (SNMP_CODE_ERR_GOFUNCTION == code) {
        return pdu->error_message;
    }
    if(code != error_strings[code].code) {
            printf("%s\n", "sssssssssssssssssssssssssssssssssssssss - snmp_pdu_get_error");
        return NULL;
    }
    return error_strings[code].str;
}

/*
* Get the next variable binding from the list.
* ASN errors on the sequence or the OID are always fatal.
*/
static enum asn_err get_var_binding(asn_buf_t *b, snmp_value_t *binding)
{
    u_char type;
    asn_len_t len, trailer;
    enum asn_err err;

    if (asn_get_sequence(b, &len) != ASN_ERR_OK) {
        snmp_error("cannot parse varbind header");
        return (ASN_ERR_FAILED);
    }

    /* temporary truncate the length so that the parser does not
    * eat up bytes behind the sequence in the case the encoding is
    * wrong of inner elements. */
    trailer = b->asn_len - len;
    b->asn_len = len;

    if (asn_get_objid(b, &binding->oid) != ASN_ERR_OK) {
        snmp_error("cannot parse binding objid");
        return (ASN_ERR_FAILED);
    }
    if (asn_get_header(b, &type, &len) != ASN_ERR_OK) {
        snmp_error("cannot parse binding value header");
        return (ASN_ERR_FAILED);
    }

    switch (type) {

    case ASN_TYPE_NULL:
        binding->syntax = SNMP_SYNTAX_NULL;
        err = asn_get_null_raw(b, len);
        break;

    case ASN_TYPE_INTEGER:
        binding->syntax = SNMP_SYNTAX_INTEGER;
        err = asn_get_integer_raw(b, len, &binding->v.integer);
        break;

    case ASN_CLASS_APPLICATION|ASN_APP_OPAQUE:
    case ASN_TYPE_OCTETSTRING:
        binding->syntax = SNMP_SYNTAX_OCTETSTRING;
        INCREMENTMEMORY();
        binding->v.octetstring.octets = malloc(len);
        if (binding->v.octetstring.octets == NULL) {
            snmp_error("%s", strerror(errno));
            return (ASN_ERR_FAILED);
        }
        binding->v.octetstring.len = len;
        err = asn_get_octetstring_raw(b, len,
            binding->v.octetstring.octets,
            &binding->v.octetstring.len);
        if (ASN_ERR_STOPPED(err)) {
            DECREMENTMEMORY();
            free(binding->v.octetstring.octets);
            binding->v.octetstring.octets = NULL;
        }
        break;

    case ASN_TYPE_OBJID:
        binding->syntax = SNMP_SYNTAX_OID;
        err = asn_get_objid_raw(b, len, &binding->v.oid);
        break;

    case ASN_CLASS_APPLICATION|ASN_APP_IPADDRESS:
        binding->syntax = SNMP_SYNTAX_IPADDRESS;
        err = asn_get_ipaddress_raw(b, len, binding->v.ipaddress);
        break;

    case ASN_CLASS_APPLICATION|ASN_APP_TIMETICKS:
        binding->syntax = SNMP_SYNTAX_TIMETICKS;
        err = asn_get_uint32_raw(b, len, &binding->v.uint32);
        break;

    case ASN_CLASS_APPLICATION|ASN_APP_COUNTER:
        binding->syntax = SNMP_SYNTAX_COUNTER;
        err = asn_get_uint32_raw(b, len, &binding->v.uint32);
        break;

    case ASN_CLASS_APPLICATION|ASN_APP_GAUGE:
        binding->syntax = SNMP_SYNTAX_GAUGE;
        err = asn_get_uint32_raw(b, len, &binding->v.uint32);
        break;

    case ASN_CLASS_APPLICATION|ASN_APP_U64:
    case ASN_CLASS_APPLICATION|ASN_APP_COUNTER64:
        binding->syntax = SNMP_SYNTAX_COUNTER64;
        err = asn_get_counter64_raw(b, len, &binding->v.counter64);
        break;

    case ASN_CLASS_CONTEXT | ASN_EXCEPT_NOSUCHOBJECT:
        binding->syntax = SNMP_SYNTAX_NOSUCHOBJECT;
        err = asn_get_null_raw(b, len);
        break;

    case ASN_CLASS_CONTEXT | ASN_EXCEPT_NOSUCHINSTANCE:
        binding->syntax = SNMP_SYNTAX_NOSUCHINSTANCE;
        err = asn_get_null_raw(b, len);
        break;

    case ASN_CLASS_CONTEXT | ASN_EXCEPT_ENDOFMIBVIEW:
        binding->syntax = SNMP_SYNTAX_ENDOFMIBVIEW;
        err = asn_get_null_raw(b, len);
        break;

    default:
        if ((err = asn_skip(b, len)) == ASN_ERR_OK)
            err = ASN_ERR_TAG;
        snmp_error("bad binding value type 0x%x", type);
        break;
    }

    if (ASN_ERR_STOPPED(err)) {
        snmp_error("cannot parse binding value");
        return (err);
    }

    if (b->asn_len != 0)
        snmp_error("ignoring junk at end of binding");

    b->asn_len = trailer;

    return (err);
}

/*
* Parse the different PDUs contents. Any ASN error in the outer components
* are fatal. Only errors in variable values may be tolerated. If all
* components can be parsed it returns either ASN_ERR_OK or the first
* error that was found.
*/
enum asn_err snmp_parse_pdus_hdr(asn_buf_t *b, snmp_pdu_t *pdu, asn_len_t *lenp)
{
    if (pdu->pdu_type == SNMP_PDU_TRAP) {
        if (asn_get_objid(b, &pdu->enterprise) != ASN_ERR_OK) {
            snmp_error("cannot parse trap enterprise");
            return (ASN_ERR_FAILED);
        }
        if (asn_get_ipaddress(b, pdu->agent_addr) != ASN_ERR_OK) {
            snmp_error("cannot parse trap agent address");
            return (ASN_ERR_FAILED);
        }
        if (asn_get_integer(b, &pdu->generic_trap) != ASN_ERR_OK) {
            snmp_error("cannot parse 'generic-trap'");
            return (ASN_ERR_FAILED);
        }
        if (asn_get_integer(b, &pdu->specific_trap) != ASN_ERR_OK) {
            snmp_error("cannot parse 'specific-trap'");
            return (ASN_ERR_FAILED);
        }
        if (asn_get_timeticks(b, &pdu->time_stamp) != ASN_ERR_OK) {
            snmp_error("cannot parse trap 'time-stamp'");
            return (ASN_ERR_FAILED);
        }
    } else {
        if (asn_get_integer(b, &pdu->request_id) != ASN_ERR_OK) {
            snmp_error("cannot parse 'request-id'");
            return (ASN_ERR_FAILED);
        }
        if (asn_get_integer(b, &pdu->error_status) != ASN_ERR_OK) {
            snmp_error("cannot parse 'error_status'");
            return (ASN_ERR_FAILED);
        }
        if (asn_get_integer(b, &pdu->error_index) != ASN_ERR_OK) {
            snmp_error("cannot parse 'error_index'");
            return (ASN_ERR_FAILED);
        }
    }

    if (asn_get_sequence(b, lenp) != ASN_ERR_OK) {
        snmp_error("cannot get varlist header");
        return (ASN_ERR_FAILED);
    }

    return (ASN_ERR_OK);
}

static enum asn_err parse_pdus(asn_buf_t *b, snmp_pdu_t *pdu, int32_t *ip)
{
    asn_len_t len, trailer;
    snmp_value_t *v;
    enum asn_err err, err1;

    err = snmp_parse_pdus_hdr(b, pdu, &len);
    if (ASN_ERR_STOPPED(err))
        return (err);

    trailer = b->asn_len - len;

    v = pdu->bindings;
    err = ASN_ERR_OK;
    while (b->asn_len != 0) {
        if (pdu->nbindings == SNMP_MAX_BINDINGS) {
            snmp_error("too many bindings (> %u) in PDU",
                SNMP_MAX_BINDINGS);
            return (ASN_ERR_FAILED);
        }
        err1 = get_var_binding(b, v);
        if (ASN_ERR_STOPPED(err1))
            return (ASN_ERR_FAILED);
        if (err1 != ASN_ERR_OK && err == ASN_ERR_OK) {
            err = err1;
            *ip = pdu->nbindings + 1;
        }
        pdu->nbindings++;
        v++;
    }

    b->asn_len = trailer;

    return (err);
}


static enum asn_err parse_secparams(asn_buf_t *b, snmp_pdu_t *pdu)
{
    asn_len_t octs_len;
    u_char buf[256]; /* XXX: calc max possible size here */
    asn_buf_t tb;

    memset(buf, 0, 256);
    tb.asn_ptr = buf;
    tb.asn_len = 256;


    if (asn_get_octetstring(b, buf, &tb.asn_len) != ASN_ERR_OK) {
        snmp_error("cannot parse usm header");
        return (ASN_ERR_FAILED);
    }

    if (asn_get_sequence(&tb, &octs_len) != ASN_ERR_OK) {
        snmp_error("cannot decode usm header");
        return (ASN_ERR_FAILED);
    }

    octs_len = SNMP_ENGINE_ID_SIZ;
    if (asn_get_octetstring(&tb, (u_char *)&pdu->engine.engine_id,
        &octs_len) != ASN_ERR_OK) {
            snmp_error("cannot decode msg engine id");
            return (ASN_ERR_FAILED);
    }
    pdu->engine.engine_len = octs_len;

    if (asn_get_integer(&tb, &pdu->engine.engine_boots) != ASN_ERR_OK) {
        snmp_error("cannot decode msg engine boots");
        return (ASN_ERR_FAILED);
    }

    if (asn_get_integer(&tb, &pdu->engine.engine_time) != ASN_ERR_OK) {
        snmp_error("cannot decode msg engine time");
        return (ASN_ERR_FAILED);
    }

    octs_len = SNMP_ADM_STR32_SIZ - 1;
    if (asn_get_octetstring(&tb, (u_char *)&pdu->user.sec_name, &octs_len)
        != ASN_ERR_OK) {
            snmp_error("cannot decode msg user name");
            return (ASN_ERR_FAILED);
    }
    pdu->user.sec_name[octs_len] = '\0';

    octs_len = sizeof(pdu->msg_digest);
    if (asn_get_octetstring(&tb, (u_char *)&pdu->msg_digest, &octs_len) !=
        ASN_ERR_OK || ((pdu->flags & SNMP_MSG_AUTH_FLAG) != 0 &&
        octs_len != sizeof(pdu->msg_digest))) {
            snmp_error("cannot decode msg authentication param");
            return (ASN_ERR_FAILED);
    }

    octs_len = sizeof(pdu->msg_salt);
    if (asn_get_octetstring(&tb, (u_char *)&pdu->msg_salt, &octs_len) !=
        ASN_ERR_OK ||((pdu->flags & SNMP_MSG_PRIV_FLAG) != 0 &&
        octs_len != sizeof(pdu->msg_salt))) {
            snmp_error("cannot decode msg authentication param");
            return (ASN_ERR_FAILED);
    }

    if ((pdu->flags & SNMP_MSG_AUTH_FLAG) != 0) {
        pdu->digest_ptr = b->asn_ptr - SNMP_USM_AUTH_SIZE;
        pdu->digest_ptr -= octs_len + ASN_MAXLENLEN;
    }

    return (ASN_ERR_OK);
}

static enum snmp_code pdu_encode_secparams(asn_buf_t *b, snmp_pdu_t *pdu)
{
    u_char buf[256], *sptr;
    asn_buf_t tb;
    size_t auth_off, moved = 0;

    auth_off = 0;
    memset(buf, 0, 256);
    tb.asn_ptr = buf;
    tb.asn_len = 256;

    if (asn_put_temp_header(&tb, (ASN_TYPE_SEQUENCE|ASN_TYPE_CONSTRUCTED),
        &sptr) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    if (asn_put_octetstring(&tb, (u_char *)pdu->engine.engine_id,
        pdu->engine.engine_len) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    if (asn_put_integer(&tb, pdu->engine.engine_boots) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    if (asn_put_integer(&tb, pdu->engine.engine_time) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    if (asn_put_octetstring(&tb, (u_char *)pdu->user.sec_name,
        strlen(pdu->user.sec_name)) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    if ((pdu->flags & SNMP_MSG_AUTH_FLAG) != 0) {
        auth_off = sizeof(buf) - tb.asn_len + ASN_MAXLENLEN;
        if (asn_put_octetstring(&tb, (u_char *)pdu->msg_digest,
            sizeof(pdu->msg_digest)) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);
    } else {
        if (asn_put_octetstring(&tb, (u_char *)pdu->msg_digest, 0)
            != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);
    }

    if ((pdu->flags & SNMP_MSG_PRIV_FLAG) != 0) {
        if (asn_put_octetstring(&tb, (u_char *)pdu->msg_salt,
            sizeof(pdu->msg_salt)) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);
    } else {
        if (asn_put_octetstring(&tb, (u_char *)pdu->msg_salt, 0)
            != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);
    }

    if (asn_commit_header(&tb, sptr, &moved) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    if ((pdu->flags & SNMP_MSG_AUTH_FLAG) != 0)
        pdu->digest_ptr = b->asn_ptr + auth_off - moved;

    if (asn_put_octetstring(b, buf, sizeof(buf) - tb.asn_len) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);
    pdu->digest_ptr += ASN_MAXLENLEN;

    if ((pdu->flags & SNMP_MSG_PRIV_FLAG) != 0 && asn_put_temp_header(b,
        ASN_TYPE_OCTETSTRING, &pdu->encrypted_ptr) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    return (SNMP_CODE_OK);
}

/*
* Decode the PDU except for the variable bindings itself.
* If decoding fails because of a bad binding, but the rest can be
* decoded, ip points to the index of the failed variable (errors
* OORANGE, BADLEN or BADVERS).
*/
enum snmp_code snmp_pdu_decode(asn_buf_t *b, snmp_pdu_t *pdu, int32_t *ip)
{
    enum snmp_code code;

    if ((code = snmp_pdu_decode_header(b, pdu)) != SNMP_CODE_OK)
        return (code);

    if (pdu->version == SNMP_V3) {
        if (pdu->security_model != SNMP_SECMODEL_USM)
            return (SNMP_CODE_FAILED);
        if ((code = snmp_pdu_decode_secmode(b, pdu)) != SNMP_CODE_OK)
            return (code);
    }
    code = snmp_pdu_decode_scoped(b, pdu, ip);

    switch (code) {
    case SNMP_CODE_FAILED:
        snmp_pdu_free(pdu);
        break;

    case SNMP_CODE_BADENC:
        if (pdu->version == SNMP_Verr)
            return (SNMP_CODE_BADVERS);

    default:
        break;
    }

    return (code);
}

enum snmp_code snmp_pdu_decode_header(asn_buf_t *b, snmp_pdu_t *pdu)
{
    int32_t version;
    asn_len_t octs_len;
    asn_len_t len;

    pdu->outer_ptr = b->asn_ptr;
    pdu->outer_len = b->asn_len;

    if (asn_get_sequence(b, &len) != ASN_ERR_OK) {
        snmp_error("cannot decode pdu header");
        return (SNMP_CODE_FAILED);
    }
    if (b->asn_len < len) {
        snmp_error("outer sequence value too short");
        return (SNMP_CODE_FAILED);
    }
    if (b->asn_len != len) {
        snmp_error("ignoring trailing junk in message");
        b->asn_len = len;
    }

    if (asn_get_integer(b, &version) != ASN_ERR_OK) {
        snmp_error("cannot decode version");
        return (SNMP_CODE_FAILED);
    }

    if (version == 0)
        pdu->version = SNMP_V1;
    else if (version == 1)
        pdu->version = SNMP_V2c;
    else if (version == 3)
        pdu->version = SNMP_V3;
    else {
        pdu->version = SNMP_Verr;
        snmp_error("unsupported SNMP version");
        return (SNMP_CODE_BADENC);
    }

    if (pdu->version == SNMP_V3) {
        if (asn_get_sequence(b, &len) != ASN_ERR_OK) {
            snmp_error("cannot decode pdu global data header");
            return (SNMP_CODE_FAILED);
        }

        if (asn_get_integer(b, &pdu->identifier) != ASN_ERR_OK) {
            snmp_error("cannot decode msg indetifier");
            return (SNMP_CODE_FAILED);
        }

        if (asn_get_integer(b, &pdu->engine.max_msg_size)
            != ASN_ERR_OK) {
                snmp_error("cannot decode msg size");
                return (SNMP_CODE_FAILED);
        }

        octs_len = 1;
        if (asn_get_octetstring(b, (u_char *)&pdu->flags,
            &octs_len) != ASN_ERR_OK) {
                snmp_error("cannot decode msg flags");
                return (SNMP_CODE_FAILED);
        }

        if (asn_get_integer(b, &pdu->security_model) != ASN_ERR_OK) {
            snmp_error("cannot decode msg size");
            return (SNMP_CODE_FAILED);
        }

        if (pdu->security_model != SNMP_SECMODEL_USM) {
            snmp_error("unsupported security model type - %d", pdu->security_model);
            return (SNMP_CODE_FAILED);
        }

        if (parse_secparams(b, pdu) != ASN_ERR_OK) {
            snmp_error("parse security params type");
            return (SNMP_CODE_FAILED);
        }
    } else {
        octs_len = SNMP_COMMUNITY_MAXLEN;
        if (asn_get_octetstring(b, (u_char *)pdu->community,
            &octs_len) != ASN_ERR_OK) {
                snmp_error("cannot decode community");
                return (SNMP_CODE_FAILED);
        }
        pdu->community[octs_len] = '\0';
    }

    return (SNMP_CODE_OK);
}

enum snmp_code snmp_pdu_decode_scoped(asn_buf_t *b, snmp_pdu_t *pdu, int32_t *ip)
{
    u_char type;
    asn_len_t len, trailer;
    enum asn_err err;

    if (pdu->version == SNMP_V3) {
        if (asn_get_sequence(b, &len) != ASN_ERR_OK) {
            snmp_error("cannot decode scoped pdu header");
            return (SNMP_CODE_FAILED);
        }

        len = SNMP_ENGINE_ID_SIZ;
        if (asn_get_octetstring(b, (u_char *)&pdu->context_engine,
            &len) != ASN_ERR_OK) {
                snmp_error("cannot decode msg context engine");
                return (SNMP_CODE_FAILED);
        }
        pdu->context_engine_len = len;

        len = SNMP_CONTEXT_NAME_SIZ;
        if (asn_get_octetstring(b, (u_char *)&pdu->context_name,
            &len) != ASN_ERR_OK) {
                snmp_error("cannot decode msg context name");
                return (SNMP_CODE_FAILED);
        }
        pdu->context_name[len] = '\0';
    }

    if (asn_get_header(b, &type, &len) != ASN_ERR_OK) {
        snmp_error("cannot get pdu header");
        return (SNMP_CODE_FAILED);
    }
    if ((type & ~ASN_TYPE_MASK) !=
        (ASN_TYPE_CONSTRUCTED | ASN_CLASS_CONTEXT)) {
            snmp_error("bad pdu header tag");
            return (SNMP_CODE_FAILED);
    }
    pdu->pdu_type = type & ASN_TYPE_MASK;

    switch (pdu->pdu_type) {

    case SNMP_PDU_GET:
    case SNMP_PDU_GETNEXT:
    case SNMP_PDU_RESPONSE:
    case SNMP_PDU_SET:
        break;

    case SNMP_PDU_TRAP:
        if (pdu->version != SNMP_V1) {
            snmp_error("bad pdu type %u", pdu->pdu_type);
            return (SNMP_CODE_FAILED);
        }
        break;

    case SNMP_PDU_GETBULK:
    case SNMP_PDU_INFORM:
    case SNMP_PDU_TRAP2:
    case SNMP_PDU_REPORT:
        if (pdu->version == SNMP_V1) {
            snmp_error("bad pdu type %u", pdu->pdu_type);
            return (SNMP_CODE_FAILED);
        }
        break;

    default:
        snmp_error("bad pdu type %u", pdu->pdu_type);
        return (SNMP_CODE_FAILED);
    }

    trailer = b->asn_len - len;
    b->asn_len = len;

    err = parse_pdus(b, pdu, ip);
    if (ASN_ERR_STOPPED(err))
        return (SNMP_CODE_FAILED);

    if (b->asn_len != 0)
        snmp_error("ignoring trailing junk after pdu");

    b->asn_len = trailer;

    return (SNMP_CODE_OK);
}

enum snmp_code snmp_pdu_decode_secmode(asn_buf_t *b, snmp_pdu_t *pdu)
{
    u_char type;
    enum snmp_code code;
    uint8_t	digest[SNMP_USM_AUTH_SIZE];
    if (pdu->user.auth_proto != SNMP_AUTH_NOAUTH &&
        (pdu->flags & SNMP_MSG_AUTH_FLAG) == 0) {
        snmp_error("bad security level for auth.");
        return (SNMP_CODE_BADSECLEVEL);
    }

    if(0 != pdu->digest_ptr)
        memset(pdu->digest_ptr, 0, sizeof(pdu->msg_digest));

    if ((code = snmp_pdu_calc_digest(pdu, digest)) != SNMP_CODE_OK)
        return (code);

    if (pdu->user.auth_proto != SNMP_AUTH_NOAUTH &&
        memcmp(digest, pdu->msg_digest, sizeof(pdu->msg_digest)) != 0) {
        //snmp_pdu_dump(pdu);
        //dump_hex("calc digest=", digest, sizeof(digest));
        //dump_hex("recv digest=", pdu->msg_digest, sizeof(pdu->msg_digest));
        return (SNMP_CODE_BADDIGEST);
    }

    if (pdu->user.priv_proto == SNMP_PRIV_NOPRIV ||
            (pdu->flags & SNMP_MSG_PRIV_FLAG) == 0)
        return (SNMP_CODE_OK);

    if (pdu->user.priv_proto != SNMP_PRIV_NOPRIV && (asn_get_header(b, &type,
        &pdu->scoped_len) != ASN_ERR_OK || type != ASN_TYPE_OCTETSTRING)) {
            snmp_error("cannot decode encrypted pdu");
            return (SNMP_CODE_FAILED);
    }
    pdu->scoped_ptr = b->asn_ptr;

    if (pdu->user.priv_proto != SNMP_PRIV_NOPRIV &&
        (pdu->flags & SNMP_MSG_PRIV_FLAG) == 0) {
        snmp_error("bad security level for priv.");
        return (SNMP_CODE_BADSECLEVEL);
    }

    if ((code = snmp_pdu_decrypt(pdu)) != SNMP_CODE_OK)
        return (code);

    return (code);
}

/*
* Check whether what we have is the complete PDU by snooping at the
* enclosing structure header. This returns:
*   -1		if there are ASN.1 errors
*    0		if we need more data
*  > 0		the length of this PDU
*/
int snmp_pdu_snoop(const asn_buf_t *b0)
{
    u_int length;
    asn_len_t len;
    asn_buf_t b = *b0;

    /* <0x10|0x20> <len> <data...> */

    if (b.asn_len == 0)
        return (0);
    if (b.asn_cptr[0] != (ASN_TYPE_SEQUENCE | ASN_TYPE_CONSTRUCTED)) {
        asn_error(&b, "bad sequence type %u", b.asn_cptr[0]);
        return (-1);
    }
    b.asn_len--;
    b.asn_cptr++;

    if (b.asn_len == 0)
        return (0);

    if (*b.asn_cptr & 0x80) {
        /* long length */
        length = *b.asn_cptr++ & 0x7f;
        b.asn_len--;
        if (length == 0) {
            asn_error(&b, "indefinite length not supported");
            return (-1);
        }
        if (length > ASN_MAXLENLEN) {
            asn_error(&b, "long length too long (%u)", length);
            return (-1);
        }
        if (length > b.asn_len)
            return (0);
        len = 0;
        while (length--) {
            len = (len << 8) | *b.asn_cptr++;
            b.asn_len--;
        }
    } else {
        len = *b.asn_cptr++;
        b.asn_len--;
    }

    if (len > b.asn_len)
        return (0);

    return (len + b.asn_cptr - b0->asn_cptr);
}

/*
* Encode the SNMP PDU without the variable bindings field.
* We do this the rather uneffective way by
* moving things around and assuming that the length field will never
* use more than 2 bytes.
* We need a number of pointers to apply the fixes afterwards.
*/
enum snmp_code snmp_pdu_encode_header(asn_buf_t *b, snmp_pdu_t *pdu)
{
    enum asn_err err;
    u_char *v3_hdr_ptr;

    if (asn_put_temp_header(b, (ASN_TYPE_SEQUENCE|ASN_TYPE_CONSTRUCTED),
        &pdu->outer_ptr) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    if (pdu->version == SNMP_V1)
        err = asn_put_integer(b, 0);
    else if (pdu->version == SNMP_V2c)
        err = asn_put_integer(b, 1);
    else if (pdu->version == SNMP_V3)
        err = asn_put_integer(b, 3);
    else
        return (SNMP_CODE_BADVERS);
    if (err != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    if (pdu->version == SNMP_V3) {
        if (asn_put_temp_header(b, (ASN_TYPE_SEQUENCE |
            ASN_TYPE_CONSTRUCTED), &v3_hdr_ptr) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);

        if (asn_put_integer(b, pdu->identifier) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);

        if (asn_put_integer(b, pdu->engine.max_msg_size) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);

        if (pdu->pdu_type != SNMP_PDU_RESPONSE &&
            pdu->pdu_type != SNMP_PDU_TRAP &&
            pdu->pdu_type != SNMP_PDU_TRAP2 &&
            pdu->pdu_type != SNMP_PDU_REPORT)
            pdu->flags |= SNMP_MSG_REPORT_FLAG;

        if (asn_put_octetstring(b, (u_char *)&pdu->flags, 1)
            != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);

        if (asn_put_integer(b, pdu->security_model) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);

        if (asn_commit_header(b, v3_hdr_ptr, NULL) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);

        if (pdu->security_model != SNMP_SECMODEL_USM)
            return (SNMP_CODE_FAILED);

        if (pdu_encode_secparams(b, pdu) != SNMP_CODE_OK)
            return (SNMP_CODE_FAILED);

        /*  View-based Access Conntrol information */
        if (asn_put_temp_header(b, (ASN_TYPE_SEQUENCE |
            ASN_TYPE_CONSTRUCTED), &pdu->scoped_ptr) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);

        if (asn_put_octetstring(b, (u_char *)pdu->context_engine,
            pdu->context_engine_len) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);

        if (asn_put_octetstring(b, (u_char *)pdu->context_name,
            strlen(pdu->context_name)) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);
    } else {
        if (asn_put_octetstring(b, (u_char *)pdu->community,
            strlen(pdu->community)) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);
    }

    if (asn_put_temp_header(b, (ASN_TYPE_CONSTRUCTED | ASN_CLASS_CONTEXT |
        pdu->pdu_type), &pdu->pdu_ptr) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    if (pdu->pdu_type == SNMP_PDU_TRAP) {
        if (pdu->version != SNMP_V1 ||
            asn_put_objid(b, &pdu->enterprise) != ASN_ERR_OK ||
            asn_put_ipaddress(b, pdu->agent_addr) != ASN_ERR_OK ||
            asn_put_integer(b, pdu->generic_trap) != ASN_ERR_OK ||
            asn_put_integer(b, pdu->specific_trap) != ASN_ERR_OK ||
            asn_put_timeticks(b, pdu->time_stamp) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);
    } else {
        if (pdu->version == SNMP_V1 && (pdu->pdu_type == SNMP_PDU_GETBULK ||
            pdu->pdu_type == SNMP_PDU_INFORM ||
            pdu->pdu_type == SNMP_PDU_TRAP2 ||
            pdu->pdu_type == SNMP_PDU_REPORT))
            return (SNMP_CODE_FAILED);

        if (asn_put_integer(b, pdu->request_id) != ASN_ERR_OK ||
            asn_put_integer(b, pdu->error_status) != ASN_ERR_OK ||
            asn_put_integer(b, pdu->error_index) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);
    }

    if (asn_put_temp_header(b, (ASN_TYPE_SEQUENCE|ASN_TYPE_CONSTRUCTED),
        &pdu->vars_ptr) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    return (SNMP_CODE_OK);
}

static enum asn_err snmp_pdu_fix_padd(asn_buf_t *b, snmp_pdu_t *pdu)
{
    asn_len_t padlen;

    if (pdu->user.priv_proto == SNMP_PRIV_DES && pdu->scoped_len % 8 != 0) {
        padlen = 8 - (pdu->scoped_len % 8);
        if (asn_pad(b, padlen) != ASN_ERR_OK)
            return (ASN_ERR_FAILED);
        pdu->scoped_len += padlen;
    }

    return (ASN_ERR_OK);
}

enum snmp_code snmp_fix_encoding(asn_buf_t *b, snmp_pdu_t *pdu)
{
    size_t moved = 0;
    enum snmp_code code;
    if (asn_commit_header(b, pdu->vars_ptr, NULL) != ASN_ERR_OK ||
        asn_commit_header(b, pdu->pdu_ptr, NULL) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    if (pdu->version == SNMP_V3) {
        if (asn_commit_header(b, pdu->scoped_ptr, NULL) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);

        pdu->scoped_len = b->asn_ptr - pdu->scoped_ptr;
        if ((code = snmp_pdu_fix_padd(b, pdu))!= ASN_ERR_OK)
            return (SNMP_CODE_FAILED);

        if (pdu->security_model != SNMP_SECMODEL_USM)
            return (SNMP_CODE_FAILED);

        if ((code = snmp_pdu_encrypt(pdu)) != SNMP_CODE_OK)
            return code;

        if (pdu->user.priv_proto != SNMP_PRIV_NOPRIV &&
            asn_commit_header(b, pdu->encrypted_ptr, NULL) != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);
    }

    if (asn_commit_header(b, pdu->outer_ptr, &moved) != ASN_ERR_OK)
        return (SNMP_CODE_FAILED);

    pdu->outer_len = b->asn_ptr - pdu->outer_ptr;
    pdu->digest_ptr -= moved;

    if (pdu->version == SNMP_V3) {
        if ((code = snmp_pdu_calc_digest(pdu, pdu->msg_digest)) !=
            SNMP_CODE_OK)
            return code;

        //dump_hex("digest_key=", pdu->user.auth_key, pdu->user.auth_len);
        //dump_hex("digest_data=", pdu->outer_ptr, pdu->outer_len);

        //dump_hex("digest=", pdu->msg_digest,
        //           sizeof(pdu->msg_digest));
        if ((pdu->flags & SNMP_MSG_AUTH_FLAG) != 0)
            memcpy(pdu->digest_ptr, pdu->msg_digest,
            sizeof(pdu->msg_digest));
    }

    return (SNMP_CODE_OK);
}

/*
* Encode a binding. Caller must ensure, that the syntax is ok for that version.
* Be sure not to cobber b, when something fails.
*/
enum asn_err snmp_binding_encode(asn_buf_t *b, const snmp_value_t *binding)
{
    u_char *ptr;
    enum asn_err err;
    asn_buf_t save = *b;

    if ((err = asn_put_temp_header(b, (ASN_TYPE_SEQUENCE |
        ASN_TYPE_CONSTRUCTED), &ptr)) != ASN_ERR_OK) {
            *b = save;
            return (err);
    }

    if ((err = asn_put_objid(b, &binding->oid)) != ASN_ERR_OK) {
        *b = save;
        return (err);
    }

    switch (binding->syntax) {

    case SNMP_SYNTAX_NULL:
        err = asn_put_null(b);
        break;

    case SNMP_SYNTAX_INTEGER:
        err = asn_put_integer(b, binding->v.integer);
        break;

    case SNMP_SYNTAX_OCTETSTRING:
        err = asn_put_octetstring(b, binding->v.octetstring.octets,
            binding->v.octetstring.len);
        break;

    case SNMP_SYNTAX_OID:
        err = asn_put_objid(b, &binding->v.oid);
        break;

    case SNMP_SYNTAX_IPADDRESS:
        err = asn_put_ipaddress(b, binding->v.ipaddress);
        break;

    case SNMP_SYNTAX_TIMETICKS:
        err = asn_put_uint32(b, ASN_APP_TIMETICKS, binding->v.uint32);
        break;

    case SNMP_SYNTAX_COUNTER:
        err = asn_put_uint32(b, ASN_APP_COUNTER, binding->v.uint32);
        break;

    case SNMP_SYNTAX_GAUGE:
        err = asn_put_uint32(b, ASN_APP_GAUGE, binding->v.uint32);
        break;

    case SNMP_SYNTAX_COUNTER64:
        err = asn_put_counter64(b, binding->v.counter64);
        break;

    case SNMP_SYNTAX_NOSUCHOBJECT:
        err = asn_put_exception(b, ASN_EXCEPT_NOSUCHOBJECT);
        break;

    case SNMP_SYNTAX_NOSUCHINSTANCE:
        err = asn_put_exception(b, ASN_EXCEPT_NOSUCHINSTANCE);
        break;

    case SNMP_SYNTAX_ENDOFMIBVIEW:
        err = asn_put_exception(b, ASN_EXCEPT_ENDOFMIBVIEW);
        break;
    }

    if (err != ASN_ERR_OK) {
        *b = save;
        return (err);
    }

    err = asn_commit_header(b, ptr, NULL);
    if (err != ASN_ERR_OK) {
        *b = save;
        return (err);
    }

    return (ASN_ERR_OK);
}

/*
* Encode an PDU.
*/
enum snmp_code snmp_pdu_encode(snmp_pdu_t *pdu, asn_buf_t *resp_b)
{
    u_int idx;
    enum snmp_code err;

    if ((err = snmp_pdu_encode_header(resp_b, pdu)) != SNMP_CODE_OK)
        return (err);
    for (idx = 0; idx < pdu->nbindings; idx++)
        if ((err = snmp_binding_encode(resp_b, &pdu->bindings[idx]))
            != ASN_ERR_OK)
            return (SNMP_CODE_FAILED);

    return (snmp_fix_encoding(resp_b, pdu));
}

static void dump_binding(const snmp_value_t *b)
{
    u_int i;
    char buf[ASN_OIDSTRLEN];

    snmp_printf("%s=", asn_oid2str_r(&b->oid, buf));
    switch (b->syntax) {

    case SNMP_SYNTAX_NULL:
        snmp_printf("NULL");
        break;

    case SNMP_SYNTAX_INTEGER:
        snmp_printf("INTEGER %d", b->v.integer);
        break;

    case SNMP_SYNTAX_OCTETSTRING:
        snmp_printf("OCTET STRING %lu:", b->v.octetstring.len);
        for (i = 0; i < b->v.octetstring.len; i++)
            snmp_printf(" %02x", b->v.octetstring.octets[i]);
        break;

    case SNMP_SYNTAX_OID:
        snmp_printf("OID %s", asn_oid2str_r(&b->v.oid, buf));
        break;

    case SNMP_SYNTAX_IPADDRESS:
        snmp_printf("IPADDRESS %u.%u.%u.%u", b->v.ipaddress[0],
            b->v.ipaddress[1], b->v.ipaddress[2], b->v.ipaddress[3]);
        break;

    case SNMP_SYNTAX_COUNTER:
        snmp_printf("COUNTER %u", b->v.uint32);
        break;

    case SNMP_SYNTAX_GAUGE:
        snmp_printf("GAUGE %u", b->v.uint32);
        break;

    case SNMP_SYNTAX_TIMETICKS:
        snmp_printf("TIMETICKS %u", b->v.uint32);
        break;

    case SNMP_SYNTAX_COUNTER64:
        snmp_printf("COUNTER64 %lld", b->v.counter64);
        break;

    case SNMP_SYNTAX_NOSUCHOBJECT:
        snmp_printf("NoSuchObject");
        break;

    case SNMP_SYNTAX_NOSUCHINSTANCE:
        snmp_printf("NoSuchInstance");
        break;

    case SNMP_SYNTAX_ENDOFMIBVIEW:
        snmp_printf("EndOfMibView");
        break;

    default:
        snmp_printf("UNKNOWN SYNTAX %u", b->syntax);
        break;
    }
}

static __inline void dump_bindings(const snmp_pdu_t *pdu)
{
    u_int i;

    for (i = 0; i < pdu->nbindings; i++) {
        snmp_printf(" [%u]: ", i);
        dump_binding(&pdu->bindings[i]);
        snmp_printf("\n");
    }
}

static __inline void dump_notrap(const snmp_pdu_t *pdu)
{
    snmp_printf(" request_id=%d", pdu->request_id);
    snmp_printf(" error_status=%d", pdu->error_status);
    snmp_printf(" error_index=%d\n", pdu->error_index);
    dump_bindings(pdu);
}

void snmp_pdu_dump(const snmp_pdu_t *pdu)
{
    char buf[ASN_OIDSTRLEN];
    const char *vers;
    static const char *types[9]; 

    types[SNMP_PDU_GET]      =	"GET";
    types[SNMP_PDU_GETNEXT]  =	"GETNEXT";
    types[SNMP_PDU_RESPONSE] =	"RESPONSE";
    types[SNMP_PDU_SET]      =	"SET";
    types[SNMP_PDU_TRAP]     =	"TRAPv1";
    types[SNMP_PDU_GETBULK]  =	"GETBULK";
    types[SNMP_PDU_INFORM]   =	"INFORM";
    types[SNMP_PDU_TRAP2]    =	"TRAPv2";
    types[SNMP_PDU_REPORT]   =	"REPORT";

    if (pdu->version == SNMP_V1)
        vers = "SNMPv1";
    else if (pdu->version == SNMP_V2c)
        vers = "SNMPv2c";
    else if (pdu->version == SNMP_V3)
        vers = "SNMPv3";
    else
        vers = "v?";

    switch (pdu->pdu_type) {
    case SNMP_PDU_TRAP:
        snmp_printf("%s %s '%s'", types[pdu->pdu_type], vers, pdu->community);
        snmp_printf(" enterprise=%s", asn_oid2str_r(&pdu->enterprise, buf));
        snmp_printf(" agent_addr=%u.%u.%u.%u", pdu->agent_addr[0],
            pdu->agent_addr[1], pdu->agent_addr[2], pdu->agent_addr[3]);
        snmp_printf(" generic_trap=%d", pdu->generic_trap);
        snmp_printf(" specific_trap=%d", pdu->specific_trap);
        snmp_printf(" time-stamp=%u\n", pdu->time_stamp);
        dump_bindings(pdu);
        break;

    case SNMP_PDU_GET:
    case SNMP_PDU_GETNEXT:
    case SNMP_PDU_RESPONSE:
    case SNMP_PDU_SET:
    case SNMP_PDU_GETBULK:
    case SNMP_PDU_INFORM:
    case SNMP_PDU_TRAP2:
    case SNMP_PDU_REPORT:
        snmp_printf("%s %s '%s'", types[pdu->pdu_type], vers, pdu->community);
        if (pdu->version == SNMP_V3) {
            snmp_printf(" identifier: %d\n", pdu->identifier);
            snmp_printf(" context_name: %s\n", pdu->context_name);
            dump_hex(" context_engine", pdu->context_engine, pdu->context_engine_len);
            
            dump_hex(" msg_digest", pdu->msg_digest, SNMP_USM_AUTH_SIZE);
            dump_hex(" msg_salt", pdu->msg_salt, SNMP_USM_PRIV_SIZE);

            snmp_printf(" user.secname: %s\n", pdu->user.sec_name);

            snmp_printf(" user.auth_proto: %d\n", pdu->user.auth_proto);
            dump_hex(" user.auth_key", pdu->user.auth_key, pdu->user.auth_len);
            snmp_printf(" user.priv_proto: %d\n", pdu->user.priv_proto);
            dump_hex(" user.priv_key", pdu->user.priv_key, pdu->user.priv_len);

            snmp_printf(" engine boots=%d, time=%d, max_msg_size=%d, ", pdu->engine.engine_boots,
                  pdu->engine.engine_time, pdu->engine.max_msg_size);
            dump_hex("engine.engine_id: ", pdu->engine.engine_id, pdu->engine.engine_len);

        }
        dump_notrap(pdu);
        break;

    default:
        snmp_printf("bad pdu pdu_type %u\n", pdu->pdu_type);
        break;
    }
}

void snmp_pdu_init(snmp_pdu_t *pdu)
{
    memset(pdu, 0, sizeof(*pdu));
}

void snmp_value_free(snmp_value_t *value)
{
    if (value->syntax == SNMP_SYNTAX_OCTETSTRING) {
        DECREMENTMEMORY();
        free(value->v.octetstring.octets);
    }
    value->syntax = SNMP_SYNTAX_NULL;
}

int snmp_value_copy(snmp_value_t *to, const snmp_value_t *from)
{
    to->oid = from->oid;
    to->syntax = from->syntax;

    if (from->syntax == SNMP_SYNTAX_OCTETSTRING) {
        if ((to->v.octetstring.len = from->v.octetstring.len) == 0)
            to->v.octetstring.octets = NULL;
        else {
            INCREMENTMEMORY();
            to->v.octetstring.octets = malloc(to->v.octetstring.len);
            if (to->v.octetstring.octets == NULL)
                return (-1);
            (void)memcpy(to->v.octetstring.octets,
                from->v.octetstring.octets, to->v.octetstring.len);
        }
    } else
        to->v = from->v;
    return (0);
}

void snmp_pdu_init_secparams(snmp_pdu_t *pdu)
{
    int32_t rval;

    if (pdu->user.auth_proto != SNMP_AUTH_NOAUTH)
        pdu->flags |= SNMP_MSG_AUTH_FLAG;

    switch (pdu->user.priv_proto) {
    case SNMP_PRIV_DES:
        memcpy(pdu->msg_salt, &pdu->engine.engine_boots,
            sizeof(pdu->engine.engine_boots));
        rval = random();
        memcpy(pdu->msg_salt + sizeof(pdu->engine.engine_boots), &rval,
            sizeof(int32_t));
        pdu->flags |= SNMP_MSG_PRIV_FLAG;
        break;
    case SNMP_PRIV_AES:
        rval = random();
        memcpy(pdu->msg_salt, &rval, sizeof(int32_t));
        rval = random();
        memcpy(pdu->msg_salt + sizeof(int32_t), &rval, sizeof(int32_t));
        pdu->flags |= SNMP_MSG_PRIV_FLAG;
        break;
    default:
        break;
    }
}

void snmp_pdu_free(snmp_pdu_t *pdu)
{
    u_int i;

    for (i = 0; i < pdu->nbindings; i++)
        snmp_value_free(&pdu->bindings[i]);
}

/*
* Parse an ASCII SNMP value into the binary form
*/
int snmp_value_parse(const char *str, enum snmp_syntax syntax, snmp_values_t *v)
{
    char *end;

    switch (syntax) {

    case SNMP_SYNTAX_NULL:
    case SNMP_SYNTAX_NOSUCHOBJECT:
    case SNMP_SYNTAX_NOSUCHINSTANCE:
    case SNMP_SYNTAX_ENDOFMIBVIEW:
        if (*str != '\0')
            return (-1);
        return (0);

    case SNMP_SYNTAX_INTEGER:
        v->integer = strtoll(str, &end, 0);
        if (*end != '\0')
            return (-1);
        return (0);

    case SNMP_SYNTAX_OCTETSTRING:
        {
            u_long len;	/* actual length of string */
            u_long alloc;	/* allocate length of string */
            u_char *octs;	/* actual octets */
            u_long oct;	/* actual octet */
            u_char *nocts;	/* to avoid memory leak */
            u_char c;	/* actual character */

# define STUFFC(C)     							                \
    if (alloc == len) {					                        \
    alloc += 100;      					                        \
    if(0 == octs){ INCREMENTMEMORY(); }                         \
    if ((nocts = (u_char*)realloc(octs, alloc)) == NULL) {	    \
    DECREMENTMEMORY();                                          \
    free(octs);                                                 \
    return (-1);                                                \
    }                                                           \
    octs = nocts;                                               \
    }                                                           \
    octs[len++] = (C);

            len = alloc = 0;
            octs = NULL;

            if (*str == '"') {
                str++;
                while((c = *str++) != '\0') {
                    if (c == '"') {
                        if (*str != '\0') {
                            DECREMENTMEMORY();
                            free(octs);
                            return (-1);
                        }
                        break;
                    }
                    if (c == '\\') {
                        switch (c = *str++) {

                        case '\\':
                            break;
                        case 'a':
                            c = '\a';
                            break;
                        case 'b':
                            c = '\b';
                            break;
                        case 'f':
                            c = '\f';
                            break;
                        case 'n':
                            c = '\n';
                            break;
                        case 'r':
                            c = '\r';
                            break;
                        case 't':
                            c = '\t';
                            break;
                        case 'v':
                            c = '\v';
                            break;
                        case 'x':
                            c = 0;
                            if (!isxdigit(*str))
                                break;
                            if (isdigit(*str))
                                c = *str++ - '0';
                            else if (isupper(*str))
                                c = *str++ - 'A' + 10;
                            else
                                c = *str++ - 'a' + 10;
                            if (!isxdigit(*str))
                                break;
                            if (isdigit(*str))
                                c += *str++ - '0';
                            else if (isupper(*str))
                                c += *str++ - 'A' + 10;
                            else
                                c += *str++ - 'a' + 10;
                            break;
                        case '0': case '1': case '2':
                        case '3': case '4': case '5':
                        case '6': case '7':
                            c = *str++ - '0';
                            if (*str < '0' || *str > '7')
                                break;
                            c = *str++ - '0';
                            if (*str < '0' || *str > '7')
                                break;
                            c = *str++ - '0';
                            break;
                        default:
                            break;
                        }
                    }
                    STUFFC(c);
                }
            } else {
                while (*str != '\0') {
                    oct = strtoul(str, &end, 16);
                    str = end;
                    if (oct > 0xff) {
                        DECREMENTMEMORY();
                        free(octs);
                        return (-1);
                    }
                    STUFFC(oct);
                    if (*str == ':')
                        str++;
                    else if(*str != '\0') {
                        DECREMENTMEMORY();
                        free(octs);
                        return (-1);
                    }
                }
            }
            v->octetstring.octets = octs;
            v->octetstring.len = len;
            return (0);
# undef STUFFC
        }

    case SNMP_SYNTAX_OID:
        {
            u_long subid;

            v->oid.len = 0;

            for (;;) {
                if (v->oid.len == ASN_MAXOIDLEN)
                    return (-1);
                subid = strtoul(str, &end, 10);
                str = end;
                if (subid > ASN_MAXID)
                    return (-1);
                v->oid.subs[v->oid.len++] = (asn_subid_t)subid;
                if (*str == '\0')
                    break;
                if (*str != '.')
                    return (-1);
                str++;
            }
            return (0);
        }

    case SNMP_SYNTAX_IPADDRESS:
        {
            struct hostent *he;
            u_long ip[4];
            int n;

            if (sscanf(str, "%lu.%lu.%lu.%lu%n", &ip[0], &ip[1], &ip[2],
                &ip[3], &n) == 4 && (size_t)n == strlen(str) &&
                ip[0] <= 0xff && ip[1] <= 0xff &&
                ip[2] <= 0xff && ip[3] <= 0xff) {
                    v->ipaddress[0] = (u_char)ip[0];
                    v->ipaddress[1] = (u_char)ip[1];
                    v->ipaddress[2] = (u_char)ip[2];
                    v->ipaddress[3] = (u_char)ip[3];
                    return (0);
            }

            if ((he = gethostbyname(str)) == NULL)
                return (-1);
            if (he->h_addrtype != AF_INET)
                return (-1);

            v->ipaddress[0] = he->h_addr[0];
            v->ipaddress[1] = he->h_addr[1];
            v->ipaddress[2] = he->h_addr[2];
            v->ipaddress[3] = he->h_addr[3];
            return (0);
        }

    case SNMP_SYNTAX_COUNTER:
    case SNMP_SYNTAX_GAUGE:
    case SNMP_SYNTAX_TIMETICKS:
        {
            uint64_t sub;

            sub = strtoull(str, &end, 0);
            if (*end != '\0' || sub > 0xffffffff)
                return (-1);
            v->uint32 = (uint32_t)sub;
            return (0);
        }

    case SNMP_SYNTAX_COUNTER64:
        v->counter64 = strtoull(str, &end, 0);
        if (*end != '\0')
            return (-1);
        return (0);
    }
    abort();
    return -1;
}

static void snmp_error_func(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "SNMP: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static void snmp_printf_func(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}


static enum snmp_code snmp_check_bad_oid(const asn_oid_t* oid) {
    static asn_subid_t      badOid[] =
    { 1, 3, 6, 1, 6, 3, 15, 1, 1};

//  static asn_subid_t      unknownSecurityLevel[] =
//        { 1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0 };
//  static asn_subid_t      notInTimeWindow[] =
//        { 1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0 };
//  static asn_subid_t      unknownUserName[] =
//        { 1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0 };
//  static asn_subid_t      unknownEngineID[] =
//        { 1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0 };
//  static asn_subid_t      wrongDigest[] =
//      { 1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0 };
//  static asn_subid_t      decryptionError[] =
//        { 1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0 };

    if(11 == oid->len && 0 == memcmp(badOid, oid->subs, sizeof(asn_subid_t) * 9)) {
        switch(oid->subs[9]) {
        case 1:
            return SNMP_CODE_BADSECLEVEL;
        case 2:
            return SNMP_CODE_NOTINTIME;
        case 3:
            return SNMP_CODE_BADUSER;
        case 4:
            return SNMP_CODE_BADENGINE;
        case 5:
            return SNMP_CODE_BADDIGEST;
        case 6:
            return SNMP_CODE_EDECRYPT;
        }
    }

    return SNMP_CODE_OK;
}

static enum snmp_code snmp_parse_bad_oid(const asn_oid_t* oid) {
    enum snmp_code ret = snmp_check_bad_oid(oid);
    if (SNMP_CODE_OK == ret) 
        ret = SNMP_CODE_BADOID;
    return ret;
}


/*
* Check the response to a SET PDU. We check: - the error status must be 0 -
* the number of bindings must be equal in response and request - the
* syntaxes must be the same in response and request - the OIDs must be the
* same in response and request
*/
enum snmp_code snmp_check_bad_oids(const snmp_pdu_t * resp) {
    uint32_t i;
    enum snmp_code ret;
    for (i = 0; i < resp->nbindings; i++) {
        ret = snmp_check_bad_oid(&resp->bindings[i].oid);
        if (ret != SNMP_CODE_OK) {
            return ret;
        }
    }
    return (SNMP_CODE_OK);
}

/*
* Check the response to a SET PDU. We check: - the error status must be 0 -
* the number of bindings must be equal in response and request - the
* syntaxes must be the same in response and request - the OIDs must be the
* same in response and request
*/
static enum snmp_code snmp_check_set_resp(const snmp_pdu_t * req, const snmp_pdu_t * resp)
{
    uint32_t i;
    for (i = 0; i < req->nbindings; i++) {
        if (asn_compare_oid(&req->bindings[i].oid,
            &resp->bindings[i].oid) != 0) {
			return snmp_parse_bad_oid(&resp->bindings[i].oid);
        }
        if (resp->bindings[i].syntax != req->bindings[i].syntax) {
            return (SNMP_CODE_SYNTAX_MISMATCH);
        }
    }
    return (SNMP_CODE_OK);
}

/*
* Check a PDU received in responce to a SNMP_PDU_GET/SNMP_PDU_GETBULK request
* but don't compare syntaxes - when sending a request PDU they must be null.
* This is a (almost) complete copy of snmp_pdu_check() - with matching syntaxes
* checks and some other checks skiped.
*/
static enum snmp_code snmp_check_get_resp(const snmp_pdu_t *resp, const snmp_pdu_t *req)
{
    uint32_t i;

    for (i = 0; i < req->nbindings; i++) {
        if (asn_compare_oid(&req->bindings[i].oid,
            &resp->bindings[i].oid) != 0) {
			return snmp_parse_bad_oid(&resp->bindings[i].oid);
        }

        if (resp->version != SNMP_V1) {
			if (resp->bindings[i].syntax == SNMP_SYNTAX_NOSUCHOBJECT)
				return (SNMP_CODE_SYNTAX_NOSUCHOBJECT);
			if ( resp->bindings[i].syntax == SNMP_SYNTAX_NOSUCHINSTANCE)
				return (SNMP_CODE_SYNTAX_NOSUCHINSTANCE);
		}
    }
	
    return (SNMP_CODE_OK);
}

static enum snmp_code snmp_check_getbulk_resp(const snmp_pdu_t *resp, const snmp_pdu_t *req)
{
    int32_t N, R, M, r;
	\
    for (N = 0; N < req->error_status; N++) {
        if (asn_is_suboid(&req->bindings[N].oid,
            &resp->bindings[N].oid) == 0)
            return (SNMP_CODE_BADRESULT);
        if (resp->bindings[N].syntax == SNMP_SYNTAX_ENDOFMIBVIEW)
            return (SNMP_CODE_SYNTAX_ENDOFMIBVIEW);
    }

    for (R = N , r = N; R  < (int32_t) req->nbindings; R++) {
        for (M = 0; M < req->error_index && (r + M) <
            (int32_t) resp->nbindings; M++) {
                if (asn_is_suboid(&req->bindings[R].oid,
                    &resp->bindings[r + M].oid) == 0)
					return (SNMP_CODE_BADOID);

                if (resp->bindings[r + M].syntax ==
                    SNMP_SYNTAX_ENDOFMIBVIEW) {
                        M++;
                        break;
                }
        }
        r += M;
    }
	
    return (SNMP_CODE_OK);
}


static enum snmp_code snmp_check_getnext_resp(const snmp_pdu_t *resp, const snmp_pdu_t *req)
{
    uint32_t i;

    for (i = 0; i < req->nbindings; i++) {
        if (asn_is_suboid(&req->bindings[i].oid, &resp->bindings[i].oid) == 0)
            return (SNMP_CODE_BADOID);

        if (resp->version != SNMP_V1 && resp->bindings[i].syntax ==
            SNMP_SYNTAX_ENDOFMIBVIEW)
            return (SNMP_CODE_SYNTAX_ENDOFMIBVIEW);
    }
	
    return (SNMP_CODE_OK);
}

/*
* Should be called to check a responce to get/getnext/getbulk.
*/
enum snmp_code snmp_pdu_check(const snmp_pdu_t *resp, const snmp_pdu_t *req)
{
	enum snmp_code ret = SNMP_CODE_OK;

    if (resp == NULL || req == NULL) {
		snmp_error(snmp_get_error(SNMP_CODE_FAILED));
        return (SNMP_CODE_FAILED);
	}

    if (resp->version != req->version) {
		snmp_error(snmp_get_error(SNMP_CODE_BADVERS));
        return (SNMP_CODE_BADVERS);
    }

    if (resp->error_status != SNMP_ERR_NOERROR) {
        snmp_error(snmp_get_error((enum snmp_code)(SNMP_CODE_ERR_NOERROR + resp->error_status)));
        return (enum snmp_code)(SNMP_CODE_ERR_NOERROR + resp->error_status);
    }

    if (resp->nbindings != req->nbindings && req->pdu_type != SNMP_PDU_GETBULK){
		snmp_error(snmp_get_error(SNMP_CODE_BADBINDINGNUMBER));
        return (SNMP_CODE_BADBINDINGNUMBER);
    }

    switch (req->pdu_type) {
    case SNMP_PDU_GET:
        ret = (snmp_check_get_resp(resp,req));
		break;
    case SNMP_PDU_GETBULK:
        ret = (snmp_check_getbulk_resp(resp,req));
		break;
    case SNMP_PDU_GETNEXT:
        ret = (snmp_check_getnext_resp(resp,req));
		break;
    case SNMP_PDU_SET:
        ret = (snmp_check_set_resp(resp,req));
		break;
    default:
        /* NOTREACHED */
        break;
    }
	if(SNMP_CODE_OK != ret) {
		snmp_error(snmp_get_error(ret));
	}

    return (ret);
}