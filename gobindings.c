
#include "bsnmp/config.h"
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include "bsnmp/gobindings.h"
#include "bsnmp/asn1.h"
#include "bsnmp/snmp.h"

#include "_cgo_export.h"

size_t get_buffer_length(asn_buf_t* u, const u_char* buf) {
  return u->asn_cptr - buf;
}

char* get_asn_u_ptr(asn_u_t* u) {
  return u->ptr;
}

void set_asn_u_ptr(asn_u_t* u, char* ptr) {
  u->ptr = ptr; 
}

void snmp_value_put_int32(snmp_values_t* value, int32_t i) {
  value->integer = i;
}

int32_t snmp_value_get_int32(snmp_values_t* value) {
  return value->integer;
}

void snmp_value_put_octets(snmp_values_t* value, void *octets, u_int octets_len) {
  value->octetstring.len = octets_len;
  if ( 0 != octets_len ) {
    if (0 != value->octetstring.octets) {
      free(value->octetstring.octets);
      DECREMENTMEMORY();
    }

    INCREMENTMEMORY();
    value->octetstring.octets = (u_char*)malloc(octets_len*sizeof(u_char));
    memcpy(value->octetstring.octets, octets, octets_len*sizeof(u_char));
  }
}

u_int snmp_value_get_octets_len(snmp_values_t* value) {
  return value->octetstring.len;
}

void snmp_value_get_octets(snmp_values_t* value, void* octets) {
  if ( 0 != value->octetstring.len ) {
    memcpy(octets, value->octetstring.octets, value->octetstring.len*sizeof(u_char));
  }
}


asn_oid_t* snmp_value_get_oid(snmp_values_t* value) {
  return &value->oid;
}


void snmp_value_put_ipaddress(snmp_values_t* value, u_char addr0, u_char addr1, 
     u_char addr2, u_char addr3) {
  value->ipaddress[0] = addr0;
  value->ipaddress[1] = addr1;
  value->ipaddress[2] = addr2;
  value->ipaddress[3] = addr3;
}

u_char* snmp_value_get_ipaddress(snmp_values_t* value) {
  return value->ipaddress;
}

void snmp_value_put_uint32(snmp_values_t* value, uint32_t i) {
  value->uint32 = i;
}

uint32_t snmp_value_get_uint32(snmp_values_t* value) {
  return value->uint32;
}

void snmp_value_put_uint64(snmp_values_t* value, uint64_t i) {
  value->counter64 = i;
}

uint64_t snmp_value_get_uint64(snmp_values_t* value) {
  return value->counter64;
}

void snmp_value_put_uint64_str(snmp_values_t* value, char* s) {
  char* endptr;
  value->counter64 = strtoull(s, &endptr, 10);
}

int32_t snmp_value_get_uint64_str(snmp_values_t* value, char* s, int32_t len) {
  return snprintf(s, len, "%" PRIu64, value->counter64);
}