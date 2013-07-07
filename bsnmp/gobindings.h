
#include "config.h"
#include <sys/types.h>
#include <string.h>
#include "asn1.h"
#include "snmp.h"

size_t get_buffer_length(asn_buf_t* u, const u_char*);

char* get_asn_u_ptr(asn_u_t* u);
void set_asn_u_ptr(asn_u_t* u, char* ptr);


void snmp_value_put_int32(snmp_values_t* value, int32_t i);
int32_t snmp_value_get_int32(snmp_values_t* value);
void snmp_value_put_octets(snmp_values_t* value, void *octets, u_int octets_len);
u_int snmp_value_get_octets_len(snmp_values_t* value);
void snmp_value_get_octets(snmp_values_t* value, void* octets);
asn_oid_t* snmp_value_get_oid(snmp_values_t* value);
void snmp_value_put_ipaddress(snmp_values_t* value, u_char addr0, u_char addr1, 
     u_char addr2, u_char addr3);
u_char* snmp_value_get_ipaddress(snmp_values_t* value);
void snmp_value_put_uint32(snmp_values_t* value, uint32_t i);
uint32_t snmp_value_get_uint32(snmp_values_t* value);
void snmp_value_put_uint64(snmp_values_t* value, uint64_t i) ;
uint64_t snmp_value_get_uint64(snmp_values_t* value);


void snmp_value_put_uint64_str(snmp_values_t* value, char* s) ;
int32_t snmp_value_get_uint64_str(snmp_values_t* value, char* s, int32_t len);
