package snmpclient

import (
	"encoding/hex"
	"flag"
	//"fmt"
	"testing"
)

var dump_pdu = flag.Bool("test.dump_pdu", false, "dump pdu")

// GET SNMPv1 '123987' request_id=234 error_status=0 error_index=0
//  [0]: 1.2.3.4.5.1.7.8.9.10.11.12.13=NULL
//  [1]: 1.2.3.4.5.2.7.8.9.10.11.12.13=INTEGER 12
//  [2]: 1.2.3.4.5.3.7.8.9.10.11.12.13=OCTET STRING 10: 31 32 33 34 35 36 37 38 39 30
//  [3]: 1.2.3.4.5.4.7.8.9.10.11.12.13=OID 2.3.4.5.6.7.8.9.10.11.12.13
//  [4]: 1.2.3.4.5.5.7.8.9.10.11.12.13=IPADDRESS 1.2.3.4
//  [5]: 1.2.3.4.5.6.7.8.9.10.11.12.13=COUNTER 2235683
//  [6]: 1.2.3.4.5.7.7.8.9.10.11.12.13=GAUGE 1235683
//  [7]: 1.2.3.4.5.8.7.8.9.10.11.12.13=TIMETICKS 1235683
//  [8]: 1.2.3.4.5.9.7.8.9.10.11.12.13=COUNTER64 12352121212122683
const snmpv1_txt = "3081e70201000406313233393837a081d9020200ea0201000201003081cc3010060c2a030405010708090a0b0c0d05003011060c2a030405020708090a0b0c0d02010c301a060c2a030405030708090a0b0c0d040a31323334353637383930301b060c2a030405040708090a0b0c0d060b530405060708090a0b0c0d3014060c2a030405050708090a0b0c0d4004010203043013060c2a030405060708090a0b0c0d4103221d233013060c2a030405070708090a0b0c0d420312dae33013060c2a030405080708090a0b0c0d430312dae33017060c2a030405090708090a0b0c0d46072be2305512363b"

// GET SNMPv2c '123987' request_id=234 error_status=0 error_index=0
//  [0]: 1.2.3.4.5.1.7.8.9.10.11.12.13=NULL
//  [1]: 1.2.3.4.5.2.7.8.9.10.11.12.13=INTEGER 12
//  [2]: 1.2.3.4.5.3.7.8.9.10.11.12.13=OCTET STRING 10: 31 32 33 34 35 36 37 38 39 30
//  [3]: 1.2.3.4.5.4.7.8.9.10.11.12.13=OID 2.3.4.5.6.7.8.9.10.11.12.13
//  [4]: 1.2.3.4.5.5.7.8.9.10.11.12.13=IPADDRESS 1.2.3.4
//  [5]: 1.2.3.4.5.6.7.8.9.10.11.12.13=COUNTER 2235683
//  [6]: 1.2.3.4.5.7.7.8.9.10.11.12.13=GAUGE 1235683
//  [7]: 1.2.3.4.5.8.7.8.9.10.11.12.13=TIMETICKS 1235683
//  [8]: 1.2.3.4.5.9.7.8.9.10.11.12.13=COUNTER64 12352121212122683
const snmpv2c_txt = "3081e70201010406313233393837a081d9020200ea0201000201003081cc3010060c2a030405010708090a0b0c0d05003011060c2a030405020708090a0b0c0d02010c301a060c2a030405030708090a0b0c0d040a31323334353637383930301b060c2a030405040708090a0b0c0d060b530405060708090a0b0c0d3014060c2a030405050708090a0b0c0d4004010203043013060c2a030405060708090a0b0c0d4103221d233013060c2a030405070708090a0b0c0d420312dae33013060c2a030405080708090a0b0c0d430312dae33017060c2a030405090708090a0b0c0d46072be2305512363b"

// GET SNMPv3 '' request_id=234 error_status=0 error_index=0
//  [0]: 1.2.3.4.5.1.7.8.9.10.11.12.13=NULL
//  [1]: 1.2.3.4.5.2.7.8.9.10.11.12.13=INTEGER 12
//  [2]: 1.2.3.4.5.3.7.8.9.10.11.12.13=OCTET STRING 10: 31 32 33 34 35 36 37 38 39 30
//  [3]: 1.2.3.4.5.4.7.8.9.10.11.12.13=OID 2.3.4.5.6.7.8.9.10.11.12.13
//  [4]: 1.2.3.4.5.5.7.8.9.10.11.12.13=IPADDRESS 1.2.3.4
//  [5]: 1.2.3.4.5.6.7.8.9.10.11.12.13=COUNTER 2235683
//  [6]: 1.2.3.4.5.7.7.8.9.10.11.12.13=GAUGE 1235683
//  [7]: 1.2.3.4.5.8.7.8.9.10.11.12.13=TIMETICKS 1235683
//  [8]: 1.2.3.4.5.9.7.8.9.10.11.12.13=COUNTER64 12352121212122683
const snmpv3_noauth_txt = "30820150020103300d020100020227170401040201030438303604203031323334353637383930313233343536373839303132333435363738393031020103020204d204076d65696a696e670400040030820100041174657374636f6e74657874656e67696e65040f74657374636f6e746578746e616d65a081d9020200ea0201000201003081cc3010060c2a030405010708090a0b0c0d05003011060c2a030405020708090a0b0c0d02010c301a060c2a030405030708090a0b0c0d040a31323334353637383930301b060c2a030405040708090a0b0c0d060b530405060708090a0b0c0d3014060c2a030405050708090a0b0c0d4004010203043013060c2a030405060708090a0b0c0d4103221d233013060c2a030405070708090a0b0c0d420312dae33013060c2a030405080708090a0b0c0d430312dae33017060c2a030405090708090a0b0c0d46072be2305512363b"

// GET SNMPv3 '' request_id=234 error_status=0 error_index=0
//  [0]: 1.2.3.4.5.1.7.8.9.10.11.12.13=NULL
//  [1]: 1.2.3.4.5.2.7.8.9.10.11.12.13=INTEGER 12
//  [2]: 1.2.3.4.5.3.7.8.9.10.11.12.13=OCTET STRING 10: 31 32 33 34 35 36 37 38 39 30
//  [3]: 1.2.3.4.5.4.7.8.9.10.11.12.13=OID 2.3.4.5.6.7.8.9.10.11.12.13
//  [4]: 1.2.3.4.5.5.7.8.9.10.11.12.13=IPADDRESS 1.2.3.4
//  [5]: 1.2.3.4.5.6.7.8.9.10.11.12.13=COUNTER 2235683
//  [6]: 1.2.3.4.5.7.7.8.9.10.11.12.13=GAUGE 1235683
//  [7]: 1.2.3.4.5.8.7.8.9.10.11.12.13=TIMETICKS 1235683
//  [8]: 1.2.3.4.5.9.7.8.9.10.11.12.13=COUNTER64 12352121212122683
const snmpv3_md5_txt = "3082015c020103300d020100020227170401050201030444304204203031323334353637383930313233343536373839303132333435363738393031020103020204d204076d65696a696e67040c3ecad6303ab094cf9fc49cc8040030820100041174657374636f6e74657874656e67696e65040f74657374636f6e746578746e616d65a081d9020200ea0201000201003081cc3010060c2a030405010708090a0b0c0d05003011060c2a030405020708090a0b0c0d02010c301a060c2a030405030708090a0b0c0d040a31323334353637383930301b060c2a030405040708090a0b0c0d060b530405060708090a0b0c0d3014060c2a030405050708090a0b0c0d4004010203043013060c2a030405060708090a0b0c0d4103221d233013060c2a030405070708090a0b0c0d420312dae33013060c2a030405080708090a0b0c0d430312dae33017060c2a030405090708090a0b0c0d46072be2305512363b"

// GET SNMPv3 '' request_id=234 error_status=0 error_index=0
//  [0]: 1.2.3.4.5.1.7.8.9.10.11.12.13=NULL
//  [1]: 1.2.3.4.5.2.7.8.9.10.11.12.13=INTEGER 12
//  [2]: 1.2.3.4.5.3.7.8.9.10.11.12.13=OCTET STRING 10: 31 32 33 34 35 36 37 38 39 30
//  [3]: 1.2.3.4.5.4.7.8.9.10.11.12.13=OID 2.3.4.5.6.7.8.9.10.11.12.13
//  [4]: 1.2.3.4.5.5.7.8.9.10.11.12.13=IPADDRESS 1.2.3.4
//  [5]: 1.2.3.4.5.6.7.8.9.10.11.12.13=COUNTER 2235683
//  [6]: 1.2.3.4.5.7.7.8.9.10.11.12.13=GAUGE 1235683
//  [7]: 1.2.3.4.5.8.7.8.9.10.11.12.13=TIMETICKS 1235683
//  [8]: 1.2.3.4.5.9.7.8.9.10.11.12.13=COUNTER64 12352121212122683
//const snmpv3_md5_des_txt = "3082016c020103300d02010002022717040107020103044c304a04203031323334353637383930313233343536373839303132333435363738393031020103020204d204076d65696a696e67040cc414cae9ec0af879221fe89904080300000029000000048201085d8e848967040c913b715e3ee20c3a175f430e774fc770d5c012e7dcd6207ae331a937ba936b521f858dd89fcec0e86516d22d6993c5b369d2df77309abe6c1e61af12305272737684b0edac7f3e9029a22fd538aa725192217133731f5e50cec6ccaf14b3a90ad688001f4cc88a10cf14aab9168ef6e8d136192af95655ef6e030325ec04a7bd0067deff5a9b9239c51c7b9adcdd9b4d3c3069cc13efe4e8535d3c2982b63f41f0da79fc920b9bf0e01886b5e7f3da222298ce15834dddf494169b71874489c981154582cfdb5f5df9815c25e788dd4a90edc0a96ca8eeae7aaebe4e9109fedec7faf1a983c5893767383d7e16a0bccef02f14a781c382ec6b24637d1fa1a3f401"
//const snmpv3_md5_des_txt = "3082016c020103300d02010002022717040107020103044c304a04203031323334353637383930313233343536373839303132333435363738393031020103020204d204076d65696a696e67040cc414cae9ec0af879221fe89904080300000029000000048201085d8e848967040c913b715e3ee20c3a175f430e774fc770d5c012e7dcd6207ae331a937ba936b521f858dd89fcec0e86516d22d6993c5b369d2df77309abe6c1e61af12305272737684b0edac7f3e9029a22fd538aa725192217133731f5e50cec6ccaf14b3a90ad688001f4cc88a10cf14aab9168ef6e8d136192af95655ef6e030325ec04a7bd0067deff5a9b9239c51c7b9adcdd9b4d3c3069cc13efe4e8535d3c2982b63f41f0da79fc920b9bf0e01886b5e7f3da222298ce15834dddf494169b71874489c981154582cfdb5f5df9815c25e788dd4a90edc0a96ca8eeae7aaebe4e9109fedec7faf1a983c5893767383d7e16a0bccef02f14a781c382ec6b24637d1fa1a3f401"

// GET SNMPv3 '' identifier: 0
//  context_name: testcontextname
//  context_engine 17: 74 65 73 74 63 6f 6e 74 65 78 74 65 6e 67 69 6e 65
//  msg_digest 12: 00 00 00 00 00 00 00 00 00 00 00 00
//  msg_salt 8: 03 00 00 00 29 00 00 00
//  user.secname: meijing
//  user.auth_proto: 1
//  user.auth_key 16: 7d 3d 68 93 07 cc f5 dc 76 93 3b df 86 57 81 51
//  user.priv_proto: 1
//  user.priv_key 16: e7 1b 79 9c 9c b2 ea b5 9b 71 e6 e1 d2 3b 6b 64
//  engine boots=3, time=1234, max_msg_size=10007, engine.engine_id:  32: 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31
//  request_id=234 error_status=0 error_index=0
//  [0]: 1.2.3.4.5.1.7.8.9.10.11.12.13=NULL
//  [1]: 1.2.3.4.5.2.7.8.9.10.11.12.13=INTEGER 12
//  [2]: 1.2.3.4.5.3.7.8.9.10.11.12.13=OCTET STRING 10: 31 32 33 34 35 36 37 38 39 30
//  [3]: 1.2.3.4.5.4.7.8.9.10.11.12.13=OID 2.3.4.5.6.7.8.9.10.11.12.13
//  [4]: 1.2.3.4.5.5.7.8.9.10.11.12.13=IPADDRESS 1.2.3.4
//  [5]: 1.2.3.4.5.6.7.8.9.10.11.12.13=COUNTER 2235683
//  [6]: 1.2.3.4.5.7.7.8.9.10.11.12.13=GAUGE 1235683
//  [7]: 1.2.3.4.5.8.7.8.9.10.11.12.13=TIMETICKS 1235683
//  [8]: 1.2.3.4.5.9.7.8.9.10.11.12.13=COUNTER64 12352121212122683

// ------------------
// priv_key= 16: e7 1b 79 9c 9c b2 ea b5 9b 71 e6 e1 d2 3b 6b 64
// data= 264: 30 82 01 00 04 11 74 65 73 74 63 6f 6e 74 65 78 74 65 6e 67 69 6e 65 04 0f 74 65 73 74 63 6f 6e 74 65 78 74 6e 61 6d 65 a0 81 d9 02 02 00 ea 02 01 00 02 01 00 30 81 cc 30 10 06 0c 2a 03 04 05 01 07 08 09 0a 0b 0c 0d 05 00 30 11 06 0c 2a 03 04 05 02 07 08 09 0a 0b 0c 0d 02 01 0c 30 1a 06 0c 2a 03 04 05 03 07 08 09 0a 0b 0c 0d 04 0a 31 32 33 34 35 36 37 38 39 30 30 1b 06 0c 2a 03 04 05 04 07 08 09 0a 0b 0c 0d 06 0b 53 04 05 06 07 08 09 0a 0b 0c 0d 30 14 06 0c 2a 03 04 05 05 07 08 09 0a 0b 0c 0d 40 04 01 02 03 04 30 13 06 0c 2a 03 04 05 06 07 08 09 0a 0b 0c 0d 41 03 22 1d 23 30 13 06 0c 2a 03 04 05 07 07 08 09 0a 0b 0c 0d 42 03 12 da e3 30 13 06 0c 2a 03 04 05 08 07 08 09 0a 0b 0c 0d 43 03 12 da e3 30 17 06 0c 2a 03 04 05 09 07 08 09 0a 0b 0c 0d 46 07 2b e2 30 55 12 36 3b 3b 3b 36
// 3b
// encryptoed_data= 264: 5d 8e 84 89 67 04 0c 91 3b 71 5e 3e e2 0c 3a 17 5f 43 0e 77 4f c7 70 d5 c0 12 e7 dc d6 20 7a e3 31 a9 37 ba 93 6b 52 1f 85 8d d8 9f ce c0 e8 65 16 d2 2d 69 93 c5 b3 69 d2 df 77 30 9a be 6c 1e 61 af 12 30 52 72 73 76 84 b0 ed ac 7f 3e 90 29 a2 2f d5 38 aa 72 51 92 21 71 33 73 1f 5e 50 ce c6 cc af 14 b3 a9 0a d6 88 00 1f 4c c8 8a 10 cf 14 aa b9 16 8e f6 e8 d1 36 19 2a f9 56 55 ef 6e 03 03 25 ec 04 a7 bd 00 67 de ff 5a 9b 92 39 c5 1c 7b 9a dc dd 9b 4d 3c 30 69 cc 13 ef e4 e8 53 5d 3c 29 82 b6 3f 41 f0 da 79 fc 92 0b 9b f0 e0 18 86 b5 e7 f3 da 22 22 98 ce 15 83 4d dd f4 94 16 9b 71 87 44 89 c9 81 15 45 82 cf db 5f 5d f9 81 5c 25 e7 88 dd 4a 90 ed c0 a9 6c a8 ee ae 7a ae be 4e 91 09 fe de c7 fa f1 a9 83 c5 89 37 67 38 3d 7e 16 a0 bc ce f0 2f 14 a7 81 c3 82 ec 6b 24 63 7d 1
// f a1 a3 f4 01
// digest_key= 16: 7d 3d 68 93 07 cc f5 dc 76 93 3b df 86 57 81 51
// digest_data= 368: 30 82 01 6c 02 01 03 30 0d 02 01 00 02 02 27 17 04 01 07 02 01 03 04 4c 30 4a 04 20 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31 32 33 34 35 36 37 38 39 30 31 02 01 03 02 02 04 d2 04 07 6d 65 69 6a 69 6e 67 04 0c 00 00 00 00 00 00 00 00 00 00 00 00 04 08 03 00 00 00 29 00 00 00 04 82 01 08 5d 8e 84 89 67 04 0c 91 3b 71 5e 3e e2 0c 3a 17 5f 43 0e 77 4f c7 70 d5 c0 12 e7 dc d6 20 7a e3 31 a9 37 ba 93 6b 52 1f 85 8d d8 9f ce c0 e8 65 16 d2 2d 69 93 c5 b3 69 d2 df 77 30 9a be 6c 1e 61 af 12 30 52 72 73 76 84 b0 ed ac 7f 3e 90 29 a2 2f d5 38 aa 72 51 92 21 71 33 73 1f 5e 50 ce c6 cc af 14 b3 a9 0a d6 88 00 1f 4c c8 8a 10 cf 14 aa b9 16 8e f6 e8 d1 36 19 2a f9 56 55 ef 6e 03 03 25 ec 04 a7 bd 00 67 de ff 5a 9b 92 39 c5 1c 7b 9a dc dd 9b 4d 3c 30 69 cc 13 ef
//  e4 e8 53 5d 3c 29 82 b6 3f 41 f0 da 79 fc 92 0b 9b f0 e0 18 86 b5 e7 f3 da 22 22 98 ce 15 83 4d dd f4 94 16 9b 71 87 44 89 c9 81 15 45 82 cf db 5f 5d f9 81 5c 25 e7 88 dd 4a 90 ed c0 a9 6c a8 ee ae 7a ae be 4e 91 09 fe de c7 fa f1 a9 83 c5 89 37 67 38 3d 7e 16 a0 bc ce f0 2f 14 a7 81 c3 82 ec 6b 24 63 7d 1f a1 a3 f4 01
// digest= 12: c4 14 ca e9 ec 0a f8 79 22 1f e8 99
const snmpv3_md5_des_txt = "3082016c020103300d02010002022717040107020103044c304a04203031323334353637383930313233343536373839303132333435363738393031020103020204d204076d65696a696e67040cc414cae9ec0af879221fe89904080300000029000000048201085d8e848967040c913b715e3ee20c3a175f430e774fc770d5c012e7dcd6207ae331a937ba936b521f858dd89fcec0e86516d22d6993c5b369d2df77309abe6c1e61af12305272737684b0edac7f3e9029a22fd538aa725192217133731f5e50cec6ccaf14b3a90ad688001f4cc88a10cf14aab9168ef6e8d136192af95655ef6e030325ec04a7bd0067deff5a9b9239c51c7b9adcdd9b4d3c3069cc13efe4e8535d3c2982b63f41f0da79fc920b9bf0e01886b5e7f3da222298ce15834dddf494169b71874489c981154582cfdb5f5df9815c25e788dd4a90edc0a96ca8eeae7aaebe4e9109fedec7faf1a983c5893767383d7e16a0bccef02f14a781c382ec6b24637d1fa1a3f401"

// GET SNMPv3 '' request_id=234 error_status=0 error_index=0
//  [0]: 1.2.3.4.5.1.7.8.9.10.11.12.13=NULL
//  [1]: 1.2.3.4.5.2.7.8.9.10.11.12.13=INTEGER 12
//  [2]: 1.2.3.4.5.3.7.8.9.10.11.12.13=OCTET STRING 10: 31 32 33 34 35 36 37 38 39 30
//  [3]: 1.2.3.4.5.4.7.8.9.10.11.12.13=OID 2.3.4.5.6.7.8.9.10.11.12.13
//  [4]: 1.2.3.4.5.5.7.8.9.10.11.12.13=IPADDRESS 1.2.3.4
//  [5]: 1.2.3.4.5.6.7.8.9.10.11.12.13=COUNTER 2235683
//  [6]: 1.2.3.4.5.7.7.8.9.10.11.12.13=GAUGE 1235683
//  [7]: 1.2.3.4.5.8.7.8.9.10.11.12.13=TIMETICKS 1235683
//  [8]: 1.2.3.4.5.9.7.8.9.10.11.12.13=COUNTER64 12352121212122683
const snmpv3_sha_txt = "3082015c020103300d020100020227170401050201030444304204203031323334353637383930313233343536373839303132333435363738393031020103020204d204076d65696a696e67040ce7a696149d5fd4e6fdb17cd9040030820100041174657374636f6e74657874656e67696e65040f74657374636f6e746578746e616d65a081d9020200ea0201000201003081cc3010060c2a030405010708090a0b0c0d05003011060c2a030405020708090a0b0c0d02010c301a060c2a030405030708090a0b0c0d040a31323334353637383930301b060c2a030405040708090a0b0c0d060b530405060708090a0b0c0d3014060c2a030405050708090a0b0c0d4004010203043013060c2a030405060708090a0b0c0d4103221d233013060c2a030405070708090a0b0c0d420312dae33013060c2a030405080708090a0b0c0d430312dae33017060c2a030405090708090a0b0c0d46072be2305512363b"

// GET SNMPv3 '' request_id=234 error_status=0 error_index=0
//  [0]: 1.2.3.4.5.1.7.8.9.10.11.12.13=NULL
//  [1]: 1.2.3.4.5.2.7.8.9.10.11.12.13=INTEGER 12
//  [2]: 1.2.3.4.5.3.7.8.9.10.11.12.13=OCTET STRING 10: 31 32 33 34 35 36 37 38 39 30
//  [3]: 1.2.3.4.5.4.7.8.9.10.11.12.13=OID 2.3.4.5.6.7.8.9.10.11.12.13
//  [4]: 1.2.3.4.5.5.7.8.9.10.11.12.13=IPADDRESS 1.2.3.4
//  [5]: 1.2.3.4.5.6.7.8.9.10.11.12.13=COUNTER 2235683
//  [6]: 1.2.3.4.5.7.7.8.9.10.11.12.13=GAUGE 1235683
//  [7]: 1.2.3.4.5.8.7.8.9.10.11.12.13=TIMETICKS 1235683
//  [8]: 1.2.3.4.5.9.7.8.9.10.11.12.13=COUNTER64 12352121212122683
const snmpv3_sha_aes_txt = "30820168020103300d02010002022717040107020103044c304a04203031323334353637383930313233343536373839303132333435363738393031020103020204d204076d65696a696e67040ca3f43fa5687d10f27616544c040823480000be1800000482010479ab3546d6732de5704f3aa5fd37f650f027932db936963781dda6ab507bd814a5f3ba65fb68ef394f7028f899487492e76855130d50059042a2f7c59a686849b8d510eabbf1d9fa5f9968535c80a60540bbe1985a2f78810549a2fa8bffedcdf827eb8976f7dbc14266394adaba3569dc1974c0003b4602c9c2909c768d871ab6d9d3ea892cab901990cc547367e0853dd99cb3a871bdc22eefa50f573107edcd9eefbce827cd20fc370589ddd14eebc8be629884bd0af384fee99c1b1eaf3c03e12e5c70ed00dae9caf7eabcca8f22ab10b0d7e6374412db478091c62bf46d0b25a4048e4ecd57b890b1122a385b49eb3aa6306abfda33e19e76bdbe0ef8dea06f0c40"

// GET SNMPv2c '' request_id= error_status=0 error_index=0
const snmpv2c_NOSUCHINSTANCE = "302002010104067075626c6963a2130201010201050201013008300606022b068100"

var oid1 []uint32 = []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
var oid2 []uint32 = []uint32{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}

// void append_bindings(snmp_pdu_t* pdu, asn_subid_t* oid
// 	, u_int oid_len, enum snmp_syntax syntax ) {

// 	pdu->bindings[pdu->nbindings].var.len = oid_len;
// 	memcpy(pdu->bindings[pdu->nbindings].var.subs, oid, oid_len*sizeof(oid[0]));
// 	pdu->bindings[pdu->nbindings].syntax = syntax;
// 	pdu->bindings[pdu->nbindings].var.subs[5] = pdu->nbindings + 1;
// 	pdu->nbindings ++;
// }

func AppendBindings(vbs *VariableBindings, s string) {
	oid := make([]uint32, len(oid1))
	copy(oid, oid1)
	oid[5] = uint32(vbs.Len() + 1)
	value, e := NewSnmpValue(s)
	if nil != e {
		panic(e)
	}
	vbs.AppendWith(SnmpOid(oid), value)
}

func checkOid(target *SnmpOid, i int, t *testing.T) {
	oid := make([]uint32, len(oid1))
	copy(oid, oid1)
	oid[5] = uint32(i + 1)
	if target.String() != NewOid(oid).String() {
		t.Errorf("decode v1 pdu failed - oid[%d] not equal, excepted is %s, value is %s", i, NewOid(oid).GetString(), target.GetString())
	}
}
func uint32ToString(ints []uint32) string {
	oid := SnmpOid(ints)
	return oid.String()
}

func fillPdu(vbs *VariableBindings) {
	AppendBindings(vbs, "[null]")
	AppendBindings(vbs, "[int32]12")
	AppendBindings(vbs, "[octets]"+hex.EncodeToString([]byte("1234567890")))
	AppendBindings(vbs, uint32ToString(oid2))
	AppendBindings(vbs, "[ip]1.2.3.4")
	AppendBindings(vbs, "[counter32]2235683")
	AppendBindings(vbs, "[gauge]1235683")
	AppendBindings(vbs, "[timeticks]1235683")
	AppendBindings(vbs, "[counter64]12352121212122683")
}

func checkVB(vbs *VariableBindings, i int, excepted string, t *testing.T, s string) {
	oid := vbs.Get(i).Oid
	checkOid(&oid, i, t)
	if vbs.Get(i).Value.String() != excepted {
		t.Errorf(s+" - value[%d] error, excepted is '%s', value is %s", i, excepted, vbs.Get(i).Value.String())
	}
}

func checkPdu(vbs *VariableBindings, t *testing.T, s string) {
	checkVB(vbs, 0, "[null]", t, s)
	checkVB(vbs, 1, "[int32]12", t, s)
	checkVB(vbs, 2, "[octets]"+hex.EncodeToString([]byte("1234567890")), t, s)
	checkVB(vbs, 3, uint32ToString(oid2), t, s)
	checkVB(vbs, 4, "[ip]1.2.3.4", t, s)
	checkVB(vbs, 5, "[counter32]2235683", t, s)
	checkVB(vbs, 6, "[gauge]1235683", t, s)
	checkVB(vbs, 7, "[timeticks]1235683", t, s)
	checkVB(vbs, 8, "[counter64]12352121212122683", t, s)
}

func TestEncodePDU(t *testing.T) {
	pdu := &V2CPDU{version: SNMP_V1, requestId: 234}
	pdu.Init(map[string]string{"snmp.community": "123987"})
	fillPdu(pdu.GetVariableBindings())
	bytes, e := pdu.encodePDU(*dump_pdu)
	if nil != e {
		t.Errorf("encode v1 pdu faile - %s", e.Error())
	}

	if snmpv1_txt != hex.EncodeToString(bytes) {
		t.Log(hex.EncodeToString(bytes))
		t.Errorf("encode v1 pdu faile.")
	}

	pdu = &V2CPDU{version: SNMP_V2C, requestId: 234}
	pdu.Init(map[string]string{"snmp.community": "123987"})
	fillPdu(pdu.GetVariableBindings())
	bytes, e = pdu.encodePDU(*dump_pdu)
	if nil != e {
		t.Errorf("encode v2 pdu faile - %s", e.Error())
	}

	if snmpv2c_txt != hex.EncodeToString(bytes) {
		t.Log(hex.EncodeToString(bytes))
		t.Errorf("encode v2 pdu faile.")
	}
}

func TestEncodeV3PDU(t *testing.T) {
	testEncodeV3PDU(t, map[string]string{"community": "123987",
		"snmp.identifier":     "0",
		"snmp.context_name":   "testcontextname",
		"snmp.context_engine": "74657374636f6e74657874656e67696e65",
		"snmp.engine_id":      "3031323334353637383930313233343536373839303132333435363738393031",
		"snmp.engine_boots":   "3",
		"snmp.engine_time":    "1234",
		"snmp.max_msg_size":   "10007",
		"snmp.secname":        "meijing",
		"snmp.secmodel":       "usm"}, snmpv3_noauth_txt, "test noauth - ")

	//  msg_salt 8: 03 00 00 00 29 00 00 00
	debug_test_enable()
	debug_salt[0] = 3
	debug_salt[4] = 2*16 + 9

	testEncodeV3PDU(t, map[string]string{"community": "123987",
		"snmp.identifier":     "0",
		"snmp.context_name":   "testcontextname",
		"snmp.context_engine": "74657374636f6e74657874656e67696e65",
		"snmp.engine_id":      "3031323334353637383930313233343536373839303132333435363738393031",
		"snmp.engine_boots":   "3",
		"snmp.engine_time":    "1234",
		"snmp.max_msg_size":   "10007",
		"snmp.secname":        "meijing",
		"snmp.secmodel":       "usm",
		"snmp.auth_pass":      "md5-mfk1234"}, snmpv3_md5_txt, "test auth=md5 - ")

	testEncodeV3PDU(t, map[string]string{"community": "123987",
		"snmp.identifier":     "0",
		"snmp.context_name":   "testcontextname",
		"snmp.context_engine": "74657374636f6e74657874656e67696e65",
		"snmp.engine_id":      "3031323334353637383930313233343536373839303132333435363738393031",
		"snmp.engine_boots":   "3",
		"snmp.engine_time":    "1234",
		"snmp.max_msg_size":   "10007",
		"snmp.secname":        "meijing",
		"snmp.secmodel":       "usm",
		"snmp.auth_pass":      "md5-mfk1234",
		"snmp.priv_pass":      "des-mj1234"}, snmpv3_md5_des_txt, "test auth=md5 and priv=des - ")

	debug_test_enable()
	bs, _ := hex.DecodeString("23480000be180000")
	copy(debug_salt, bs)

	testEncodeV3PDU(t, map[string]string{"community": "123987",
		"snmp.identifier":     "0",
		"snmp.context_name":   "testcontextname",
		"snmp.context_engine": "74657374636f6e74657874656e67696e65",
		"snmp.engine_id":      "3031323334353637383930313233343536373839303132333435363738393031",
		"snmp.engine_boots":   "3",
		"snmp.engine_time":    "1234",
		"snmp.max_msg_size":   "10007",
		"snmp.secname":        "meijing",
		"snmp.secmodel":       "usm",
		"snmp.auth_pass":      "sha-mfk1234"}, snmpv3_sha_txt, "test auth=sha - ")

	testEncodeV3PDU(t, map[string]string{"community": "123987",
		"snmp.identifier":     "0",
		"snmp.context_name":   "testcontextname",
		"snmp.context_engine": "74657374636f6e74657874656e67696e65",
		"snmp.engine_id":      "3031323334353637383930313233343536373839303132333435363738393031",
		"snmp.engine_boots":   "3",
		"snmp.engine_time":    "1234",
		"snmp.max_msg_size":   "10007",
		"snmp.secname":        "meijing",
		"snmp.secmodel":       "usm",
		"snmp.auth_pass":      "sha-mfk1234",
		"snmp.priv_pass":      "aes-mj1234"}, snmpv3_sha_aes_txt, "test auth=sha and priv=aes - ")

	debug_test_disable()
}

func testEncodeV3PDU(t *testing.T, args map[string]string, txt, msg string) {
	pduv3 := &V3PDU{requestId: 234}
	pduv3.Init(args)
	if !pduv3.securityModel.IsLocalize() {
		pduv3.securityModel.Localize(pduv3.engine.engine_id)
		// usm := pduv3.securityModel.(*USM)
		// usm.localization_auth_key = usm.auth_key
		// usm.localization_priv_key = usm.priv_key
	}
	fillPdu(pduv3.GetVariableBindings())
	bytes, e := pduv3.encodePDU(*dump_pdu)
	if nil != e {
		t.Errorf("%sencode v3 pdu failed - %s", msg, e.Error())
	}

	if txt != hex.EncodeToString(bytes) {
		t.Log(hex.EncodeToString(bytes))
		t.Errorf("%sencode v3 pdu failed.", msg)
	}
}

func TestDecodePDU(t *testing.T) {
	bytes, err := hex.DecodeString(snmpv1_txt)
	if nil != err {
		t.Errorf("decode hex failed - %s", err.Error())
		return
	}
	pdu, e := DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, *dump_pdu)
	if nil != e {
		t.Errorf("decode v1 pdu failed - %s", e.Error())
	} else {
		if SNMP_V1 != pdu.GetVersion() {
			t.Errorf("decode v1 pdu failed - version error, excepted is v1, actual value is %d", pdu.GetVersion())
		} else {
			if "123987" != pdu.(*V2CPDU).community {
				t.Errorf("decode v1 pdu failed - community error, excepted is '123987', actual value is %s", pdu.(*V2CPDU).community)
			}
			if 234 != pdu.(*V2CPDU).requestId {
				t.Errorf("decode v1 pdu failed - requestId error, excepted is '234', actual value is %d", pdu.(*V2CPDU).requestId)
			}
		}
		checkPdu(pdu.GetVariableBindings(), t, "decode v1 pdu failed")
	}

	bytes, err = hex.DecodeString(snmpv2c_txt)
	if nil != err {
		t.Errorf("decode hex failed - %s", err.Error())
		return
	}
	pdu, e = DecodePDU(bytes, SNMP_PRIV_NOPRIV, nil, *dump_pdu)
	if nil != e {
		t.Errorf("decode v2 pdu failed - %s", e.Error())
	} else {
		if SNMP_V2C != pdu.GetVersion() {
			t.Errorf("decode v2 pdu failed - version error, excepted is v2C, actual value is %d", pdu.GetVersion())
		} else {
			if "123987" != pdu.(*V2CPDU).community {
				t.Errorf("decode v2 pdu failed - community error, excepted is '123987', actual value is %s", pdu.(*V2CPDU).community)
			}
			if 234 != pdu.(*V2CPDU).requestId {
				t.Errorf("decode v2 pdu failed - requestId error, excepted is '234', actual value is %d", pdu.(*V2CPDU).requestId)
			}
		}
		checkPdu(pdu.GetVariableBindings(), t, "decode v2 pdu failed")
	}

}

func TestDecodeV3PDU(t *testing.T) {
	des, _ := hex.DecodeString("e71b799c9cb2eab59b71e6e1d23b6b64")
	aes, _ := hex.DecodeString("ddab124da80010de687447b013d8ce96642b38cd")
	testDecodeV3PDU(t, snmpv3_noauth_txt, SNMP_AUTH_NOAUTH, "mfk1234", SNMP_PRIV_NOPRIV, nil, "test no priv - ")

	testDecodeV3PDU(t, snmpv3_md5_txt, SNMP_AUTH_HMAC_MD5, "mfk1234", SNMP_PRIV_NOPRIV, nil, "test auth=md5 - ")
	testDecodeV3PDU(t, snmpv3_md5_des_txt, SNMP_AUTH_HMAC_MD5, "mfk1234", SNMP_PRIV_DES, des, "test auth=md5 and priv=des - ")

	testDecodeV3PDU(t, snmpv3_sha_txt, SNMP_AUTH_HMAC_SHA, "mfk1234", SNMP_PRIV_NOPRIV, nil, "test auth=sha - ")
	testDecodeV3PDU(t, snmpv3_sha_aes_txt, SNMP_AUTH_HMAC_SHA, "mfk1234", SNMP_PRIV_AES, aes, "test auth=sha and priv=aes - ")

}

func testDecodeV3PDU(t *testing.T, txt string, auth AuthType, auth_s string, priv PrivType, priv_s []byte, msg string) {
	bytes, err := hex.DecodeString(txt)
	if nil != err {
		t.Errorf(msg+"decode hex failed - %s", err.Error())
		return
	}
	pdu, e := DecodePDU(bytes, priv, priv_s, *dump_pdu)
	if nil != e {
		t.Errorf(msg+"decode v3 pdu failed - %s", e.Error())
	} else {
		if SNMP_V3 != pdu.GetVersion() {
			t.Errorf(msg+"decode v3 pdu failed - version error, excepted is v2C, actual value is %d", pdu.GetVersion())
		} else {

			if 234 != pdu.(*V3PDU).requestId {
				t.Errorf(msg+"decode v3 pdu failed - requestId error, excepted is '234', actual value is %d", pdu.(*V2CPDU).requestId)
			}

			if nil == pdu.(*V3PDU).engine {
				t.Errorf(msg + "decode v3 pdu failed - engine is null")
			}

			if "testcontextname" != pdu.(*V3PDU).contextName {
				t.Errorf(msg+"decode v3 pdu failed - contextEngine error, excepted is 'testcontextname', actual value is %s",
					pdu.(*V3PDU).contextName)
			}

			if "74657374636f6e74657874656e67696e65" != hex.EncodeToString(pdu.(*V3PDU).contextEngine) {
				t.Errorf(msg+"decode v3 pdu failed - contextEngine error, excepted is '74657374636f6e74657874656e67696e65', actual value is %s",
					hex.EncodeToString(pdu.(*V3PDU).contextEngine))
			}

			if "3031323334353637383930313233343536373839303132333435363738393031" != hex.EncodeToString(pdu.(*V3PDU).engine.engine_id) {
				t.Errorf(msg+"decode v3 pdu failed - engine_boots error, excepted is '2', actual value is %d", pdu.(*V3PDU).engine.engine_boots)
			}
			if 3 != pdu.(*V3PDU).engine.engine_boots {
				t.Errorf(msg+"decode v3 pdu failed - engine_boots error, excepted is '2', actual value is %d", pdu.(*V3PDU).engine.engine_boots)
			}
			if 1234 != pdu.(*V3PDU).engine.engine_time {
				t.Errorf(msg+"decode v3 pdu failed - engine_time error, excepted is '2', actual value is %d", pdu.(*V3PDU).engine.engine_time)
			}

			if nil == pdu.(*V3PDU).securityModel {
				t.Errorf(msg + "decode v3 pdu failed - securityModel is null")
			}
			if "meijing" != pdu.(*V3PDU).securityModel.(*USM).name {
				t.Errorf(msg+"decode v3 pdu failed - sec_name error, excepted is 'meijing', actual value is %s", pdu.(*V3PDU).securityModel.(*USM).name)
			}
			// if auth != pdu.(*V3PDU).securityModel.(*HashUSM).auth_proto {
			//	t.Errorf("decode v3 pdu faile - auth_proto error, excepted is '%s', actual value is %s",
			//		auth.String(), pdu.(*V3PDU).securityModel.(*HashUSM).auth_proto.String())
			// }

			// if SNMP_AUTH_NOAUTH != auth {
			//	if auth_s != hex.EncodeToString(pdu.(*V3PDU).securityModel.(*HashUSM).auth_key) {
			//		t.Errorf("decode v3 pdu faile - auth_key error, excepted is '%s', actual value is %s",
			//			auth_s, hex.EncodeToString(pdu.(*V3PDU).securityModel.(*HashUSM).auth_key))
			//	}
			// }

			// if priv != pdu.(*V3PDU).securityModel.(*HashUSM).priv_proto {
			//	t.Errorf("decode v3 pdu faile - priv_proto error, excepted is '%d', actual value is %s",
			//		priv.String(), pdu.(*V3PDU).securityModel.(*HashUSM).priv_proto.String())
			// }

			// if SNMP_PRIV_NOPRIV != priv {

			//	if priv_s != hex.EncodeToString(pdu.(*V3PDU).securityModel.(*HashUSM).priv_key) {
			//		t.Errorf("decode v3 pdu faile - priv_key error, excepted is '%d', actual value is %s",
			//			priv_s, hex.EncodeToString(pdu.(*V3PDU).securityModel.(*HashUSM).priv_key))
			//	}
			// }
		}
		checkPdu(pdu.GetVariableBindings(), t, "decode v3 pdu failed")
	}
}
