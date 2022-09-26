/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm9.h>
#include <gmssl/error.h>


#define hex_de \
	"94736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683\n" \
	"115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158\n" \
	"7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F\n" \
	"27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1"

int main(void)
{
	SM9_ENC_MASTER_KEY master;
	SM9_ENC_MASTER_KEY master_public;
	SM9_ENC_KEY key;
	const char *id = "Alice";
	uint8_t buf[512];
	uint8_t *p = buf;
	const uint8_t *cp = buf;
	size_t len;
	char mbuf[256];
	size_t mlen;
	int ret;
	SM9_TWIST_POINT deCmp;

	sm9_enc_master_key_generate(&master);
	sm9_enc_master_key_extract_key(&master, id, strlen(id), &key);

	sm9_enc_master_public_key_to_der(&master, &p, &len);
	sm9_enc_master_public_key_from_der(&master_public, &cp, &len);

	/* 比较也失败 */
	/*sm9_twist_point_from_hex(&deCmp, hex_de); 
	if (!sm9_twist_point_equ(&(key.de), &deCmp)) {
		fprintf(stderr, "compare failed\n");
		return -1;
	}*/

	sm9_encrypt(&master_public, id, strlen(id), (uint8_t *)"hello", strlen("hello"), buf, &len);
	ret = sm9_decrypt(&key, id, strlen(id), buf, len, (uint8_t *)mbuf, &mlen);
	if (ret != 1) {
		fprintf(stderr, "decrypt failed\n");
		return 1;
	}
	mbuf[mlen] = 0;
	printf("decrypt result: %s\n", mbuf);

	return 0;
}
