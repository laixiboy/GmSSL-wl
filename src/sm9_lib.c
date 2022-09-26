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
#include <stdint.h>
#include <gmssl/hex.h>
#include <gmssl/mem.h>
#include <gmssl/sm3.h>
#include <gmssl/sm9.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


int sm9_signature_to_der(const SM9_SIGNATURE *sig, uint8_t **out, size_t *outlen)
{
	uint8_t hbuf[32];
	uint8_t Sbuf[65];
	size_t len = 0;

	sm9_fn_to_bytes(sig->h, hbuf);
	sm9_point_to_uncompressed_octets(&sig->S, Sbuf);

	if (asn1_octet_string_to_der(hbuf, sizeof(hbuf), NULL, &len) != 1
		|| asn1_bit_octets_to_der(Sbuf, sizeof(Sbuf), NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_octet_string_to_der(hbuf, sizeof(hbuf), out, outlen) != 1
		|| asn1_bit_octets_to_der(Sbuf, sizeof(Sbuf), out, outlen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int sm9_signature_from_der(SM9_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *h;
	size_t hlen;
	const uint8_t *S;
	size_t Slen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_octet_string_from_der(&h, &hlen, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&S, &Slen, &d, &dlen) != 1
		|| asn1_check(hlen == 32) != 1
		|| asn1_check(Slen == 65) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (sm9_fn_from_bytes(sig->h, h) != 1
		|| sm9_point_from_uncompressed_octets(&sig->S, S) != 1) {
		error_print();
		return -1;
	}

	printf("sm9_signature_from_der complete!\n"); // test only
	return 1;
}

int sm9_sign_init(SM9_SIGN_CTX *ctx)
{
	const uint8_t prefix[1] = { SM9_HASH2_PREFIX };
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, prefix, sizeof(prefix));
	return 1;
}

int sm9_sign_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
	return 1;
}

int sm9_sign_finish(SM9_SIGN_CTX *ctx, const SM9_SIGN_KEY *key, uint8_t *sig, size_t *siglen)
{
	SM9_SIGNATURE signature;

	if (sm9_do_sign(key, &ctx->sm3_ctx, &signature) != 1) {
		error_print();
		return -1;
	}

	// test only
	printf("signature(h,S)------------------\n");
	sm9_print_bn("h:",signature.h);
	sm9_print_bn("X:",signature.S.X);
	sm9_print_bn("Y:",signature.S.Y);
	sm9_print_bn("Z:",signature.S.Z);
	// test only

	*siglen = 0;
	if (sm9_signature_to_der(&signature, &sig, siglen) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int zmn_sm9_sign_finish(SM9_SIGN_CTX *ctx, const SM9_SIGN_KEY *key, 
	uint8_t *sig, size_t *siglen,
	SM9_SIGNATURE* signature)
{
	if (sm9_do_sign(key, &ctx->sm3_ctx, signature) != 1) {
		printf("sign failed\n");// test only
		error_print();
		return -1;
	}
	*siglen = 0;
	if (sm9_signature_to_der(signature, &sig, siglen) != 1) {
		printf("sign to DER failed\n"); //test only
		error_print();
		return -1;
	}

	// test only------------
	/*printf("!!!!!!!!der len:%ld\n",*siglen);
	for (int a=0;a<*siglen;a++){
		printf("%02X",sig[a]);
	}
	printf("\n");
	if (sm9_signature_from_der(signature, (const uint8_t**)&sig, siglen) != 1){
		printf("!!!!!!!!!!!! err from der\n");
		error_print();
		return -1;
	}else{
		printf("!!!!!!!!!!!! suc from der\n");
	}*/
	// test only------------

	return 1;
}

int sm9_do_sign(const SM9_SIGN_KEY *key, const SM3_CTX *sm3_ctx, SM9_SIGNATURE *sig)
{
	sm9_fn_t r;
	sm9_fp12_t g;
	uint8_t wbuf[32 * 12];
	SM3_CTX ctx = *sm3_ctx;
	SM3_CTX tmp_ctx;
	uint8_t ct1[4] = {0,0,0,1};
	uint8_t ct2[4] = {0,0,0,2};
	uint8_t Ha[64];

	// A1: g = e(P1, Ppubs)
	sm9_pairing(g, &key->Ppubs, SM9_P1);

	do {
		// A2: rand r in [1, N-1]
		if (sm9_fn_rand(r) != 1) {
			error_print();
			return -1;
		}
		//sm9_fn_from_hex(r, "00033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE"); // for testing

		// A3: w = g^r
		sm9_fp12_pow(g, g, r);
		sm9_fp12_to_bytes(g, wbuf);

		/* 打印r和wbuf */
		/*printf("r:------------------\n");
		for (int i=0;i<8;i++){
			printf("0x%016lX,", r[i]);
		}
		printf("\n");*/

		// A4: h = H2(M || w, N)
		sm3_update(&ctx, wbuf, sizeof(wbuf));
		tmp_ctx = ctx;
		sm3_update(&ctx, ct1, sizeof(ct1));
		sm3_finish(&ctx, Ha);
		sm3_update(&tmp_ctx, ct2, sizeof(ct2));
		sm3_finish(&tmp_ctx, Ha + 32);
		sm9_fn_from_hash(sig->h, Ha);

		// A5: l = (r - h) mod N, if l = 0, goto A2
		sm9_fn_sub(r, r, sig->h);

	} while (sm9_fn_is_zero(r));

	// A6: S = l * dsA
	sm9_point_mul(&sig->S, r, &key->ds);

	/* 检测S在不在Curve上 */
	if (!sm9_point_is_on_curve(&sig->S)) {
		printf("[X][X][X][X] checked!,signature-S is NOT on curve >>>>>>>>>>>>>>>>>>>>>\n");
	}

	gmssl_secure_clear(&r, sizeof(r));
	gmssl_secure_clear(&g, sizeof(g));
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(&tmp_ctx, sizeof(tmp_ctx));
	gmssl_secure_clear(Ha, sizeof(Ha));

	return 1;
}

// 主密钥
#define hex_ks		"000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4"
// 签名私钥
#define hex_ds		"A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820-78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3"

void zmn_sm9_random(char* IDA_str,/* 输入：身份标识，十六进制字符，最多100个字符 */
		size_t IDA_str_len, /* 输入：身份标示的hex字符个数 */
		char* ks_str,/* 输出：主密钥,不足64的话会自动前补0 */
		int* ks_str_len, /* 输出：主密钥的字符个数 */
		char* ppubs_str,/* 输出：主公钥,长度不少于64*4+3，格式:"x1-x2\ny1-y2" */
		int* ppubs_str_len,/* 输出：主公钥的字符个数 */
		char* ds_str,/* 输出：签名私钥,长度不少于129,格式：“x-y”，不带z */
		int* ds_str_len/* 输出：签名密钥的字符个数 */){

	SM9_SIGN_MASTER_KEY sign_master;
	SM9_SIGN_KEY sign_key;
	sm9_fp4_t ppubs;
	sm9_fp2_t ds;
	SM9_POINT dsCmp;// 用于与规约中的ds比较

	uint8_t *IDA = (uint8_t*)malloc(IDA_str_len); 
	size_t IDA_bytes_len = 0;

	/* 注意：M和IDA都是LE */
	if(hex_to_bytes(IDA_str,IDA_str_len,IDA,&IDA_bytes_len)<0){
		error_print();
		goto err;
	}
	printf("[input]----->IDA(len:%ld, byte len:%ld):\t",IDA_str_len,IDA_bytes_len);
	for(int a=0;a<IDA_bytes_len;a++){
		printf("%02X",IDA[a]);
	}
	printf("\n");
	printf("[input]----->ks_str(len:%d):\t%s\n",*ks_str_len,ks_str);

	//if(*ks_str_len>0) {
		// ks已经生成好，通常用于测试
		sm9_bn_from_hex(sign_master.ks, ks_str);
		//sm9_print_bn("ks:",sign_master.ks); // test only
		sm9_twist_point_mul_generator(&sign_master.Ppubs, sign_master.ks);
	//}else {
	//	sm9_sign_master_key_generate(&sign_master);
	//}

	//sm9_sign_master_public_key_to_pem(&sign_master, stdout);
	if(0>sm9_sign_master_key_extract_key(&sign_master, (const char*)IDA, IDA_bytes_len, &sign_key)){
		error_print();
		goto err;
	}

	//if(*ks_str_len<1){
		sm9_bn_to_hex(sign_master.ks,ks_str);
		*ks_str_len = (int)strlen(ks_str);
	//}

	/* 注意：经过验证，不相同的也可以正常签名验签 */
	/*sm9_point_from_hex(&dsCmp, hex_ds); 
	if (!sm9_point_equ(&(sign_key.ds), &dsCmp)) {
		error_print();
		goto err; 
	} else {
		printf(">>>>>>>>>>>>>>>>>>> DSa(X,Y,Z) generated vs loaded is EQ <<<<<<<<<<<<<<<<\n");
	}*/

	//sm9_fp2_copy(ppubs[1],sign_master.Ppubs.X);// [1]在字符串前面显示
	//sm9_fp2_copy(ppubs[0],sign_master.Ppubs.Y);
	sm9_twist_point_get_xy(&sign_master.Ppubs,ppubs[1],ppubs[0]);
	sm9_fp4_to_hex(ppubs,ppubs_str);
	*ppubs_str_len = (int)strlen(ppubs_str);

	//sm9_fp_copy(ds[1],sign_key.ds.X);
	//sm9_fp_copy(ds[0],sign_key.ds.Y);
	sm9_point_get_xy(&sign_key.ds,ds[1],ds[0]); //注意，不能直接获取x，y需要做处理
	sm9_fp2_to_hex(ds,ds_str);
	*ds_str_len = strlen(ds_str);

	free(IDA);
	return;
err:
	printf("%s test failed\n", __FUNCTION__);
	error_print();
	free(IDA);
}
int zmn_sm9_sign(int op_type /* 0:签名 1:验签 */,
		char* data_str, /* 输入（签名用）：消息 或者 输入（验签用）：消息，注意不是摘要后的消息 */
		int data_str_len, /* hex字符个数 */
		char* IDA_str, /* 输入：身份标识，十六进制字符，最多100个字符 */
		int IDA_str_len, /* hex字符个数 */
		char* ks_str, /* 输入（签名用）：签名主密钥,十六进制字符串，固定64个字符 */
		int ks_str_len, /* hex字符个数 */
		char* ds_str,/* 输入（签名用）：签名私钥,十六进制字符，长度不少于129，不多于200个字符,格式：“x-y”，不需要传入z */
		int ds_str_len, /* hex字符个数 */
		char* ppubs_str,/* 输入：主公钥,十六进制字符,长度不少于64*4+3(259),不多于300个字符，格式:"x1-x2\ny1-y2" */
		int ppubs_str_len, /* hex字符个数 */
		char* sig_h_str,/* 输出(签名用)：签名(h) */
		int *sig_h_str_len/* 输出(签名用)：签名(h)的长度 */,
		char* sig_Sx_str,/* 输出(签名用)：签名(S-x) */
		int *sig_Sx_str_len/* 输出(签名用)：签名(S-x)的长度 */,
		char* sig_Sy_str,/* 输出(签名用)：签名(S-y) */
		int *sig_Sy_str_len/* 输出(签名用)：签名(S-y)的长度 */,
		char* sig_Sz_str,/* 输出(签名用)：签名(S-z) */
		int *sig_Sz_str_len/* 输出(签名用)：签名(S-z)的长度 */,
		char* sig_der_str,/* 输出(签名用)：签名(DER格式) 或者 输入(验签用)：签名(DER格式)，十六进制字符，不大于1024个字符 */
		int *sig_der_str_len,/* 输出(签名用)：签名(DER格式)的长度 或者 输入(验签用)：签名(DER格式)的长度 */
		char* Hash_data_str/* 输出(签名用 或者 验签用)：消息的摘要信息,字符串长度固定为64个 */) {
	SM9_SIGN_CTX ctx;
	SM9_SIGN_KEY key;
	SM9_SIGN_MASTER_KEY mpk;
	SM9_POINT ds_cmp;
	SM9_SIGNATURE signature;
	uint8_t sig_der[1000] = {0};
	uint8_t *p_sig_der = NULL;
	int j = 1;
	int ret = 1;
	size_t data_bytes_len = 0;
	size_t IDA_bytes_len = 0;
	size_t sig_der_bytes_len = 0;

	printf("\nprocess sign or verify: %d...........................\n",op_type);
	if(data_str_len<1||IDA_str_len<1) {
		printf("invalid data length or IDA length\n");
		goto err;
	}
	printf("[input]----->data(len:%d):\t%s\n",data_str_len, data_str);
	printf("[input]----->IDA(len:%d):\t%s\n", IDA_str_len,IDA_str);
	printf("[input]----->ppub(len:%d):\t%s\n", ppubs_str_len,ppubs_str);

	//uint8_t data[20] = {0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64, 0x61, 0x72, 0x64};
	//uint8_t IDA[5] = {0x41, 0x6C, 0x69, 0x63, 0x65};
	uint8_t *data = (uint8_t*)malloc(data_str_len);
	uint8_t *IDA = (uint8_t*)malloc(IDA_str_len); 

	/* 注意：M和IDA都是LE */
	if(hex_to_bytes(data_str,data_str_len,data,&data_bytes_len)<0){
		error_print();
		goto err;
	}

	/* 注意：M和IDA都是LE */
	if(hex_to_bytes(IDA_str,IDA_str_len,IDA,&IDA_bytes_len)<0){
		error_print();
		goto err;
	}

	if (op_type == 0) {

		printf("[input]----->ks(len:%d):\t%s\n",ks_str_len,ks_str);
		printf("[input]----->ds(len:%d):\t%s\n",  ds_str_len,  ds_str);
		if(ks_str_len!=64) {
			printf("ks should be 64, not %d\n", ks_str_len);
			return -1;
		}

		if(ds_str_len!=129) {
			printf("ds should be 64+64+1, not %d\n", ds_str_len);
			return -1;
		}
		/* 获取外部输入的主密钥 */
		sm9_bn_from_hex(mpk.ks, ks_str); 

		if (ppubs_str_len > 0){
			/* 使用外部输入的公钥，公钥输入格式为： */
			sm9_twist_point_from_hex(&(mpk.Ppubs),ppubs_str);
		} else { /* 使用自己生成的公钥\签名私钥 */
			sm9_twist_point_mul_generator(&(mpk.Ppubs), mpk.ks);
		}
		
		if (sm9_sign_master_key_extract_key(&mpk, (char *)IDA, IDA_bytes_len, &key) < 0) {
			printf("failed to generate ds\n");
			goto err;
		} 
		++j;
		/*if(ds_str_len > 0) {
			sm9_point_from_hex(&key.ds,ds_str);
		} else {
			if (sm9_sign_master_key_extract_key(&mpk, (char *)IDA, IDA_bytes_len, &key) < 0) {
				printf("failed to generate ds\n");
				goto err;
			} 
			++j;
		}*/

		printf("\n-------------------Ppubs(X,Y,Z):-------------------\n");
		for(int i=2-1;i>=0;i--){
			for(int a=7;a>=0;a--){
				printf("%08lX ",mpk.Ppubs.X[i][a]);
			}
			printf(",");
		}
		printf("\n");
		for(int i=2-1;i>=0;i--){
			for(int a=7;a>=0;a--){
				printf("%08lX ",mpk.Ppubs.Y[i][a]);
			}
			printf(",");
		}
		printf("\n");
		for(int i=2-1;i>=0;i--){
			for(int a=7;a>=0;a--){
				printf("%08lX ",mpk.Ppubs.Z[i][a]);
			}
		}
		printf(",\n-------------------Ppubs(X,Y,Z):-------------------\n");

		printf("\n-------------------DSa(X,Y,Z):-------------------\n");
		for(int a=7;a>=0;a--){
			printf("%08lX ",key.ds.X[a]);
		}
		printf(",\n");
		for(int a=7;a>=0;a--){
			printf("%08lX ",key.ds.Y[a]);
		}
		printf(",\n");
		for(int a=7;a>=0;a--){
			printf("%08lX ",key.ds.Z[a]);
		}
		printf(",\n-------------------DSa(X,Y,Z):-------------------\n");

		/**
		 * 生成的签名私钥和输入的签名私钥比对，不相同的报错 
		 * 目前z不相同，因为z没有从random中继承过来
		 * 注意：经过验证，不相同的也可以正常签名验签
		 * */
		/*sm9_point_from_hex(&ds_cmp, hex_ds); 
		if (!sm9_point_equ(&(key.ds), &ds_cmp)) {
			printf("[X][X][X][X] DSa(X,Y,Z) generated vs loaded is not EQ\n");
			error_print();
			goto err; 
		} else {
			printf(">>>>>>>>>>>>>>>>>>> DSa(X,Y,Z) generated vs loaded is EQ <<<<<<<<<<<<<<<<\n");
		}
		++j;*/

		sm9_sign_init(&ctx);
		sm9_sign_update(&ctx, data, data_bytes_len);	

		//输出 消息的摘要
		for(int a=8-1;a>=0;a--){
			(void)sprintf(Hash_data_str + 8*(8-1-a), "%08X", ctx.sm3_ctx.digest[a]);
		}
		printf("SM3 value:\t%s\n",Hash_data_str);// test only
		
		p_sig_der = sig_der;
		if (zmn_sm9_sign_finish(&ctx, &key, p_sig_der, &sig_der_bytes_len,&signature) < 0) {
			printf("sign finish failed\n");
			goto err; 
		}
		++j;

		/* 输出sig-h */
		sm9_bn_to_hex(signature.h,sig_h_str);
		*sig_h_str_len = 64;

		/* 输出sig-S */
		sm9_bn_to_hex(signature.S.X,sig_Sx_str);
		*sig_Sx_str_len = 64;
		sm9_bn_to_hex(signature.S.Y,sig_Sy_str);
		*sig_Sy_str_len = 64;
		sm9_bn_to_hex(signature.S.Z,sig_Sz_str);
		*sig_Sz_str_len = 64;

		/* 检测S在不在Curve上 */
		if (!sm9_point_is_on_curve(&signature.S)) {
			error_print();
			return -1;
		} else {
			printf("<<<<<<<<<<<<<<<<<<<<<<<<< checked!,signature-S is on curve >>>>>>>>>>>>>>>>>>>>>\n");
		}

		/* 输出sig der格式 */
		printf("\n------------------signature(h,S)------------------\n");
		printf("h(len:%d):%s\n",*sig_h_str_len,sig_h_str);
		printf("S-x(len:%d):%s\n",*sig_Sx_str_len,sig_Sx_str);
		printf("S-y(len:%d):%s\n",*sig_Sy_str_len,sig_Sy_str);
		printf("S-z(len:%d):%s\n",*sig_Sz_str_len,sig_Sz_str);

		/* 输出sig der格式 */
		printf("signature(DER)(byte len:%ld):\t",sig_der_bytes_len);
		for (int a = sig_der_bytes_len-1; a >= 0; a--) {
			(void)sprintf(sig_der_str + 2*(sig_der_bytes_len-1-a), "%02X", sig_der[a]);
		}
		*sig_der_str_len = sig_der_bytes_len*2;
		printf("%s\n------------------signature(h,S)------------------\n",sig_der_str);

	} else { /* 验签 */

		printf("[input]----->signature(DER)(len:%d):\t%s\n", *sig_der_str_len,sig_der_str);
		if (ppubs_str_len > 0){
			/* 使用外部输入的公钥，公钥输入格式为： */
			sm9_twist_point_from_hex(&(mpk.Ppubs),ppubs_str);
		} else {
			printf("verify must need Ppubs\n");
			error_print();
			return -1;
		}

		if (*sig_der_str_len > 0) {	
			if (hex_to_bytes_r(sig_der_str,*sig_der_str_len,sig_der,&sig_der_bytes_len)<0){
				printf("signature(DER) is not HEX format\n");
				goto err;
			}
			printf("\n");
		} else {
			printf("signature(DER) must have, not %d\n", *sig_der_str_len);
			error_print();
			return -1;
		}

		printf("\n-------------------Ppubs(X,Y,Z):-------------------\n");
		for(int i=2-1;i>=0;i--){
			for(int a=7;a>=0;a--){
				printf("%08lX ",mpk.Ppubs.X[i][a]);
			}
			printf(",");
		}
		printf("\n");
		for(int i=2-1;i>=0;i--){
			for(int a=7;a>=0;a--){
				printf("%08lX ",mpk.Ppubs.Y[i][a]);
			}
			printf(",");
		}
		printf("\n");
		for(int i=2-1;i>=0;i--){
			for(int a=7;a>=0;a--){
				printf("%08lX ",mpk.Ppubs.Z[i][a]);
			}
			printf(",");
		}
		printf(",\n-------------------Ppubs(X,Y,Z):-------------------\n");

		printf("\n-------------------DSa(X,Y,Z):-------------------\n");
		for(int a=7;a>=0;a--){
			printf("%08lX ",key.ds.X[a]);
		}
		printf(",\n");
		for(int a=7;a>=0;a--){
			printf("%08lX ",key.ds.Y[a]);
		}
		printf(",\n");
		for(int a=7;a>=0;a--){
			printf("%08lX ",key.ds.Z[a]);
		}
		printf(",\n-------------------DSa(X,Y,Z):-------------------\n");

		/* 输出sig der格式 */
		printf("\n------------------signature(h,S)------------------\n");
		printf("h(len:%d):%s\n",*sig_h_str_len,sig_h_str);
		printf("S-x(len:%d):%s\n",*sig_Sx_str_len,sig_Sx_str);
		printf("S-y(len:%d):%s\n",*sig_Sy_str_len,sig_Sy_str);
		printf("S-z(len:%d):%s\n",*sig_Sz_str_len,sig_Sz_str);
		printf("%s\n------------------signature(h,S)------------------\n",sig_der_str);

		sm9_verify_init(&ctx);
		sm9_verify_update(&ctx, data, data_bytes_len);

		//输出 消息的摘要
		for(int a=8-1;a>=0;a--){
			(void)sprintf(Hash_data_str + 8*(8-1-a), "%08X", ctx.sm3_ctx.digest[a]);
		}
		printf("SM3 value:\t%s\n",Hash_data_str);// test only

		p_sig_der = sig_der;
		ret = zmn_sm9_verify_finish(&ctx,p_sig_der,sig_der_bytes_len,&mpk, (const char *)IDA, IDA_bytes_len,&signature);
		printf("<<<<<<<<<<<<<<<<<<<<<<<<< verify result: %s >>>>>>>>>>>>>>>>>>>>>\n", ret == 1 ? "success" : "failure");
	}

	free(data);
	free(IDA);
	printf("%s() DONE\n", __FUNCTION__); //test only
	return ret;

err:
	printf("%s step %d failed\n", __FUNCTION__, j); //test only
	error_print();

	free(data);
	free(IDA);
	return -1;
}

#define hex_de \
	"94736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683\n" \
	"115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158\n" \
	"7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F\n" \
	"27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1"
#define hex_ke		"0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22"

/* 1: 成功 非1:失败*/
int zmn_sm9_enc_random(char* IDb_str, /* 输入：解密者的身份标识，，十六进制字符，最多100个字符 */
		int IDb_str_len, /* 输入：解密者的身份标识十六进制字符个数 */
		char* ke_str,/* 输出：加密主私钥，KGC保存，不给用户，十六进制字符串,长度至少128个字符，不多于200个字符 */
		int* ke_str_len, /* 输出：加密主私钥的十六进制字符个数 */
		char* ppubs_der_str,/* 输出：加密主公钥(DER)，用于加密,十六进制字符串,长度最多512个字节（1024个字符） */
		int* ppubs_der_str_len,/* 输出：加密主公钥(DER)的十六进制字符个数 */
		char* de_str,/* 输出：加密用户私钥，用于解密，十六进制字符串,长度至少259个字符，不多于300个字符 */
		int* de_str_len /* 输出：加密用户私钥的十六进制字符个数 */) {

	uint8_t *IDb = NULL;
	size_t IDb_bytes_len = 0;
	SM9_ENC_MASTER_KEY master;
	SM9_ENC_KEY key;
	uint8_t ppubs_der_buf[512] = {'\0'};
	size_t ppubs_der_buf_len = 0;
	uint8_t *p_ppubs_der_buf = NULL;
	sm9_fp2_t ppubs;
	sm9_fp4_t de;
	SM9_TWIST_POINT deCmp;

	printf("[input]------->IDb(len:%d):\t%s\n",IDb_str_len,IDb_str);
	if (IDb_str_len<1){
		printf("IDb must have, not %d\n", IDb_str_len);
		return -1;
	}

	IDb = (uint8_t*)malloc(IDb_str_len); 
	if(hex_to_bytes(IDb_str,IDb_str_len,IDb,&IDb_bytes_len)<0){
		free(IDb);
		error_print();
		return -1;
	}
	printf("IDb(byte len:%ld):\t",IDb_bytes_len);
	for(int a=0;a<IDb_bytes_len;a++){
		printf("%02X",IDb[a]);
	}
	printf("\n");

	/* 生成加密主私钥，主公钥 */
	sm9_enc_master_key_generate(&master);

	/* 输出加密主私钥 */
	sm9_bn_to_hex(master.ke,ke_str);
	*ke_str_len = (int)strlen(ke_str);

	//生成加密私钥
	if (sm9_enc_master_key_extract_key(&master, (char *)IDb, IDb_bytes_len, &key) < 0){
		free(IDb);
		error_print();
		return -1;	
	}

	//原计划测试加密私钥的有效性，过测的才能用
	//实际上不需要，测不过的情况下也能进行加解密，所以该环节无意义
	/*sm9_twist_point_from_hex(&deCmp, hex_de); 
	if (!sm9_twist_point_equ(&(key.de), &deCmp)) {
		free(IDb);
		error_print();
		return -1;
	}*/

	/* 输出加密用户私钥 */
	sm9_twist_point_get_xy(&key.de,de[1],de[0]);
	sm9_fp4_to_hex(de,de_str);
	*de_str_len = strlen(de_str);

	// test only
	/*printf("Ppubs(X,Y,Z):-------------------\n");
	for(int a=7;a>=0;a--){
		printf("%08lX ",master.Ppube.X[a]);
	}
	printf(",\n");
	for(int a=7;a>=0;a--){
		printf("%08lX ",master.Ppube.Y[a]);
	}
	printf(",\n");
	for(int a=7;a>=0;a--){
		printf("%08lX ",master.Ppube.Z[a]);
	}
	printf(",\n");*/
	// test only

	/* 生成公钥DER格式 */
	p_ppubs_der_buf = ppubs_der_buf;
	sm9_enc_master_public_key_to_der(&master, &p_ppubs_der_buf, &ppubs_der_buf_len);
	
	// test only
	printf("ppubs(DER)(len:%ld):\t",ppubs_der_buf_len);
	for(int a=ppubs_der_buf_len-1;a>=0;a--){
		printf("%02X",ppubs_der_buf[a]);
	}
	printf("\n");
	// test only

	/* 输出sig der格式 */
	for (int a = ppubs_der_buf_len-1; a >= 0; a--) {
		(void)sprintf(ppubs_der_str + 2*(ppubs_der_buf_len-1-a), "%02X", ppubs_der_buf[a]);
	}
	*ppubs_der_str_len = ppubs_der_buf_len*2;

	free(IDb);
	return 1;
}

/* 1: 成功 非1:失败*/
int zmn_sm9_encrypt(int optype,/* 0:加密 1:解密 */
	char* IDb_str, /* 输入：解密者的身份标识，十六进制字符，最多100个字符 */
	int IDb_str_len, /* hex字符个数 */
	char* data_str,/* 输入(加密用)：明文数据，十六进制字符串 或者 输入(解密用)：密文数据，十六进制字符串 */
	int data_str_len,/* 输入(加密用)：明文数据十六进制字符个数 或者  输入(解密用)：密文数据十六进制字符个数 */
	char* ppubs_der_str,/* 输入(加密用)：加密主公钥，十六进制字符串, 长度至多2048个字符 */
	int ppubs_der_str_len,/* 输入(加密用)：加密主公钥的十六进制字符个数 */
	char* de_str, /* 输入(解密用)：加密私钥，十六进制字符串,长度至少259个字符 */
	int de_str_len /* 输入(解密用)：加密私钥的十六进制字符个数 */,
	char* m_str,/* 输出(加密用)：密文数据，十六进制字符串 或者 输出(解密用)：明文数据，十六进制字符串，最大1024个字符 */
	int* m_str_len/* 输出(加密用)：密文数据十六进制字符个数 或者  输出(解密用)：明文数据十六进制字符个数 */){

	SM9_ENC_MASTER_KEY master_public;
	SM9_ENC_KEY key;
	uint8_t M[1024] = {'\0'};
	size_t M_bytes_len = 0;

	uint8_t ppube_buf[1024] = {'\0'};
	size_t ppube_buf_bytes_len = 0;
	uint8_t* p_ppube_buf = NULL;

	uint8_t *IDb = NULL;
	uint8_t *data = NULL;
	size_t data_bytes_len = 0;
	size_t IDb_bytes_len = 0;

	printf("[input]----->IDb(len:%d):\t%s\n",IDb_str_len,IDb_str);
	printf("[input]----->data(len:%d):\t%s\n",data_str_len,data_str);
	if(data_str_len<0){
		printf("data must have, not %d\n",data_str_len);
		return -1;
	}

	if(IDb_str_len<0){
		printf("IDb must have, not %d\n",IDb_str_len);
		return -1;
	}

	IDb = (uint8_t*)malloc(IDb_str_len+1);
	data = (uint8_t*)malloc(data_str_len+1);

	if(hex_to_bytes(data_str,data_str_len,data,&data_bytes_len)<0){
		printf("data tranform failed\n");
		goto err;
	}

	if(hex_to_bytes(IDb_str,IDb_str_len,IDb,&IDb_bytes_len)<0){
		printf("IDb tranform failed\n");
		goto err;
	}

	// test only
	printf("[input]----->IDB(byte len:%ld):\t",IDb_bytes_len);
	for(int a=0; a<IDb_bytes_len ;a++){
		printf("%02X",IDb[a]);
	}
	printf("\n");
	printf("[input]----->data(byte len:%ld):\t",data_bytes_len);
	for(int a=0; a<data_bytes_len ;a++){
		printf("%02X",data[a]);
	}
	printf("\n");
	// test only

	if (optype == 0){

		printf("\n******************* process encrypt *******************\n");

		printf("[input]----->ppub-e(str len:%d):%s\n",ppubs_der_str_len,ppubs_der_str);
		if (ppubs_der_str_len > 0){
			if(hex_to_bytes_r(ppubs_der_str,ppubs_der_str_len,ppube_buf,&ppube_buf_bytes_len)<0){
				goto err;
			}

			//test only
			printf("ppub loaded(byte len:%ld):\t",ppube_buf_bytes_len);
			for(int a=ppube_buf_bytes_len-1; a>=0 ;a--){
				printf("%02X",ppube_buf[a]);
			}
			printf("\n");
			//test only

			p_ppube_buf = ppube_buf;
			sm9_enc_master_public_key_from_der(&master_public,(const uint8_t**)&p_ppube_buf, &ppube_buf_bytes_len);
		} else {
			printf("ppub-e must have, not %d\n",ppubs_der_str_len);
			goto err;
		}
		
		/*printf("Ppubs:-------------------\n");
		printf("Ppubs-X:");
		for(int a=7;a>=0;a--){
			printf("%08lX ",master_public.Ppube.X[a]);
		}
		printf(",\n");
		printf("Ppubs-Y:");
		for(int a=7;a>=0;a--){
			printf("%08lX ",master_public.Ppube.Y[a]);
		}
		printf(",\n");
		printf("Ppubs-Z:");
		for(int a=7;a>=0;a--){
			printf("%08lX ",master_public.Ppube.Z[a]);
		}
		printf(",\n");*/

		if(0 > sm9_encrypt(&master_public, IDb, IDb_bytes_len, data, data_bytes_len, M, &M_bytes_len)){
			fprintf(stderr, "encrypt failed\n");
			goto err;
		}
		//test only
		printf("encrypted(byte len:%ld):",M_bytes_len);
		for(int a=0; a<M_bytes_len ;a++){
			printf("%02X",M[a]);
		}
		printf("\n");
		//test only

		for(int a=0; a<M_bytes_len ;a++){
			(void)sprintf(m_str + 2*(a), "%02X", M[a]);
		}
		*m_str_len = M_bytes_len*2;
	} else {

		printf("\n******************* process decrypt *******************\n");

		if(de_str_len < 259) {
			printf("de should be 259, not %d\n", de_str_len);
			goto err;
		}

		sm9_twist_point_from_hex(&(key.de),de_str);
		if (0 > sm9_decrypt(&key, IDb, IDb_bytes_len, data, data_bytes_len,M, &M_bytes_len)){
			fprintf(stderr, "decrypt failed\n");
			goto err;
		}

		//test only
		printf("decrypted(byte len:%ld):",M_bytes_len);
		for(int a=0; a<M_bytes_len ;a++){
			printf("%02X",M[a]);
		}
		printf("\n");
		//test only
	}

	for(int a=0; a<M_bytes_len ;a++){
		(void)sprintf(m_str + 2*(a), "%02X", M[a]);
	}
	*m_str_len = M_bytes_len*2;

	free(IDb);
	free(data);
	return 1;

err:
	free(IDb);
	free(data);
	return -1;
}

int sm9_verify_init(SM9_SIGN_CTX *ctx)
{
	const uint8_t prefix[1] = { SM9_HASH2_PREFIX };
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, prefix, sizeof(prefix));
	return 1;
}

int sm9_verify_update(SM9_SIGN_CTX *ctx, const uint8_t *data, size_t datalen)
{
	sm3_update(&ctx->sm3_ctx, data, datalen);
	return 1;
}

int sm9_verify_finish(SM9_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen,
	const SM9_SIGN_MASTER_KEY *mpk, const char *id, size_t idlen)
{
	int ret;
	SM9_SIGNATURE signature;

	if (sm9_signature_from_der(&signature, &sig, &siglen) != 1
		|| asn1_length_is_zero(siglen) != 1) {
		error_print();
		return -1;
	}

	if ((ret = sm9_do_verify(mpk, id, idlen, &ctx->sm3_ctx, &signature)) < 0) {
		error_print();
		return -1;
	}
	return ret;
}

int zmn_sm9_verify_finish(SM9_SIGN_CTX *ctx, const uint8_t *sig, size_t siglen,
		const SM9_SIGN_MASTER_KEY *mpk, const char *id, size_t idlen,
		SM9_SIGNATURE* signature)
{
	int ret;

	if ((ret=sm9_signature_from_der(signature, &sig, &siglen)) != 1){
		error_print();
		return -1;
	}
	if((ret=asn1_length_is_zero(siglen)) != 1) {
		error_print();
		return -1;
	}

	if ((ret = sm9_do_verify(mpk, id, idlen, &ctx->sm3_ctx, signature)) < 0) {
		error_print();
		return -1;
	}

	return ret;
}

int sm9_do_verify(const SM9_SIGN_MASTER_KEY *mpk, const char *id, size_t idlen,
	const SM3_CTX *sm3_ctx, const SM9_SIGNATURE *sig)
{
	sm9_fn_t h1;
	sm9_fn_t h2;
	sm9_fp12_t g;
	sm9_fp12_t t;
	sm9_fp12_t u;
	sm9_fp12_t w;
	SM9_TWIST_POINT P;
	uint8_t wbuf[32 * 12];
	SM3_CTX ctx = *sm3_ctx;
	SM3_CTX tmp_ctx;
	uint8_t ct1[4] = {0,0,0,1};
	uint8_t ct2[4] = {0,0,0,2};
	uint8_t Ha[64];

	// B1: check h in [1, N-1]

	// B2: check S in G1

	// B3: g = e(P1, Ppubs)
	sm9_pairing(g, &mpk->Ppubs, SM9_P1);

	// B4: t = g^h
	sm9_fp12_pow(t, g, sig->h);

	// B5: h1 = H1(ID || hid, N)
	sm9_hash1(h1, id, idlen, SM9_HID_SIGN);

	// B6: P = h1 * P2 + Ppubs
	sm9_twist_point_mul_generator(&P, h1);
	sm9_twist_point_add_full(&P, &P, &mpk->Ppubs);

	// B7: u = e(S, P)
	sm9_pairing(u, &P, &sig->S);

	// B8: w = u * t
	sm9_fp12_mul(w, u, t);
	sm9_fp12_to_bytes(w, wbuf);

	// B9: h2 = H2(M || w, N), check h2 == h
	sm3_update(&ctx, wbuf, sizeof(wbuf));
	tmp_ctx = ctx;
	sm3_update(&ctx, ct1, sizeof(ct1));
	sm3_finish(&ctx, Ha);
	sm3_update(&tmp_ctx, ct2, sizeof(ct2));
	sm3_finish(&tmp_ctx, Ha + 32);
	sm9_fn_from_hash(h2, Ha);

	sm9_print_bn("h2:",h2);// test only
	sm9_print_bn("sig-h:",sig->h);// test only
	if (sm9_fn_equ(h2, sig->h) != 1) {
		return 0;
	}

	return 1;
}

int sm9_kem_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	size_t klen, uint8_t *kbuf, SM9_POINT *C)
{
	sm9_fn_t r;
	sm9_fp12_t w;
	uint8_t wbuf[32 * 12];
	uint8_t cbuf[65];
	SM3_KDF_CTX kdf_ctx;

	// A1: Q = H1(ID||hid,N) * P1 + Ppube
	sm9_hash1(r, id, idlen, SM9_HID_ENC);
	sm9_point_mul(C, r, SM9_P1);
	sm9_point_add(C, C, &mpk->Ppube);

	do {
		// A2: rand r in [1, N-1]
		if (sm9_fn_rand(r) != 1) {
			error_print();
			return -1;
		}

		// A3: C1 = r * Q
		sm9_point_mul(C, r, C);
		sm9_point_to_uncompressed_octets(C, cbuf);

		// A4: g = e(Ppube, P2)
		sm9_pairing(w, SM9_P2, &mpk->Ppube);

		// A5: w = g^r
		sm9_fp12_pow(w, w, r);
		sm9_fp12_to_bytes(w, wbuf);

		// A6: K = KDF(C || w || ID_B, klen), if K == 0, goto A2
		sm3_kdf_init(&kdf_ctx, klen);
		sm3_kdf_update(&kdf_ctx, cbuf + 1, 64);
		sm3_kdf_update(&kdf_ctx, wbuf, sizeof(wbuf));
		sm3_kdf_update(&kdf_ctx, (uint8_t *)id, idlen);
		sm3_kdf_finish(&kdf_ctx, kbuf);

	} while (mem_is_zero(kbuf, klen) == 1);

	gmssl_secure_clear(&r, sizeof(r));
	gmssl_secure_clear(&w, sizeof(w));
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(&kdf_ctx, sizeof(kdf_ctx));

	// A7: output (K, C)
	return 1;
}

int sm9_kem_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen, const SM9_POINT *C,
	size_t klen, uint8_t *kbuf)
{
	sm9_fp12_t w;
	uint8_t wbuf[32 * 12];
	uint8_t cbuf[65];
	SM3_KDF_CTX kdf_ctx;

	// B1: check C in G1
	sm9_point_to_uncompressed_octets(C, cbuf);

	// B2: w = e(C, de);
	sm9_pairing(w, &key->de, C);
	sm9_fp12_to_bytes(w, wbuf);

	// B3: K = KDF(C || w || ID, klen)
	sm3_kdf_init(&kdf_ctx, klen);
	sm3_kdf_update(&kdf_ctx, cbuf + 1, 64);
	sm3_kdf_update(&kdf_ctx, wbuf, sizeof(wbuf));
	sm3_kdf_update(&kdf_ctx, (uint8_t *)id, idlen);
	sm3_kdf_finish(&kdf_ctx, kbuf);

	if (mem_is_zero(kbuf, klen)) {
		error_print();
		return -1;
	}

	gmssl_secure_clear(&w, sizeof(w));
	gmssl_secure_clear(wbuf, sizeof(wbuf));
	gmssl_secure_clear(&kdf_ctx, sizeof(kdf_ctx));

	// B4: output K
	return 1;
}

int sm9_do_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen,
	SM9_POINT *C1, uint8_t *c2, uint8_t c3[SM3_HMAC_SIZE])
{
	SM3_HMAC_CTX hmac_ctx;
	uint8_t K[inlen + 32];

	if (sm9_kem_encrypt(mpk, id, idlen, sizeof(K), K, C1) != 1) {
		error_print();
		return -1;
	}
	gmssl_memxor(c2, K, in, inlen);

	//sm3_hmac(K + inlen, 32, c2, inlen, c3);
	sm3_hmac_init(&hmac_ctx, K + inlen, SM3_HMAC_SIZE);
	sm3_hmac_update(&hmac_ctx, c2, inlen);
	sm3_hmac_finish(&hmac_ctx, c3);
	gmssl_secure_clear(&hmac_ctx, sizeof(hmac_ctx));
	return 1;
}

int sm9_do_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const SM9_POINT *C1, const uint8_t *c2, size_t c2len, const uint8_t c3[SM3_HMAC_SIZE],
	uint8_t *out)
{
	SM3_HMAC_CTX hmac_ctx;
	uint8_t k[c2len + SM3_HMAC_SIZE];
	uint8_t mac[SM3_HMAC_SIZE];

	if (sm9_kem_decrypt(key, id, idlen, C1, sizeof(k), k) != 1) {
		error_print();
		return -1;
	}
	//sm3_hmac(k + c2len, SM3_HMAC_SIZE, c2, c2len, mac);
	sm3_hmac_init(&hmac_ctx, k + c2len, SM3_HMAC_SIZE);
	sm3_hmac_update(&hmac_ctx, c2, c2len);
	sm3_hmac_finish(&hmac_ctx, mac);
	gmssl_secure_clear(&hmac_ctx, sizeof(hmac_ctx));

	if (gmssl_secure_memcmp(c3, mac, sizeof(mac)) != 0) {
		error_print();
		return -1;
	}
	gmssl_memxor(out, k, c2, c2len);
	return 1;
}

#define SM9_ENC_TYPE_XOR	0
#define SM9_ENC_TYPE_ECB	1
#define SM9_ENC_TYPE_CBC	2
#define SM9_ENC_TYPE_OFB	4
#define SM9_ENC_TYPE_CFB	8

/*
SM9Cipher ::= SEQUENCE {
	EnType		INTEGER, -- 0 for XOR
	C1		BIT STRING, -- uncompressed octets of ECPoint
	C3		OCTET STRING, -- 32 bytes HMAC-SM3 tag
	CipherText	OCTET STRING,
}
*/
int sm9_ciphertext_to_der(const SM9_POINT *C1, const uint8_t *c2, size_t c2len,
	const uint8_t c3[SM3_HMAC_SIZE], uint8_t **out, size_t *outlen)
{
	int en_type = SM9_ENC_TYPE_XOR;
	uint8_t c1[65];
	size_t len = 0;

	if (sm9_point_to_uncompressed_octets(C1, c1) != 1) {
		error_print();
		return -1;
	}
	if (asn1_int_to_der(en_type, NULL, &len) != 1
		|| asn1_bit_octets_to_der(c1, sizeof(c1), NULL, &len) != 1
		|| asn1_octet_string_to_der(c3, SM3_HMAC_SIZE, NULL, &len) != 1
		|| asn1_octet_string_to_der(c2, c2len, NULL, &len) != 1
		|| asn1_sequence_header_to_der(len, out, outlen) != 1
		|| asn1_int_to_der(en_type, out, outlen) != 1
		|| asn1_bit_octets_to_der(c1, sizeof(c1), out, outlen) != 1
		|| asn1_octet_string_to_der(c3, SM3_HMAC_SIZE, out, outlen) != 1
		|| asn1_octet_string_to_der(c2, c2len, out, outlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_ciphertext_from_der(SM9_POINT *C1, const uint8_t **c2, size_t *c2len,
	const uint8_t **c3, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	int en_type;
	const uint8_t *c1;
	size_t c1len;
	size_t c3len;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_int_from_der(&en_type, &d, &dlen) != 1
		|| asn1_bit_octets_from_der(&c1, &c1len, &d, &dlen) != 1
		|| asn1_octet_string_from_der(c3, &c3len, &d, &dlen) != 1
		|| asn1_octet_string_from_der(c2, c2len, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	if (en_type != SM9_ENC_TYPE_XOR) {
		error_print();
		return -1;
	}
	if (c1len != 65) {
		error_print();
		return -1;
	}
	if (c3len != SM3_HMAC_SIZE) {
		error_print();
		return -1;
	}
	if (sm9_point_from_uncompressed_octets(C1, c1) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm9_encrypt(const SM9_ENC_MASTER_KEY *mpk, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM9_POINT C1;
	uint8_t c2[inlen];
	uint8_t c3[SM3_HMAC_SIZE];

	if (sm9_do_encrypt(mpk, id, idlen, in, inlen, &C1, c2, c3) != 1) {
		error_print();
		return -1;
	}
	*outlen = 0;
	if (sm9_ciphertext_to_der(&C1, c2, inlen, c3, &out, outlen) != 1) { // FIXME: when out == NULL	
		error_print();
		return -1;
	}
	return 1;
}

int sm9_decrypt(const SM9_ENC_KEY *key, const char *id, size_t idlen,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen)
{
	SM9_POINT C1;
	const uint8_t *c2;
	size_t c2len;
	const uint8_t *c3;
	int ret = 0;

	// test only
	/*ret = sm9_ciphertext_from_der(&C1, &c2, &c2len, &c3, &in, &inlen);
	printf("sm9_ciphertext_from_der ret:%d\n",ret);	
	if(ret==1){	
		ret = asn1_length_is_zero(inlen);
		printf("asn1_length_is_zero ret:%d\n",ret);	
		if(ret != 1){
			error_print();
			return -1;
		}
	}*/
	// test only

	if (sm9_ciphertext_from_der(&C1, &c2, &c2len, &c3, &in, &inlen) != 1
		|| asn1_length_is_zero(inlen) != 1) {
		error_print();
		return -1;
	}
	*outlen = c2len;
	if (!out) {
		return 1;
	}
	if (sm9_do_decrypt(key, id, idlen, &C1, c2, c2len, c3, out) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
