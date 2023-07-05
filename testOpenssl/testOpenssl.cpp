// testOpenssl.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/sm2.h>
#include <openssl/bn.h>
#include <crypto/evp.h>


#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"ws2_32.lib")


#ifdef _DEBUG
#define DEBUG_PRINT(fmt, ...) \
    do { fprintf(stderr, "[%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); } while (0)
#else
#define DEBUG_PRINT(fmt, ...) \
    do {} while (0)
#endif


void getOpensslErrMsg()
{
#ifdef _DEBUG
	// 获取最近一次错误代码
	unsigned long err = ERR_get_error();
	if (err != 0) {
		// 将错误代码转换为错误信息
		char err_msg[256];
		ERR_error_string_n(err, err_msg, sizeof(err_msg));
		DEBUG_PRINT("OpenSSL error: %s\n", err_msg);
	}
#endif // _DEBUG
}


//#include "openssl/ec.h"
static const char Hex[] = "0123456789ABCDEF";

static EC_KEY* CalculateKey(const EC_GROUP* ec_group, const char* privkey_hex_string)
{
	EC_KEY* ec_key = NULL;
	EC_POINT* pubkey = NULL;
	BIGNUM* privkey = NULL;

	if (!BN_hex2bn(&privkey, (const char*)privkey_hex_string)) return NULL;
	if ((pubkey = EC_POINT_new(ec_group)) == NULL) goto err;
	if (!ec_key)
	{
		ec_key = EC_KEY_new();
		if (!ec_key) goto err;
		if (!EC_KEY_set_group(ec_key, ec_group))
		{
			EC_KEY_free(ec_key);
			ec_key = NULL;
			goto err;
		}
	}

	if (!EC_POINT_mul(ec_group, pubkey, privkey, NULL, NULL, NULL))
	{
		EC_KEY_free(ec_key);
		ec_key = NULL;
		goto err;
	}

	if (!EC_KEY_set_private_key(ec_key, privkey) || !EC_KEY_set_public_key(ec_key, pubkey))
	{
		EC_KEY_free(ec_key);
		ec_key = NULL;
		goto err;
	}

err:
	if (privkey)
	{
		BN_free(privkey);
		privkey = NULL;
	}
	if (pubkey)
	{
		EC_POINT_free(pubkey);
		pubkey = NULL;
	}

	return ec_key;
}

static EC_KEY* CalculatePubKey(const EC_GROUP* ec_group, const char* pub_hex_string)
{
	EC_KEY* ec_key = NULL;
	EC_POINT* pubkey = NULL;

	if ((pubkey = EC_POINT_new(ec_group)) == NULL) goto err;
	if (!EC_POINT_hex2point(ec_group, pub_hex_string, pubkey, NULL)) goto err;

	if (!ec_key)
	{
		ec_key = EC_KEY_new();
		if (!ec_key) goto err;
		if (!EC_KEY_set_group(ec_key, ec_group))
		{
			EC_KEY_free(ec_key);
			ec_key = NULL;
			goto err;
		}
	}

	if (!EC_KEY_set_public_key(ec_key, pubkey))
	{
		EC_KEY_free(ec_key);
		ec_key = NULL;
		goto err;
	}

err:
	if (pubkey)
	{
		EC_POINT_free(pubkey);
		pubkey = NULL;
	}

	return ec_key;
}
/* Must 'OPENSSL_free' the returned data */
static char* bin2hex(const unsigned char* bin, size_t binLen)
{
	int i;
	char* buf = NULL;
	char* p = NULL;
	if (bin==NULL || binLen<=0)
	{
		goto err;
	}
	buf = (char*)OPENSSL_malloc(binLen * 2 + 2);
	if (buf == NULL) {
		BNerr(BN_F_BN_BN2HEX, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	p = buf;
	for (i = 0; i < binLen; i++) {
		*p++ = Hex[bin[i] >> 4];
		*p++ = Hex[bin[i] & 0x0f];
	}
	*p = '\0';
err:
	return buf;
}
static int hex2bin(const char* hex, unsigned char* bin)
{
	int i;
	int len = strlen(hex);
	if (hex == NULL || bin ==NULL)
	{
		return 0;
	}
	if (len % 2 != 0) return -1;
	for (i = 0; i < len; i += 2)
	{
		char tmp[3] = { hex[i],hex[i + 1],'\0' };
		bin[i / 2] = (unsigned char)strtol(tmp, NULL, 16);
	}
	return len / 2;
}

//privKey:私钥,16进制DER或者PEM
static EVP_PKEY* getEvpKey(const char* privKeyStr)
{
	int ret = -1;
	EVP_PKEY* pkey = NULL;
	unsigned char privKey[4096] = { 0 };
	size_t privKeyLen;
	int flag = 0;
	int bits;
	const char* alg_name;
	BIO* priBio = NULL;
	do
	{
		//检查参数
		if (privKeyStr == NULL)
		{
			ret = 1;
			DEBUG_PRINT("Parameter error.\n");
			break;
		}
		//判断signData是DER还是PEM格式
		if (privKeyStr[0] == '-' && privKeyStr[1] == '-')
		{
			priBio = BIO_new_mem_buf(privKeyStr, strlen(privKeyStr));
			if (priBio == NULL)
			{
				ret = 3;
				DEBUG_PRINT("BIO_new_mem_buf Error. \n");
				break;
			}
			pkey = PEM_read_bio_PrivateKey(priBio, NULL, NULL, NULL);
			if (!pkey)
			{
				ret = 4;
				DEBUG_PRINT("PEM_read_bio_PrivateKey Error.\n");
				break;
			}
		}
		else
		{
			privKeyLen = hex2bin(privKeyStr, privKey);
			if (!privKey)
			{
				ret = 2;
				DEBUG_PRINT("Hex To Bin Error.\n");
				break;
			}
			/*pkey = EVP_PKEY_new();
			if (!pkey)
			{
				ret = 3;
				DEBUG_PRINT("EVP_PKEY_new Error.\n");
				break;
			}*/
			priBio = BIO_new_mem_buf(privKey, privKeyLen);
			if (priBio == NULL)
			{
				ret = 3;
				DEBUG_PRINT("BIO_new_mem_buf Error. \n");
				break;
			}
			pkey = d2i_PrivateKey_bio(priBio, NULL);
			if (!pkey)
			{
				ret = 4;
				DEBUG_PRINT("d2i_PrivateKey_bio Error.\n");
				break;
			}
		}


		switch (EVP_PKEY_base_id(pkey))
		{
		case EVP_PKEY_RSA:
			bits = BN_num_bits(RSA_get0_n(pkey->pkey.rsa));
			alg_name = "RSA";
			break;
		case EVP_PKEY_DSA:
			bits = BN_num_bits(DSA_get0_p(pkey->pkey.dsa));
			alg_name = "DSA";
			break;
		case EVP_PKEY_EC:
			bits = EC_GROUP_order_bits(EC_KEY_get0_group(pkey->pkey.ec));
			alg_name = "EC";
			break;
		case EVP_PKEY_SM2:
			bits = EC_GROUP_order_bits(EC_KEY_get0_group(pkey->pkey.ec));
			alg_name = "SM2";
			break;
		default:
			bits = -1;
			alg_name = "Unknown";
			break;
		}

		/*//根据flag生成EVP_PKEY
		if (flag == 1|| flag ==2 || flag ==4) //RSA1024
		{
			//if (!EVP_PKEY_assign_RSA(pkey, d2i_RSAPrivateKey(NULL, (const unsigned char**)&privKey, privKeyLen)))
			if (EVP_PKEY_assign_RSA(pkey, privKey))
			{
				ret = 5;
				DEBUG_PRINT("EVP_PKEY_assign_RSA Error.\n");
				break;
			}
		}
		else if (flag == 3)
		{
			EC_GROUP* sm2group = EC_GROUP_new_by_curve_name(NID_sm2);
			if (!sm2group)
			{
				ret = 6;
				DEBUG_PRINT("EC_GROUP_new_by_curve_name Error.\n");
				break;
			}
			EC_KEY* tmp = CalculateKey((const EC_GROUP*)sm2group, privKey);
			if (!tmp)
			{
				ret = 7;
				DEBUG_PRINT("CalculateKey Error.\n");
				if (sm2group) EC_GROUP_free(sm2group);
				break;
			}
			EVP_PKEY_assign_EC_KEY(pkey, tmp);
			if (sm2group) EC_GROUP_free(sm2group);
		}*/
		ret = 0;

	} while (0);
	if (ret)
	{
		if (pkey)
		{
			EVP_PKEY_free(pkey);
			pkey = NULL;
		}
	}

	return pkey;
}
//将DER私钥转成PEM格式
static int der2pem(unsigned char* der, size_t derLen, char* pem, size_t* pemLen)
{
	//将DER私钥转成PEM格式
	int ret = -1;
	BIO* priBio = NULL;
	EVP_PKEY* pkey = NULL;
	unsigned char* tmp = NULL;
	size_t tmpLen;
	int keyType;
	do
	{
		//参数检查
		if (der == NULL || pem == NULL || pemLen == NULL)
		{
			ret = 1;
			DEBUG_PRINT("Parameter error.\n");
			break;
		}
		//DER转EVP_PKEY
		/*pkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, (const unsigned char**)&der, derLen);
		if (pkey == NULL)
		{
			ret = 2;
			DEBUG_PRINT("d2i_PrivateKey Error.\n");
			break;
		}*/
		priBio = BIO_new_mem_buf(der, derLen);
		if (priBio == NULL)
		{
			ret = 2;
			DEBUG_PRINT("BIO_new_mem_buf Error.\n");
			break;
		}
		pkey = d2i_PrivateKey_bio(priBio, NULL);
		if (!pkey)
		{
			ret = 3;
			DEBUG_PRINT("d2i_PrivateKey_bio Error.\n");
			break;
		}
		BIO_free(priBio); priBio = NULL;

		//EVP_PKEY转PEM
		priBio = BIO_new(BIO_s_mem());
		if (priBio == NULL)
		{
			ret = 4;
			DEBUG_PRINT("BIO_new Error.\n");
			break;
		}

		keyType = EVP_PKEY_base_id(pkey); //获取ID

		switch (keyType)
		{
		case EVP_PKEY_RSA:
			if (!PEM_write_bio_RSAPrivateKey(priBio, pkey->pkey.rsa, NULL, NULL, 0, NULL, NULL))
			{
				ret = 5;
				DEBUG_PRINT("PEM_write_bio_RSAPrivateKey Error.\n");
				break;
			}
			break;
		case EVP_PKEY_DSA:
			if (!PEM_write_bio_DSAPrivateKey(priBio, pkey->pkey.dsa, NULL, NULL, 0, NULL, NULL))
			{
				ret = 5;
				DEBUG_PRINT("PEM_write_bio_DSAPrivateKey Error.\n");
				break;
			}
			break;
		case EVP_PKEY_EC:
		case EVP_PKEY_SM2:
			if (!PEM_write_bio_ECPrivateKey(priBio, pkey->pkey.ec, NULL, NULL, 0, NULL, NULL))
			{
				ret = 5;
				DEBUG_PRINT("PEM_write_bio_ECPrivateKey Error.\n");
				break;
			}
			break;
		default:
			ret = -1;
			DEBUG_PRINT("unknow keyType.\n");
			break;
		}


		tmpLen = BIO_pending(priBio);
		tmp = (unsigned char*)malloc(tmpLen + 1);
		if (tmp == NULL)
		{
			ret = 6;
			DEBUG_PRINT("malloc Error.\n");
			break;
		}
		memset(tmp, 0, tmpLen + 1);
		BIO_read(priBio, tmp, tmpLen);
		//PEM转换成字符串
		memcpy(pem, tmp, tmpLen);
		*pemLen = tmpLen;
		ret = 0;
	} while (0);
	if (tmp)
	{
		free(tmp);
		tmp = NULL;
	}
	if (priBio)
	{
		BIO_free(priBio);
		priBio = NULL;
	}
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	return ret;


}
//将PEM私钥转DER私钥格式
int pem2der(const char* pem, unsigned char* der, size_t* derLen)
{
	int ret = -1;
	EVP_PKEY* pkey = NULL;
	BIO* bio = NULL;
	unsigned char** tmp = NULL;
	size_t tmpLen;
	do
	{
		//参数检查
		if (pem == NULL || der == NULL || derLen == NULL)
		{
			ret = 1;
			DEBUG_PRINT("Parameter error.\n");
			break;
		}
		/*// 创建并读取 PEM 格式的私钥对象
		bio = BIO_new_mem_buf(pem_data, -1);
		if (!bio)
		{
			DEBUG_PRINT("Error creating BIO\n");
			return 0;
		}
		pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
		if (!pkey)
		{
			DEBUG_PRINT("Error reading private key\n");
			BIO_free(bio);
			return 0;
		}
		BIO_free(bio);*/
		pkey = getEvpKey(pem);
		if (!pkey)
		{
			ret = 2;
			DEBUG_PRINT("Error reading private key\n");
			break;
		}
		// 将私钥对象转换为内存中的 DER 编码数据
		tmpLen = i2d_PrivateKey(pkey, NULL);
		if (tmpLen <= 0)
		{
			ret = 3;
			DEBUG_PRINT("Error getting DER length\n");
			break;
		}
		tmp = (unsigned char**)malloc(sizeof(void*));
		if (tmp == NULL)
		{
			ret = 4;
			DEBUG_PRINT("malloc Error.\n");
			break;
		}
		*tmp = (unsigned char*)malloc(tmpLen);
		if (*tmp == NULL)
		{
			ret = 5;
			DEBUG_PRINT("malloc Error.\n");
			break;
		}
		unsigned char* p = *tmp;
		if (i2d_PrivateKey(pkey, &p) != tmpLen)
		{
			ret = 6;
			DEBUG_PRINT("malloc Error.\n");
			break;
		}

		memcpy(der, *tmp, tmpLen);
		*derLen = tmpLen;
		ret = 0;
	} while (0);
	if (*tmp)
	{
		free(*tmp); *tmp = NULL;
	}
	if (tmp)
	{
		free(tmp); tmp = NULL;
	}
	// 释放资源
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	return ret;
}

//使用外送的EVP_PKEY sm2Key进行SM2签名
//data:待签名数据
//dataLen:待签名数据长度
//sign:签名结果
//signLen:签名结果长度
int sm2SignEx(EVP_PKEY* sm2Key, unsigned char* data, size_t dataLen, unsigned char* sign, size_t* signLen)
{
	int ret = -1;
	EC_GROUP* sm2group = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	EVP_MD_CTX* md_ctx = NULL;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned char* out = NULL;
	size_t len;
	int loop, ilen;

	OpenSSL_add_all_algorithms();
	//参数检查
	if (sm2Key == NULL || data == NULL || dataLen == 0 || sign == NULL || signLen == NULL)
	{
		DEBUG_PRINT("Parameter error.\n");
		goto err;
	}

	/*Calculate Z value*/
	len = sizeof(digest);
	if (!ECDSA_sm2_get_Z(EVP_PKEY_get0_EC_KEY(sm2Key), NULL, NULL, 0, digest, &len))
	{
		DEBUG_PRINT("Calculate Z value Error.\n");
		goto err;
	}
#ifdef _DEBUG
	DEBUG_PRINT("Calculate Z-value: [");
	for (loop = 0; loop < len; loop++)
		DEBUG_PRINT("%02X", digest[loop] & 0xff);
	DEBUG_PRINT("]\n");
#endif
	/*Calculate DIGEST*/
	//EVP_MD_CTX_init(md_ctx_ptr);
	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL) {
		DEBUG_PRINT("EVP_MD_CTX_new() fail!\n");
		goto err;
	}
	EVP_SignInit(md_ctx, EVP_sm3());
	EVP_SignUpdate(md_ctx, digest, len);
	EVP_SignUpdate(md_ctx, data, (size_t)strlen((char*)data));
	if (!EVP_SignFinal(md_ctx, NULL, (unsigned int*)&ilen, sm2Key))
	{
		DEBUG_PRINT("Calculate Signature Length error!\n");
		goto err;
	}

	/*ALLOC Sign BUFFER*/
	if (out) OPENSSL_free(out);
	out = (unsigned char*)OPENSSL_malloc(ilen);
	if (!out)
	{
		DEBUG_PRINT("Error of alloc memory.\n");
		goto err;
	}

	/*SIGN*/
	if (!EVP_SignFinal(md_ctx, out, (unsigned int*)&ilen, sm2Key))
	{
		DEBUG_PRINT("Calculate Signature Length error!\n");
		goto err;
	}
	if (ilen > *signLen)
	{
		goto err;
	}
	memcpy(sign, out, ilen);
	*signLen = ilen;
#ifdef _DEBUG
	DEBUG_PRINT("Signature: [");
	for (loop = 0; loop < ilen; loop++)
		DEBUG_PRINT("%02X", out[loop] & 0xff);
	DEBUG_PRINT("]\n");
#endif // _DEBUG
	ret = 0;

err:
	if (sm2group)
	{
		EC_GROUP_free(sm2group);
		sm2group = NULL;
	}
	if (pctx)
	{
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;
	}
	if (out)
	{
		OPENSSL_free(out);
		out = NULL;
	}
	if (md_ctx)
	{
		EVP_MD_CTX_free(md_ctx);
		md_ctx = NULL;
	}

	return ret;
}


int sm2Sign(const char* privKey, unsigned char* data, size_t dataLen, unsigned char* sign, size_t* signLen)
{
	int ret = -1;
	EVP_PKEY* sm2key = NULL;
	EC_GROUP* sm2group = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	EVP_MD_CTX* md_ctx = NULL;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned char* out = NULL;
	size_t len;
	int loop, ilen;
	EC_KEY* tmp = NULL;
	//const char* data = "abc";
	/*if (argc < 2)
	{
		DEBUG_PRINT("Usage: %s testmessage\n", argv[0]);
		exit(0);
	}*/
	do
	{
		OpenSSL_add_all_algorithms();
		//参数检查
		if (privKey == NULL || data == NULL || dataLen == 0 || sign == NULL || signLen == NULL)
		{
			ret = 1;
			DEBUG_PRINT("Parameter error.\n");
			break;
		}
		/*First Generate SM2 Key*/
		sm2key = EVP_PKEY_new();
		if (!sm2key)
		{
			ret = 2;
			DEBUG_PRINT("Alloc EVP_PKEY Object error.\n");
			break;
		}
		sm2group = EC_GROUP_new_by_curve_name(NID_sm2);
		if (!sm2group)
		{
			ret = 3;
			break;
		}
		tmp = CalculateKey((const EC_GROUP*)sm2group, privKey);
		if (!tmp)
		{
			ret = 4;
			break;
		}
		EVP_PKEY_assign_EC_KEY(sm2key, tmp);


		/*OUTPUT EVP PKEY*/
		len = i2d_PrivateKey(sm2key, &out);
		if (len <= 0)
		{
			ret = 5;
			DEBUG_PRINT("Output SM2 Private Key Error.\n");
			break;
		}
#ifdef _DEBUG
		DEBUG_PRINT("Generated SM2 Key: [");
		for (loop = 0; loop < len; loop++)
			DEBUG_PRINT("%02X", out[loop] & 0xff);
		DEBUG_PRINT("]\n");
#endif // _DEBUG

		/*Calculate Z value*/
		len = sizeof(digest);
		if (!ECDSA_sm2_get_Z(EVP_PKEY_get0_EC_KEY(sm2key), NULL, NULL, 0, digest, &len))
		{
			ret = 6;
			DEBUG_PRINT("Calculate Z value Error.\n");
			break;
		}
#ifdef _DEBUG
		DEBUG_PRINT("Calculate Z-value: [");
		for (loop = 0; loop < len; loop++)
			DEBUG_PRINT("%02X", digest[loop] & 0xff);
		DEBUG_PRINT("]\n");
#endif // _DEBUG
		/*Calculate DIGEST*/
		//EVP_MD_CTX_init(md_ctx_ptr);
		md_ctx = EVP_MD_CTX_new();
		if (md_ctx == NULL)
		{
			ret = 7;
			DEBUG_PRINT("EVP_MD_CTX_new() fail!\n");
			break;
		}
		EVP_SignInit(md_ctx, EVP_sm3());
		EVP_SignUpdate(md_ctx, digest, len);
		EVP_SignUpdate(md_ctx, data, (size_t)strlen((char*)data));
		if (!EVP_SignFinal(md_ctx, NULL, (unsigned int*)&ilen, sm2key))
		{
			ret = 8;
			DEBUG_PRINT("Calculate Signature Length error!\n");
			break;
		}

		/*ALLOC Sign BUFFER*/
		if (out) OPENSSL_free(out);
		out = (unsigned char*)OPENSSL_malloc(ilen);
		if (!out)
		{
			ret = 9;
			DEBUG_PRINT("Error of alloc memory.\n");
			break;
		}

		/*SIGN*/
		if (!EVP_SignFinal(md_ctx, out, (unsigned int*)&ilen, sm2key))
		{
			ret = 10;
			DEBUG_PRINT("Calculate Signature Length error!\n");
			break;
		}
		if (ilen > *signLen)
		{
			ret = 11;
			break;
		}
		memcpy(sign, out, ilen);
		*signLen = ilen;
#ifdef _DEBUG
		DEBUG_PRINT("Signature: [");
		for (loop = 0; loop < ilen; loop++)
			DEBUG_PRINT("%02X", out[loop] & 0xff);
		DEBUG_PRINT("]\n");
#endif // _DEBUG

		ret = 0;

	} while (0);

err:
	if (sm2key)
	{
		EVP_PKEY_free(sm2key);
		sm2key = NULL;
	}
	if (sm2group)
	{
		EC_GROUP_free(sm2group);
		sm2group = NULL;
	}
	if (pctx)
	{
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;
	}
	if (out)
	{
		OPENSSL_free(out);
		out = NULL;
	}
	if (md_ctx)
	{
		EVP_MD_CTX_free(md_ctx);
		md_ctx = NULL;
	}

	return ret;
}
int sm2VerifySign(const char* pubKey, unsigned char* data, size_t dataLen, unsigned char* sign, size_t signLen)
{
	int ret = -1;
	EVP_PKEY* sm2key = NULL;
	EC_GROUP* sm2group = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	EVP_MD_CTX* md_ctx = NULL;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned char* out = NULL;
	size_t len;
	int loop;
	EC_KEY* tmp = NULL;
	OpenSSL_add_all_algorithms();

	/*First Generate SM2 Key*/
	sm2key = EVP_PKEY_new();
	if (!sm2key)
	{
		DEBUG_PRINT("Alloc EVP_PKEY Object error.\n");
		goto err;
	}
	sm2group = EC_GROUP_new_by_curve_name(NID_sm2);
	if (!sm2group)
	{
		goto err;
	}
	tmp = CalculatePubKey((const EC_GROUP*)sm2group, pubKey);
	if (!tmp)
	{
		goto err;
	}
	EVP_PKEY_assign_EC_KEY(sm2key, tmp);


	/*OUTPUT EVP PKEY*/
	len = i2d_PublicKey(sm2key, &out);
	if (len <= 0)
	{
		DEBUG_PRINT("Output SM2 Private Key Error.\n");
		goto err;
	}

	DEBUG_PRINT("Generated SM2 Key: [");
	for (loop = 0; loop < len; loop++)
		DEBUG_PRINT("%02X", out[loop] & 0xff);
	DEBUG_PRINT("]\n");

	/*Calculate Z value*/
	len = sizeof(digest);
	if (!ECDSA_sm2_get_Z(EVP_PKEY_get0_EC_KEY(sm2key), NULL, NULL, 0, digest, &len))
	{
		DEBUG_PRINT("Calculate Z value Error.\n");
		goto err;
	}

	DEBUG_PRINT("Calculate Z-value: [");
	for (loop = 0; loop < len; loop++)
		DEBUG_PRINT("%02X", digest[loop] & 0xff);
	DEBUG_PRINT("]\n");


	/*VERIFY*/
	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL) {
		DEBUG_PRINT("EVP_MD_CTX_new() fail!\n");
		goto err;
	}
	EVP_VerifyInit(md_ctx, EVP_sm3());
	EVP_VerifyUpdate(md_ctx, digest, len);
	EVP_VerifyUpdate(md_ctx, data, (size_t)strlen((char*)data));
	if (EVP_VerifyFinal(md_ctx, sign, signLen, sm2key) <= 0)
	{
		DEBUG_PRINT("EVP_PKEY_verify Error.\n");
	}
	else
	{
		DEBUG_PRINT("EVP_PKEY_verify Successed.\n");
	}
	ret = 0;
err:
	if (sm2key)
	{
		EVP_PKEY_free(sm2key);
		sm2key = NULL;
	}
	if (sm2group)
	{
		EC_GROUP_free(sm2group);
		sm2group = NULL;
	}
	if (pctx)
	{
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;
	}
	if (out)
	{
		OPENSSL_free(out);
		out = NULL;
	}
	if (md_ctx)
	{
		EVP_MD_CTX_free(md_ctx);
		md_ctx = NULL;
	}
	return ret;
}

int sm2GenKey(unsigned char* privKey, size_t* privKeyLen, unsigned char* pubKey, size_t* pubKeyLen)
{
	int ret = -1;
	const EC_GROUP* group = NULL;
	EVP_PKEY* sm2key = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	unsigned char* out = NULL;
	size_t len;
	int loop;
	const BIGNUM* bn_priv = NULL;
	//BIGNUM* bn_pub =NULL;
	const EC_POINT* point = NULL;
	int pri_len;
	int pub_len;
	/*First Generate SM2 Key*/
	sm2key = EVP_PKEY_new();
	if (!sm2key)
	{
		DEBUG_PRINT("Alloc EVP_PKEY Object error.\n");
		goto err;
	}

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!pctx)
	{
		DEBUG_PRINT("Create EVP_PKEY_CTX Object error.\n");
		goto err;
	}

	EVP_PKEY_keygen_init(pctx);
	if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2))
	{
		DEBUG_PRINT("Set EC curve name error.\n");
		goto err;
	}

	if (!EVP_PKEY_CTX_set_ec_param_enc(pctx, OPENSSL_EC_NAMED_CURVE))
	{
		DEBUG_PRINT("Set EC curve is named curve error.\n");
		goto err;
	}

	if (EVP_PKEY_keygen(pctx, &sm2key) <= 0)
	{
		DEBUG_PRINT("Generate SM2 key error.\n");
		goto err;
	}

	/*OUTPUT EVP PKEY*/
	len = i2d_PrivateKey(sm2key, &out);
	if (len <= 0)
	{
		DEBUG_PRINT("Output SM2 Private Key Error.\n");
		goto err;
	}

	DEBUG_PRINT("Generated SM2 Private Key ASN1 value: [");
	for (loop = 0; loop < len; loop++)
		DEBUG_PRINT("%02X", out[loop] & 0xff);
	DEBUG_PRINT("]\n");

	if (out) OPENSSL_free(out);
	out = NULL;

	len = i2d_PublicKey(sm2key, &out);
	if (len > 0)
	{
		DEBUG_PRINT("Generated SM2 Public Key ASN1 value: [");
		for (loop = 0; loop < len; loop++)
			DEBUG_PRINT("%02X", out[loop] & 0xff);
		DEBUG_PRINT("]\n");
	}

	if (out) OPENSSL_free(out);
	out = NULL;

	/*OUTPUT X + Y + d*/
	group = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(sm2key));

	/*Output SM2 Key*/
	bn_priv = EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(sm2key));
	//bn_pub=EC_KEY_get0_public_key((EVP_PKEY_get0_EC_KEY(sm2key)));
	point = EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(sm2key));
	pub_len = i2o_ECPublicKey(EVP_PKEY_get0_EC_KEY(sm2key), NULL);
	if (bn_priv == NULL || point == NULL)
	{
		DEBUG_PRINT("EC_KEY_get0_private_key or  EC_KEY_get0_public_key Error.\n");
		goto err;
	}
	pri_len = BN_num_bytes(bn_priv);
	//pub_len = BN_num_bytes(bn_pub);

	if (pri_len > *privKeyLen || pub_len > *pubKeyLen)
	{
		DEBUG_PRINT("Output SM2 Key Error.外送变量内存空间不足\n");
		goto err;
	}

	//将大数转为字节数组
	if (!BN_bn2bin(bn_priv, privKey))
	{
		DEBUG_PRINT("BN_bn2bin err,bn_priv\n");
		goto err;
	}
	*privKeyLen = pri_len;
	if (!i2o_ECPublicKey(EVP_PKEY_get0_EC_KEY(sm2key), &pubKey))
	{
		DEBUG_PRINT("i2o_ECPublicKey err\n");
		goto err;
	}
	*pubKeyLen = pub_len;
#ifdef _DEBUG
	out = (unsigned char*)BN_bn2hex(bn_priv);
	if (!out)
	{
		DEBUG_PRINT("Error Of Output SM2 Private key.\n");
		goto err;
	}

	DEBUG_PRINT("\n              Private Key: [%s]\n", out);
	OPENSSL_free(out);
	out = (unsigned char*)EC_POINT_point2hex(group, EC_KEY_get0_public_key((EVP_PKEY_get0_EC_KEY(sm2key))), POINT_CONVERSION_UNCOMPRESSED, NULL);
	if (!out)
	{
		DEBUG_PRINT("Error Of Output SM2 Public key.\n");
		goto err;
	}
	DEBUG_PRINT("              Public Key: [%s]\n", out);
#endif // DEBUG
	ret = 0;
err:
	if (sm2key)
	{
		EVP_PKEY_free(sm2key);
		sm2key = NULL;
	}
	if (pctx)
	{
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;
	}
	if (out)
	{
		OPENSSL_free(out);
		out = NULL;
	}

	return ret;
}





//EVP RSAsign
int rsaSign(const char* privKeyHex, const char* data, size_t dataLen, unsigned char* sign, size_t* signLen)
{
	int ret = -1;
	EVP_PKEY* pkey = NULL;
	EVP_MD_CTX* mdctx = NULL;
	unsigned char* out = NULL;
	size_t outlen = 0;
	unsigned char privKey[4096] = { 0 };
	size_t privKeyLen = 0;
	if (!privKeyHex || !data || !sign || !signLen)
	{
		DEBUG_PRINT("Input Parameter Error.\n");
		goto err;
	}
	privKeyLen = hex2bin(privKeyHex, privKey);
	if (!privKey)
	{
		DEBUG_PRINT("Hex To Bin Error.\n");
		goto err;
	}
	pkey = EVP_PKEY_new();
	if (!pkey)
	{
		DEBUG_PRINT("EVP_PKEY_new Error.\n");
		goto err;
	}
	//if (!EVP_PKEY_assign_RSA(pkey, d2i_RSAPrivateKey(NULL, (const unsigned char**)&privKey, privKeyLen)))
	if (EVP_PKEY_assign_RSA(pkey, privKey))
	{
		DEBUG_PRINT("EVP_PKEY_assign_RSA Error.\n");
		goto err;
	}
	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
	{
		DEBUG_PRINT("EVP_MD_CTX_create Error.\n");
		goto err;
	}
	if (!EVP_SignInit_ex(mdctx, EVP_sha256(), NULL))
	{
		DEBUG_PRINT("EVP_SignInit_ex Error.\n");
		goto err;
	}
	if (!EVP_SignUpdate(mdctx, data, dataLen))
	{
		DEBUG_PRINT("EVP_SignUpdate Error.\n");
		goto err;
	}
	if (!EVP_SignFinal(mdctx, NULL, &outlen, pkey))
	{
		DEBUG_PRINT("EVP_SignFinal Error.\n");
		goto err;
	}
	out = (unsigned char*)OPENSSL_malloc(outlen);
	if (!out)
	{
		DEBUG_PRINT("OPENSSL_malloc Error.\n");
		goto err;
	}
	if (!EVP_SignFinal(mdctx, out, &outlen, pkey))
	{
		DEBUG_PRINT("EVP_SignFinal Error.\n");
		goto err;
	}
	if (outlen > *signLen)
	{
		DEBUG_PRINT("Output");
	}
	memcpy(sign, out, outlen);
	*signLen = outlen;
err:
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	if (mdctx)
	{
		EVP_MD_CTX_destroy(mdctx);
		mdctx = NULL;
	}
	if (out)
	{
		OPENSSL_free(out);
		out = NULL;
	}
	return ret;
}

//使用外送的EVP_PKEY sm2Key进行RSA签名
int rsaSignEx(EVP_PKEY* rsaKey, const char* data, size_t dataLen, unsigned char* sign, size_t* signLen)
{
	int ret = -1;
	EVP_PKEY* pkey = NULL;
	EVP_MD_CTX* mdctx = NULL;
	unsigned char* out = NULL;
	size_t outlen = 0;
	size_t privKeyLen = 0;
	if (!rsaKey || !data || !sign || !signLen)
	{
		DEBUG_PRINT("Input Parameter Error.\n");
		goto err;
	}
	pkey = rsaKey;
	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
	{
		DEBUG_PRINT("EVP_MD_CTX_create Error.\n");
		goto err;
	}
	if (!EVP_SignInit_ex(mdctx, EVP_sha256(), NULL))
	{
		DEBUG_PRINT("EVP_SignInit_ex Error.\n");
		goto err;
	}
	if (!EVP_SignUpdate(mdctx, data, dataLen))
	{
		DEBUG_PRINT("EVP_SignUpdate Error.\n");
		goto err;
	}
	if (!EVP_SignFinal(mdctx, NULL, &outlen, pkey))
	{
		DEBUG_PRINT("EVP_SignFinal Error.\n");
		goto err;
	}
	out = (unsigned char*)OPENSSL_malloc(outlen);
	if (!out)
	{
		DEBUG_PRINT("OPENSSL_malloc Error.\n");
		goto err;
	}
	if (!EVP_SignFinal(mdctx, out, &outlen, pkey))
	{
		DEBUG_PRINT("EVP_SignFinal Error.\n");
		goto err;
	}
	if (outlen > *signLen)
	{
		DEBUG_PRINT("Output");
	}
	memcpy(sign, out, outlen);
	*signLen = outlen;
err:

	if (mdctx)
	{
		EVP_MD_CTX_destroy(mdctx);
		mdctx = NULL;
	}
	if (out)
	{
		OPENSSL_free(out);
		out = NULL;
	}
	return ret;
}

//EVP RSAverify
int rsaVerifySign(const char* pubKeyHex, const char* data, size_t dataLen, unsigned char* sign, size_t signLen)
{
	int ret = -1;
	EVP_PKEY* pkey = NULL;
	EVP_MD_CTX* mdctx = NULL;
	unsigned char* pubKey = NULL;
	size_t pubKeyLen = 0;
	if (!pubKeyHex || !data || !sign || !signLen)
	{
		DEBUG_PRINT("Input Parameter Error.\n");
		goto err;
	}
	pubKeyLen = hex2bin(pubKeyHex, pubKey);
	if (!pubKey)
	{
		DEBUG_PRINT("Hex To Bin Error.\n");
		goto err;
	}
	pkey = EVP_PKEY_new();
	if (!pkey)
	{
		DEBUG_PRINT("EVP_PKEY_new Error.\n");
		goto err;
	}
	//if (!EVP_PKEY_assign_RSA(pkey, d2i_RSAPublicKey(NULL, (const unsigned char**)&pubKey, pubKeyLen)))
	if (EVP_PKEY_assign_RSA(pkey, pubKey))
	{
		DEBUG_PRINT("EVP_PKEY_assign_RSA Error.\n");
		goto err;
	}
	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
	{
		DEBUG_PRINT("EVP_MD_CTX_create Error.\n");
		goto err;
	}
	if (!EVP_VerifyInit_ex(mdctx, EVP_sha256(), NULL))
	{
		DEBUG_PRINT("EVP_VerifyInit_ex Error.\n");
		goto err;
	}
	if (!EVP_VerifyUpdate(mdctx, data, dataLen))
	{
		DEBUG_PRINT("EVP_VerifyUpdate Error.\n");
		goto err;
	}
	if (EVP_VerifyFinal(mdctx, sign, signLen, pkey) != 1)
	{
		DEBUG_PRINT("EVP_VerifyFinal Error.\n");
		goto err;
	}
	ret = 0;
err:
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	if (mdctx)
	{
		EVP_MD_CTX_destroy(mdctx);
		mdctx = NULL;
	}
	if (pubKey)
	{
		OPENSSL_free(pubKey);
		pubKey = NULL;
	}
	return ret;
}

#include "openssl/rsa.h"
#include <openssl/pkcs7.h>
//EVP RSAGenKey
int rsaGenKey(size_t bits, unsigned char* privKey, size_t* privKeyLen, unsigned char* pubKey, size_t* pubKeyLen)
{
	int ret = -1;
	RSA* rsa = NULL;
	BIGNUM* bne = NULL;
	EVP_PKEY* pkey = NULL;
	BIO* bio = NULL;
	unsigned char* out = NULL;
	size_t outlen = 0;
	if (!privKey || !privKeyLen || !pubKey || !pubKeyLen)
	{
		DEBUG_PRINT("Input Parameter Error.\n");
		goto err;
	}
	bne = BN_new();
	if (!bne)
	{
		DEBUG_PRINT("BN_new Error.\n");
		goto err;
	}
	if (!BN_set_word(bne, RSA_F4))
	{
		DEBUG_PRINT("BN_set_word Error.\n");
		goto err;
	}
	rsa = RSA_new();
	if (!rsa)
	{
		DEBUG_PRINT("RSA_new Error.\n");
		goto err;
	}
	if (!RSA_generate_key_ex(rsa, bits, bne, NULL))
	{
		DEBUG_PRINT("RSA_generate_key_ex Error.\n");
		goto err;
	}
	pkey = EVP_PKEY_new();
	if (!pkey)
	{
		DEBUG_PRINT("EVP_PKEY_new Error.\n");
		goto err;
	}
	if (!EVP_PKEY_assign_RSA(pkey, rsa))
	{
		DEBUG_PRINT("EVP_PKEY_assign_RSA Error.\n");
		goto err;
	}
	bio = BIO_new(BIO_s_mem());
	if (!bio)
	{
		DEBUG_PRINT("BIO_new Error.\n");
		goto err;
	}
	//pKey转换字节bio对象
	if (!i2d_PrivateKey_bio(bio, pkey))
	{
		DEBUG_PRINT("i2d_PrivateKey_bio Error.\n");
		goto err;
	}
	outlen = BIO_pending(bio);
	out = (unsigned char*)OPENSSL_malloc(outlen);
	if (!out)
	{
		DEBUG_PRINT("OPENSSL_malloc Error.\n");
		goto err;
	}
	if (BIO_read(bio, out, outlen) != outlen)
	{
		DEBUG_PRINT("BIO_read Error.\n");
		goto err;
	}
	if (outlen > *privKeyLen)
	{
		DEBUG_PRINT("Output");
	}
	memcpy(privKey, out, outlen);
	*privKeyLen = outlen;
	ret = 0;
err:
	if (bne)
	{
		BN_free(bne);
		bne = NULL;
	}
	if (rsa)
	{
		RSA_free(rsa);
		rsa = NULL;
	}
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	if (bio)
	{
		BIO_free(bio);
		bio = NULL;
	}
	if (out)
	{
		OPENSSL_free(out);
		out = NULL;
	}
	return ret;
}

/*
SM2 加密数据将会产生三个值:
#C1 为随机产生的公钥
#C2 为密文，与明文长度等长
#C3 为 SM3 算法对明文数计算得到消息摘要，长度固定为 256 位

0009-2012 C1|C3|C2
*/
int sm2Encrypt(const char* pubKeyHex, const char* data, size_t dataLen, unsigned char* cipher, size_t* cipherLen)
{
	int ret = -1;
	EVP_PKEY* sm2key = NULL;
	EC_GROUP* sm2group = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	size_t outlen;
	unsigned char* out = NULL;
	int retval;
	EC_KEY* tmp = NULL;
	if (!pubKeyHex || !data || !dataLen || !cipher || !cipherLen)
	{
		DEBUG_PRINT("Input Parameter Error.\n");
		goto err;
	}

	sm2group = EC_GROUP_new_by_curve_name(NID_sm2);
	if (!sm2group)
	{
		goto err;
	}

	sm2key = EVP_PKEY_new();
	if (!sm2key)
	{
		DEBUG_PRINT("Create EVP_PKEY Object Error.\n");
		goto err;
	}

	/*Encrypt*/
	tmp = CalculatePubKey((const EC_GROUP*)sm2group, pubKeyHex);

	if (!tmp)
	{
		DEBUG_PRINT("Error Of Calculate SM2 Public Key.\n");
		goto err;
	}

	EVP_PKEY_assign_EC_KEY(sm2key, tmp);

	if ((EVP_PKEY_set_alias_type(sm2key, EVP_PKEY_SM2)) != 1)
	{
		DEBUG_PRINT("EVP_PKEY_set_alias_type failed.\n");
		goto err;
	}

	pctx = EVP_PKEY_CTX_new(sm2key, NULL);
	if (!pctx)
	{
		DEBUG_PRINT("Create EVP_PKEY_CTX Error.\n");
		goto err;
	}

	if (EVP_PKEY_encrypt_init(pctx) <= 0)
	{
		DEBUG_PRINT("Error Of EVP_PKEY_encrypt_init.\n");
		goto err;
	}

	/*Set SM2 Encrypt EVP_MD. If it not set, SM2 default is EVP_sm3(), Other curve default is sha1*/
	EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_MD, 0, (void*)EVP_sm3());

	/*Set sm2 encdata format, 0 for ASN1(default), 1 for C1C3C2*/
	EVP_PKEY_CTX_set_sm2_encdata_format(pctx, 0);

	//EVP_PKEY_CTX_set_sm2_encdata_format(pctx, 1);

	/*Calculate Cipher Text Length*/
	if (EVP_PKEY_encrypt(pctx, NULL, &outlen, (const unsigned char*)data, dataLen) < 0)
	{
		DEBUG_PRINT("Calculate SM2 Cipher text length error.\n");
		goto err;
	}

	out = (unsigned char*)OPENSSL_malloc(outlen);
	if (!out)
	{
		DEBUG_PRINT("Error Of Alloc memory.\n");
		goto err;
	}

	if (EVP_PKEY_encrypt(pctx, out, &outlen, (const unsigned char*)data, dataLen) < 0)
	{
		DEBUG_PRINT("EVP_PKEY_encrypt error.\n");
		goto err;
	}
	if (outlen > *cipherLen)
	{
		DEBUG_PRINT("Output Buffer Too Small.\n");
		goto err;
	}
	memcpy(cipher, out, outlen);
	*cipherLen = outlen;
	ret = 0;
	/*OK, output cipher*/
	DEBUG_PRINT("SM2 Encrypt Cipher Text:\n\tLength: [%ld]\n\tContent: [", outlen);
	for (retval = 0; retval < outlen; retval++)
		DEBUG_PRINT("%02X", out[retval] & 0xff);
	DEBUG_PRINT("]\n");
err:

	if (sm2key)
	{
		EVP_PKEY_free(sm2key);
		sm2key = NULL;
	}
	if (sm2group)
	{
		EC_GROUP_free(sm2group);
		sm2group = NULL;
	}
	if (pctx)
	{
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;
	}
	if (out)
	{
		OPENSSL_free(out);
		out = NULL;
	}
	return ret;
}



//EVP sm2Decrypt
int sm2Decrypt(const char* privKeyHex, unsigned char* cipher, size_t cipherLen, unsigned char* data, size_t* dataLen)
{
	int ret = -1;
	EVP_PKEY* sm2key = NULL;
	EC_GROUP* sm2group = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	size_t outlen;
	unsigned char* out = NULL;

	EC_KEY* tmp = NULL;
	unsigned char* in = cipher;
	size_t inlen = cipherLen;
	if (!privKeyHex || !data || !dataLen || !cipher || !cipherLen)
	{
		DEBUG_PRINT("Input Parameter Error.\n");
		goto err;
	}

	sm2group = EC_GROUP_new_by_curve_name(NID_sm2);
	if (!sm2group)
	{
		goto err;
	}
	sm2key = EVP_PKEY_new();
	if (!sm2key)
	{
		DEBUG_PRINT("Create EVP_PKEY Object Error.\n");
		goto err;
	}
	/*Decrypt*/
	tmp = CalculateKey((const EC_GROUP*)sm2group, privKeyHex);
	if (!tmp)
	{
		DEBUG_PRINT("Error Of Calculate SM2 Private Key.\n");
		goto err;
	}

	EVP_PKEY_assign_EC_KEY(sm2key, tmp);

	if ((EVP_PKEY_set_alias_type(sm2key, EVP_PKEY_SM2)) != 1)
	{
		DEBUG_PRINT("EVP_PKEY_set_alias_type failed.\n");
		goto err;
	}


	pctx = EVP_PKEY_CTX_new(sm2key, NULL);
	if (!pctx)
	{
		DEBUG_PRINT("Create EVP_PKEY_CTX Error.\n");
		goto err;
	}

	if (EVP_PKEY_decrypt_init(pctx) <= 0)
	{
		DEBUG_PRINT("Error Of EVP_PKEY_encrypt_init.\n");
		goto err;
	}

	/*Set SM2 Encrypt EVP_MD. If it not set, SM2 default is EVP_sm3(), Other curve default is sha1*/
	EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_MD, 0, (void*)EVP_sm3());

	EVP_PKEY_CTX_set_sm2_encdata_format(pctx, 0);
	/*in = OPENSSL_malloc(inlen);
	if (!in)
	{
		DEBUG_PRINT("Error Of Alloc Memory.\n");
		goto err;
	}*/

	//hex2bin(cipher, inlen * 2, in);
	//b2s(argv[3], in);

	/*Set sm2 encdata format, 0 for ASN1(default), 1 for C1C3C2*/
	/*EVP_PKEY_CTX_set_sm2_encdata_format(ctx, 1);*/

	/*Calculate plain text length*/
	if (EVP_PKEY_decrypt(pctx, NULL, &outlen, (const unsigned char*)in, inlen) < 0)
	{
		OPENSSL_free(in);
		DEBUG_PRINT("Calculate SM2 plain text length error.\n");
		goto err;
	}

	out = (unsigned char*)OPENSSL_malloc(outlen);
	if (!out)
	{
		OPENSSL_free(in);
		DEBUG_PRINT("Error Of Alloc Memory.\n");
		goto err;
	}

	memset(out, 0, outlen);
	if (EVP_PKEY_decrypt(pctx, out, &outlen, (const unsigned char*)in, inlen) < 0)
	{
		OPENSSL_free(in);
		DEBUG_PRINT("Error Of EVP_PKEY_decrypt.\n");
		/*Your Can't get error detail*/
		goto err;
	}

	if (outlen > *dataLen)
	{
		DEBUG_PRINT("Output Buffer Too Small.\n");
		goto err;
	}
	memcpy(data, out, outlen);
	*dataLen = outlen;
	ret = 0;
	DEBUG_PRINT("SM2 Decrypt plain Text:\n\tLength: [%ld]\n\tContent: [%s]\n", outlen, (char*)out);
	/*for (retval = 0; retval < outlen; retval++)
		DEBUG_PRINT("%02X", out[retval] & 0xff);
	DEBUG_PRINT("]\n");*/

err:

	if (sm2key)
	{
		EVP_PKEY_free(sm2key);
		sm2key = NULL;
	}
	if (sm2group)
	{
		EC_GROUP_free(sm2group);
		sm2group = NULL;
	}
	if (pctx)
	{
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;
	}
	if (out)
	{
		OPENSSL_free(out);
		out = NULL;
	}
	return ret;
}

//使用外送的EVP_PKEY sm2Key进行SM2解密
int sm2DecryptEx(EVP_PKEY* sm2key, unsigned char* cipher, size_t cipherLen, unsigned char* data, size_t* dataLen)
{
	int ret = -1;
	EC_GROUP* sm2group = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	size_t outlen;
	unsigned char* out = NULL;

	EC_KEY* tmp = NULL;
	unsigned char* in = cipher;
	size_t inlen = cipherLen;
	if (!sm2key || !data || !dataLen || !cipher || !cipherLen)
	{
		DEBUG_PRINT("Input Parameter Error.\n");
		goto err;
	}

	pctx = EVP_PKEY_CTX_new(sm2key, NULL);
	if (!pctx)
	{
		DEBUG_PRINT("Create EVP_PKEY_CTX Error.\n");
		goto err;
	}

	if (EVP_PKEY_decrypt_init(pctx) <= 0)
	{
		DEBUG_PRINT("Error Of EVP_PKEY_encrypt_init.\n");
		goto err;
	}

	/*Set SM2 Encrypt EVP_MD. If it not set, SM2 default is EVP_sm3(), Other curve default is sha1*/
	EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_MD, 0, (void*)EVP_sm3());

	/*in = OPENSSL_malloc(inlen);
	if (!in)
	{
		DEBUG_PRINT("Error Of Alloc Memory.\n");
		goto err;
	}*/

	//hex2bin(cipher, inlen * 2, in);
	//b2s(argv[3], in);

	/*Set sm2 encdata format, 0 for ASN1(default), 1 for C1C3C2*/
	/*EVP_PKEY_CTX_set_sm2_encdata_format(ctx, 1);*/

	/*Calculate plain text length*/
	if (EVP_PKEY_decrypt(pctx, NULL, &outlen, (const unsigned char*)in, inlen) < 0)
	{
		OPENSSL_free(in);
		DEBUG_PRINT("Calculate SM2 plain text length error.\n");
		goto err;
	}

	out = (unsigned char*)OPENSSL_malloc(outlen);
	if (!out)
	{
		OPENSSL_free(in);
		DEBUG_PRINT("Error Of Alloc Memory.\n");
		goto err;
	}

	memset(out, 0, outlen);
	if (EVP_PKEY_decrypt(pctx, out, &outlen, (const unsigned char*)in, inlen) < 0)
	{
		OPENSSL_free(in);
		DEBUG_PRINT("Error Of EVP_PKEY_decrypt.\n");
		/*Your Can't get error detail*/
		goto err;
	}

	if (outlen > *dataLen)
	{
		DEBUG_PRINT("Output Buffer Too Small.\n");
		goto err;
	}
	memcpy(data, out, outlen);
	*dataLen = outlen;
	ret = 0;
	DEBUG_PRINT("SM2 Decrypt plain Text:\n\tLength: [%ld]\n\tContent: [%s]\n", outlen, (char*)out);
	/*for (retval = 0; retval < outlen; retval++)
		DEBUG_PRINT("%02X", out[retval] & 0xff);
	DEBUG_PRINT("]\n");*/

err:
	if (sm2group)
	{
		EC_GROUP_free(sm2group);
		sm2group = NULL;
	}
	if (pctx)
	{
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;
	}
	if (out)
	{
		OPENSSL_free(out);
		out = NULL;
	}

	return ret;
}




// 生成SM2密钥对
EVP_PKEY* generate_sm2_keypair()
{
	EVP_PKEY* pkey = EVP_PKEY_new();
	EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_sm2);
	EC_KEY_generate_key(ec_key);
	EVP_PKEY_assign_EC_KEY(pkey, ec_key);
	return pkey;
}
int sm3(uint8_t* data, uint32_t dataLen, uint8_t* digest, uint32_t* digest_len)
{
	int ret = EXIT_FAILURE;
	EVP_MD_CTX* mdctx = NULL;
	const EVP_MD* md = NULL;


	// 选择 SM3 算法
	md = EVP_sm3();
	if (md == NULL) {
		DEBUG_PRINT("EVP_sm3() failed\n");
		goto cleanup;
	}

	// 创建 MD 上下文对象
	mdctx = EVP_MD_CTX_new();
	if (mdctx == NULL) {
		DEBUG_PRINT("EVP_MD_CTX_new() failed\n");
		goto cleanup;
	}

	// 初始化 MD 上下文对象
	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		DEBUG_PRINT("EVP_DigestInit_ex() failed\n");
		goto cleanup;
	}

	// 输入待计算的数据
	if (EVP_DigestUpdate(mdctx, data, dataLen) != 1) {
		DEBUG_PRINT("EVP_DigestUpdate() failed\n");
		goto cleanup;
	}

	// 完成摘要计算并输出结果
	if (EVP_DigestFinal_ex(mdctx, digest, digest_len) != 1) {
		DEBUG_PRINT("EVP_DigestFinal_ex() failed\n");
		goto cleanup;
	}
#ifdef _DEBUG
	DEBUG_PRINT("SM3 digest: ");
	for (size_t i = 0; i < *digest_len; i++)
	{
		DEBUG_PRINT("%02x", digest[i]);
	}
	DEBUG_PRINT("\n");
#endif // _DEBUG

	ret = EXIT_SUCCESS;

cleanup:
	// 释放资源
	EVP_MD_CTX_free(mdctx);
	return ret;
}
// 对数据进行P7签名
static PKCS7* p7_sign_data(const unsigned char* data, size_t data_len, EVP_PKEY* pkey, X509* cert, size_t flags)
{
	int ret = -1;
	PKCS7* p7 = NULL;
	//PKCS7_set_type(p7, NID_pkcs7_sm2_signed);
	//PKCS7_add_certificate(p7, cert);
	STACK_OF(X509)* certs = NULL;

	//PKCS7_add_certificate(p7, cert);
	//PKCS7_add_certificate(p7, cert);
	//PKCS7_add_signer(p7, pkey, cert, EVP_sm3());
	//PKCS7_content_new(p7, NID_pkcs7_data);
	//PKCS7_set_detached(p7, 1);
	//uint8_t digest[32];
	//uint32_t digest_len;
	//sm3(data,data_len,digest,&digest_len);
	////BIO* in = BIO_new_mem_buf((void*)digest, 32);
	//uint8_t dgst[32];
	//int dgstLen = BIO_read(in, dgst, 32);
	BIO* in = NULL;
	//EVP_PKEY_base_id(pkey); //获取ID
	//int flags = PKCS7_DETACHED | PKCS7_NOCERTS | PKCS7_NOSMIMECAP; //| PKCS7_STREAM | PKCS7_NOCHAIN  | PKCS7_NOSMIMECAP | PKCS7_NOSMIMECAP:不包含加密算法能力集
	do
	{
		//参数检查
		if (!data || !data_len || !pkey || !cert)
		{
			ret = 1;
			DEBUG_PRINT("Invalid input param\n");
			break;
		}
		in = BIO_new_mem_buf(data, data_len);
		if (!in)
		{
			ret = 2;
			DEBUG_PRINT("BIO_new_mem_buf err\n");
			break;
		}
		/*p7 = PKCS7_new();
		if (!p7)
		{
			ret = 3;
			DEBUG_PRINT("PKCS7_new err\n");
			break;
		}*/
		certs = sk_X509_new_null();
		if (!certs)
		{
			ret = 4;
			DEBUG_PRINT("sk_X509_new_null err\n");
			break;
		}
		if (sk_X509_push(certs, cert) < 0)
		{
			ret = 5;
			DEBUG_PRINT("sk_X509_push err\n");
			break;
		}
		p7 = PKCS7_sign(cert, pkey, NULL, in, flags);
		if (!p7)
		{
			ret = 6;
			DEBUG_PRINT("PKCS7_sign error\n");
			break;
		}

#ifdef _DEBUG
		//将p7转为PEM
		BIO* out = BIO_new(BIO_s_mem());
		if (!out)
		{
			ret = 7;
			DEBUG_PRINT("BIO_new error\n");
			break;
		}
		PEM_write_bio_PKCS7(out, p7);
		char* p7_pem = NULL;
		int p7_pem_len = BIO_get_mem_data(out, &p7_pem);
		p7_pem[p7_pem_len] = 0;
		DEBUG_PRINT("p7_pem_len = %d\n", p7_pem_len);
		DEBUG_PRINT("p7_pem = %s\n", p7_pem);
		BIO_free(out);
#endif // DEBUG	
		ret = 0;
	} while (0);

err:
	if (in)
	{
		BIO_free(in);
		in = NULL;
	}
	if (certs)
	{
		sk_X509_free(certs);
		certs = NULL;
	}
	return p7;
}

int sm2SignData(const char* privKeyHex, unsigned char* data, size_t dataLen, size_t flags, unsigned char* pemCert, size_t pemCertLen, unsigned char* signData, size_t* signDataLen)
{
	int ret = -1;
	EVP_PKEY* sm2key = NULL;
	EC_GROUP* sm2group = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	size_t outlen;
	unsigned char* out = NULL;
	int retval;
	EC_KEY* tmp = NULL;
	X509* cert = NULL;
	BIO* certBio = NULL;
	PKCS7* p7 = NULL;
	unsigned char* buf = NULL;
	int len;
	//const char* data = "abc";
	//int data_len= strlen(data);
	do
	{


		if (!privKeyHex || !data || dataLen <= 0 || !pemCert || pemCertLen <= 0 || !signData || !signDataLen || *signDataLen <= 0)
		{
			ret = 1;
			DEBUG_PRINT("Input Parameter Error.\n");
			break;
		}

		sm2group = EC_GROUP_new_by_curve_name(NID_sm2);
		if (!sm2group)
		{
			ret = 2;
			break;
		}
		sm2key = EVP_PKEY_new();
		if (!sm2key)
		{
			ret = 3;
			DEBUG_PRINT("Create EVP_PKEY Object Error.\n");
			break;
		}
		/*Decrypt*/
		tmp = CalculateKey((const EC_GROUP*)sm2group, privKeyHex);
		if (!tmp)
		{
			ret = 4;
			DEBUG_PRINT("Error Of Calculate SM2 Private Key.\n");
			break;
		}

		EVP_PKEY_assign_EC_KEY(sm2key, tmp);

		if ((EVP_PKEY_set_alias_type(sm2key, EVP_PKEY_SM2)) != 1)
		{
			ret = 5;
			DEBUG_PRINT("EVP_PKEY_set_alias_type failed.\n");
			break;
		}

		//使用BIO读取本地证书和密钥
		/*BIO* keyBio = BIO_new_file("./certs/SS.key", "r");
		BIO* certBio = BIO_new_file("./certs/SS.crt", "r");
		if (!keyBio ||!certBio)
		{
			DEBUG_PRINT("read file error \n");
		}*/
		//EVP读取SM2密钥
		//pkey = PEM_read_bio_PrivateKey(keyBio, NULL, NULL, NULL);
		certBio = BIO_new_mem_buf(pemCert, pemCertLen);
		cert = PEM_read_bio_X509(certBio, NULL, 0, NULL);
		if (!certBio || !cert)
		{
			ret = 6;
			DEBUG_PRINT("PEM_read_bio_X509 failed.\n");
			break;
		}


		// 对数据进行P7签名
		p7 = p7_sign_data(data, dataLen, sm2key, cert, flags);
		if (!p7)
		{
			ret = 7;
			DEBUG_PRINT("p7_sign_data failed.\n");
			break;
		}
		ret = 0;

		len = i2d_PKCS7(p7, &buf); // 编码 PKCS7 对象为 DER 格式
		// 现在 buf 中包含编码后的数据，长度为 len
		if (len > *signDataLen)
		{
			ret = 8;
			DEBUG_PRINT("signData buffer is too small.\n");
			break;
		}
		memcpy(signData, buf, len);
		*signDataLen = len;

#ifdef _DEBUG
		// 保存P7签名数据到文件
		FILE* fp = fopen("signed.p7", "wb");
		i2d_PKCS7_fp(fp, p7);
		fclose(fp);
#endif // DEBUG
	} while (0);
err:
	// 释放资源
	if (certBio)
	{
		BIO_free(certBio);
		certBio = NULL;
	}
	if (p7)
	{
		PKCS7_free(p7);
		p7 = NULL;
	}
	if (cert)
	{
		X509_free(cert);
		cert = NULL;
	}
	if (sm2group)
	{
		EC_GROUP_free(sm2group);
		sm2group = NULL;
	}
	if (sm2key)
	{
		EVP_PKEY_free(sm2key);
		sm2key = NULL;
	}
	if (pctx)
	{
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;
	}
	if (buf)
	{
		OPENSSL_free(buf); // 释放临时缓冲区
		buf = NULL;
	}
	return ret;
}

int sm2SignDataEx(EVP_PKEY* sm2key, unsigned char* data, size_t dataLen, size_t flags, unsigned char* pemCert, size_t pemCertLen, unsigned char* signData, size_t* signDataLen)
{
	int ret = -1;
	EC_GROUP* sm2group = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	size_t outlen;
	unsigned char* out = NULL;
	int retval;
	EC_KEY* tmp = NULL;
	X509* cert = NULL;
	BIO* certBio = NULL;
	PKCS7* p7 = NULL;
	unsigned char* buf = NULL;
	int len;
	//const char* data = "abc";
	//int data_len= strlen(data);
	do
	{


		if (!sm2key || !data || dataLen <= 0 || !pemCert || pemCertLen <= 0 || !signData || !signDataLen || *signDataLen <= 0)
		{
			ret = 1;
			DEBUG_PRINT("Input Parameter Error.\n");
			break;
		}

		//使用BIO读取本地证书和密钥
		/*BIO* keyBio = BIO_new_file("./certs/SS.key", "r");
		BIO* certBio = BIO_new_file("./certs/SS.crt", "r");
		if (!keyBio ||!certBio)
		{
			DEBUG_PRINT("read file error \n");
		}*/
		//EVP读取SM2密钥
		//pkey = PEM_read_bio_PrivateKey(keyBio, NULL, NULL, NULL);
		certBio = BIO_new_mem_buf(pemCert, pemCertLen);
		cert = PEM_read_bio_X509(certBio, NULL, 0, NULL);
		if (!certBio || !cert)
		{
			ret = 6;
			DEBUG_PRINT("PEM_read_bio_X509 failed.\n");
			break;
		}


		// 对数据进行P7签名
		p7 = p7_sign_data(data, dataLen, sm2key, cert, flags);
		if (!p7)
		{
			ret = 7;
			DEBUG_PRINT("p7_sign_data failed.\n");
			break;
		}
		ret = 0;

		len = i2d_PKCS7(p7, &buf); // 编码 PKCS7 对象为 DER 格式
		// 现在 buf 中包含编码后的数据，长度为 len
		if (len > *signDataLen)
		{
			ret = 8;
			DEBUG_PRINT("signData buffer is too small.\n");
			break;
		}
		memcpy(signData, buf, len);
		*signDataLen = len;

#ifdef _DEBUG
		// 保存P7签名数据到文件
		FILE* fp = fopen("signed.p7", "wb");
		i2d_PKCS7_fp(fp, p7);
		fclose(fp);
#endif // DEBUG
	} while (0);
err:
	// 释放资源
	if (certBio)
	{
		BIO_free(certBio);
		certBio = NULL;
	}
	if (p7)
	{
		PKCS7_free(p7);
		p7 = NULL;
	}
	if (cert)
	{
		X509_free(cert);
		cert = NULL;
	}
	if (sm2group)
	{
		EC_GROUP_free(sm2group);
		sm2group = NULL;
	}
	if (pctx)
	{
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;
	}
	if (buf)
	{
		OPENSSL_free(buf); // 释放临时缓冲区
		buf = NULL;
	}
	return ret;
}


//添加PEM或者DER格式的证书到证书链中
X509_STORE* addCertToStore(X509_STORE* st, unsigned char* cert, size_t certLen)
{
	int ret = -1;
	X509* x509Cert = NULL;
	BIO* certBio = NULL;
	do
	{
		if (!st || !cert || certLen <= 0)
		{
			ret = 1;
			DEBUG_PRINT("Input Parameter Error.\n");
			break;
		}
		certBio = BIO_new_mem_buf(cert, certLen);
		if (!certBio)
		{
			ret = 2;
			DEBUG_PRINT("BIO_new_mem_buf failed.\n");
			break;
		}

		if (cert[0] == '-' && cert[1] == '-')
		{
			x509Cert = PEM_read_bio_X509(certBio, NULL, 0, NULL);
			if (!x509Cert)
			{
				ret = 3;
				DEBUG_PRINT("PEM_read_bio_X509 err\n");
				break;
			}
		}
		else
		{
			x509Cert = d2i_X509_bio(certBio, NULL);
			if (!x509Cert)
			{
				ret = 3;
				DEBUG_PRINT("d2i_X509_bio err\n");
				break;
			}
		}

		ret = X509_STORE_add_cert(st, x509Cert);
		if (!ret)
		{
			ret = 5;
			DEBUG_PRINT("X509_STORE_add_cert failed.ret:%d\n", ret);
			break;
		}
		ret = 0;
	} while (0);
	if (ret)
	{
		return NULL;
	}
	return st;
}


int sm2VerifySignData(unsigned char* data, size_t dataLen, size_t flags, unsigned char* signCert, size_t signCertLen, unsigned char* signData, size_t signDataLen, X509_STORE* st)
{
	int ret = -1;
	//读取本地文件P7签名文件p7.byte
	STACK_OF(X509)* certs = NULL; // 证书链，使用 sk_X509_push 添加证书
	//X509_STORE* st = NULL;  // 证书存储，使用 X509_STORE_add_cert 添加证书
	BIO* p7Bio = NULL;
	PKCS7* p7 = NULL;
	//读取原文
	BIO* dataBio = NULL;//BIO_new_file("data.txt", "r");
	//读取本地证书
	//BIO* caCertBio = NULL;// BIO_new_file("./certs/CA.crt", "r");
	BIO* certBio = NULL;//BIO_new_file("./certs/SS.crt", "r");

	//X509* caCert = NULL;// PEM_read_bio_X509(caCertBio, NULL, 0, NULL);//d2i_X509_bio(caCertBio, NULL);
	//读取DER编码的证书，certBio
	X509* cert = NULL;// PEM_read_bio_X509(certBio, NULL, 0, NULL);//d2i_X509_bio(certBio, NULL);
	BIO* out_bio = NULL;
	do
	{
		//判断外送参数是否为空
		if (!data || dataLen <= 0 || !signCert || signCertLen <= 0 || !signData || signDataLen <= 0)
		{
			DEBUG_PRINT("Input Parameter Error.\n");
			ret = 1;
			break;
		}
		if ((flags & PKCS7_NOCHAIN) && (flags & PKCS7_NOVERIFY) && !st)	//这个PKCS7_NOVERIFY不验证书链才有效，不知道为啥
		{
			DEBUG_PRINT("st is null.\n");
			ret = 2;
			break;
		}
		//读取data到dataBio
		dataBio = BIO_new_mem_buf(data, dataLen);
		if (!dataBio)
		{
			DEBUG_PRINT("BIO_new_mem_buf err\n");
			ret = 3;
			break;
		}
		//将signData转为BIO	
		p7Bio = BIO_new_mem_buf(signData, signDataLen);
		if (!p7Bio)
		{
			DEBUG_PRINT("BIO_new_mem_buf err\n");
			ret = 3;
			break;
		}


		//判断signData是DER还是PEM格式
		if (signData[0] == '-' && signData[1] == '-')
		{
			//PEM格式
			p7 = PEM_read_bio_PKCS7(p7Bio, NULL, NULL, NULL);
			if (!p7)
			{
				ret = 4;
				DEBUG_PRINT("PEM_read_bio_PKCS7 err\n");
				break;
			}
		}
		else
		{
			//DER格式
			p7 = d2i_PKCS7_bio(p7Bio, NULL);
			if (!p7)
			{
				ret = 4;
				DEBUG_PRINT("d2i_PKCS7_bio err\n");
				break;
			}
		}
		//读取pemCert到cert
		certBio = BIO_new_mem_buf(signCert, signCertLen);
		if (!certBio)
		{
			ret = 5;
			DEBUG_PRINT("BIO_new_mem_buf err\n");
			break;
		}
		if (signCert[0] == '-' && signCert[1] == '-')
		{
			cert = PEM_read_bio_X509(certBio, NULL, 0, NULL);
			if (!cert)
			{
				ret = 6;
				DEBUG_PRINT("PEM_read_bio_X509 err\n");
				break;
			}
		}
		else
		{
			cert = d2i_X509_bio(certBio, NULL);
			if (!cert)
			{
				ret = 6;
				DEBUG_PRINT("d2i_X509_bio err\n");
				break;
			}
		}


		certs = sk_X509_new_null();
		if (!certs)
		{
			ret = 7;
			DEBUG_PRINT("sk_X509_new_null err\n");
			break;
		}

		ret = sk_X509_push(certs, cert);
		if (!ret)
		{
			ret = 8;
			DEBUG_PRINT("sk_X509_push err\n");
			break;
		}
		//验证P7签名	
		out_bio = BIO_new(BIO_s_mem());
		if (p7->d.sign->cert == NULL)
		{
			//p7->d.sign->cert = certs; //为了SM2做Z值计算，必须要有证书链，实际如果P7中没有证书链，可以使用外送的签名证书，但是那样需要改
		}
		ret = PKCS7_verify(p7, certs, st, dataBio, out_bio, flags);
		if (!ret)
		{
			getOpensslErrMsg();
			break;
		}
#ifdef _DEBUG
		DEBUG_PRINT("verify ret = %d\n", ret);
		//打印out_bio里面的数据，输出编码为16进制
		BUF_MEM* mem = NULL;
		BIO_get_mem_ptr(out_bio, &mem);
		for (int i = 0; i < mem->length; i++)
		{
			DEBUG_PRINT("%02x ", mem->data[i]);
		}
		DEBUG_PRINT("\n");

#endif // _DEBUG
		ret = 0;
	} while (0);

	//释放资源
	if (dataBio)
	{
		BIO_free(dataBio);
		dataBio = NULL;
	}
	//if (caCertBio)BIO_free(caCertBio);
	if (certBio)BIO_free(certBio);
	{
		BIO_free(certBio);
		certBio = NULL;
	}
	if (out_bio)
	{
		BIO_free(out_bio);
		out_bio = NULL;
	}
	if (certs)
	{
		sk_X509_free(certs);
		certs = NULL;
	}
	if (cert)
	{
		X509_free(cert);
		cert = NULL;
	}
	//if (caCert)X509_free(caCert);
	if (p7)
	{
		PKCS7_free(p7);
		p7 = NULL;
	}


	return ret;
}



//RSA P7签名
int rsaSignData(const char* privKeyHex, unsigned char* data, size_t dataLen, size_t flags, unsigned char* pemCert, size_t pemCertLen, unsigned char* signData, size_t* signDataLen)
{
	int ret = -1;
	EVP_PKEY* rsakey = NULL;
	EVP_PKEY_CTX* pctx = NULL;
	size_t outlen;
	unsigned char* out = NULL;
	int retval;
	EC_KEY* tmp = NULL;
	X509* cert = NULL;
	BIO* certBio = NULL;
	PKCS7* p7 = NULL;
	unsigned char* buf = NULL;
	int len;
	//const char* data = "abc";
	//int data_len= strlen(data);
	do
	{


		if (!privKeyHex || !data || dataLen <= 0 || !pemCert || pemCertLen <= 0 || !signData || !signDataLen || *signDataLen <= 0)
		{
			ret = 1;
			DEBUG_PRINT("Input Parameter Error.\n");
			break;
		}
		rsakey = getEvpKey(privKeyHex);


		//使用BIO读取本地证书和密钥
		/*BIO* keyBio = BIO_new_file("./certs/SS.key", "r");
		BIO* certBio = BIO_new_file("./certs/SS.crt", "r");
		if (!keyBio ||!certBio)
		{
			DEBUG_PRINT("read file error \n");
		}*/
		//EVP读取SM2密钥
		//pkey = PEM_read_bio_PrivateKey(keyBio, NULL, NULL, NULL);
		certBio = BIO_new_mem_buf(pemCert, pemCertLen);
		cert = PEM_read_bio_X509(certBio, NULL, 0, NULL);
		if (!certBio || !cert)
		{
			ret = 6;
			DEBUG_PRINT("PEM_read_bio_X509 failed.\n");
			break;
		}


		// 对数据进行P7签名
		p7 = p7_sign_data(data, dataLen, rsakey, cert, flags);
		if (!p7)
		{
			ret = 7;
			DEBUG_PRINT("p7_sign_data failed.\n");
			break;
		}
		ret = 0;

		len = i2d_PKCS7(p7, &buf); // 编码 PKCS7 对象为 DER 格式
		// 现在 buf 中包含编码后的数据，长度为 len
		if (len > *signDataLen)
		{
			ret = 8;
			DEBUG_PRINT("signData buffer is too small.\n");
			break;
		}
		memcpy(signData, buf, len);
		*signDataLen = len;

#ifdef _DEBUG
		// 保存P7签名数据到文件
		FILE* fp = fopen("signed_rsa.p7", "wb");
		i2d_PKCS7_fp(fp, p7);
		fclose(fp);
#endif // DEBUG
	} while (0);
err:
	// 释放资源
	if (certBio)
	{
		BIO_free(certBio);
		certBio = NULL;
	}
	if (p7)
	{
		PKCS7_free(p7);
		certBio = NULL;
	}
	if (cert)
	{
		X509_free(cert);
		cert = NULL;
	}
	if (rsakey)
	{
		EVP_PKEY_free(rsakey);
		rsakey = NULL;
	}
	if (pctx)
	{
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;
	}
	if (buf)
	{
		OPENSSL_free(buf); // 释放临时缓冲区
		buf = NULL;
	}
	return ret;
}

//RSA P7签名
int rsaSignDataEx(EVP_PKEY* rsakey, unsigned char* data, size_t dataLen, size_t flags, unsigned char* pemCert, size_t pemCertLen, unsigned char* signData, size_t* signDataLen)
{
	int ret = -1;
	EVP_PKEY_CTX* pctx = NULL;
	size_t outlen;
	unsigned char* out = NULL;
	int retval;
	EC_KEY* tmp = NULL;
	X509* cert = NULL;
	BIO* certBio = NULL;
	PKCS7* p7 = NULL;
	unsigned char* buf = NULL;
	int len;
	//const char* data = "abc";
	//int data_len= strlen(data);
	do
	{


		if (!rsakey || !data || dataLen <= 0 || !pemCert || pemCertLen <= 0 || !signData || !signDataLen || *signDataLen <= 0)
		{
			ret = 1;
			DEBUG_PRINT("Input Parameter Error.\n");
			break;
		}

		certBio = BIO_new_mem_buf(pemCert, pemCertLen);
		cert = PEM_read_bio_X509(certBio, NULL, 0, NULL);
		if (!certBio || !cert)
		{
			ret = 6;
			DEBUG_PRINT("PEM_read_bio_X509 failed.\n");
			break;
		}


		// 对数据进行P7签名
		p7 = p7_sign_data(data, dataLen, rsakey, cert, flags);
		if (!p7)
		{
			ret = 7;
			DEBUG_PRINT("p7_sign_data failed.\n");
			break;
		}
		ret = 0;

		len = i2d_PKCS7(p7, &buf); // 编码 PKCS7 对象为 DER 格式
		// 现在 buf 中包含编码后的数据，长度为 len
		if (len > *signDataLen)
		{
			ret = 8;
			DEBUG_PRINT("signData buffer is too small.\n");
			break;
		}
		memcpy(signData, buf, len);
		*signDataLen = len;

#ifdef _DEBUG
		// 保存P7签名数据到文件
		FILE* fp = fopen("signed.p7", "wb");
		i2d_PKCS7_fp(fp, p7);
		fclose(fp);
		fp = NULL;
#endif // DEBUG
	} while (0);
err:
	// 释放资源
	if (certBio)
	{
		BIO_free(certBio);
		certBio = NULL;
	}
	if (p7)
	{
		PKCS7_free(p7);
		p7 = NULL;
	}
	if (cert)
	{
		X509_free(cert);
		cert = NULL;
	}
	if (pctx)
	{
		EVP_PKEY_CTX_free(pctx);
		pctx = NULL;
	}
	if (buf)
	{
		OPENSSL_free(buf); // 释放临时缓冲区
		buf = NULL;
	}
	return ret;
}

int rsaVerifySignData(unsigned char* data, size_t dataLen, size_t flags, unsigned char* signCert, size_t signCertLen, unsigned char* signData, size_t signDataLen, X509_STORE* st)
{
	int ret = -1;
	//读取本地文件P7签名文件p7.byte
	STACK_OF(X509)* certs = NULL; // 证书链，使用 sk_X509_push 添加证书
	//X509_STORE* st = NULL;  // 证书存储，使用 X509_STORE_add_cert 添加证书
	BIO* p7Bio = NULL;
	PKCS7* p7 = NULL;
	//读取原文
	BIO* dataBio = NULL;//BIO_new_file("data.txt", "r");
	//读取本地证书
	//BIO* caCertBio = NULL;// BIO_new_file("./certs/CA.crt", "r");
	BIO* certBio = NULL;//BIO_new_file("./certs/SS.crt", "r");

	//X509* caCert = NULL;// PEM_read_bio_X509(caCertBio, NULL, 0, NULL);//d2i_X509_bio(caCertBio, NULL);
	//读取DER编码的证书，certBio
	X509* cert = NULL;// PEM_read_bio_X509(certBio, NULL, 0, NULL);//d2i_X509_bio(certBio, NULL);
	BIO* out_bio = NULL;
	do
	{
		//判断外送参数是否为空
		if (!data || dataLen <= 0 || !signCert || signCertLen <= 0 || !signData || signDataLen <= 0)
		{
			DEBUG_PRINT("Input Parameter Error.\n");
			ret = 1;
			break;
		}
		if ((flags & PKCS7_NOCHAIN) && (flags & PKCS7_NOVERIFY) && !st)	//这个PKCS7_NOVERIFY不验证书链才有效，不知道为啥
		{
			DEBUG_PRINT("st is null.\n");
			ret = 2;
			break;
		}
		//读取data到dataBio
		dataBio = BIO_new_mem_buf(data, dataLen);
		if (!dataBio)
		{
			DEBUG_PRINT("BIO_new_mem_buf err\n");
			ret = 3;
			break;
		}
		//将signData转为BIO	
		p7Bio = BIO_new_mem_buf(signData, signDataLen);
		if (!p7Bio)
		{
			DEBUG_PRINT("BIO_new_mem_buf err\n");
			ret = 3;
			break;
		}


		//判断signData是DER还是PEM格式
		if (signData[0] == '-' && signData[1] == '-')
		{
			//PEM格式
			p7 = PEM_read_bio_PKCS7(p7Bio, NULL, NULL, NULL);
			if (!p7)
			{
				ret = 4;
				DEBUG_PRINT("PEM_read_bio_PKCS7 err\n");
				break;
			}
		}
		else
		{
			//DER格式
			p7 = d2i_PKCS7_bio(p7Bio, NULL);
			if (!p7)
			{
				ret = 4;
				DEBUG_PRINT("d2i_PKCS7_bio err\n");
				break;
			}
		}
		//读取pemCert到cert
		certBio = BIO_new_mem_buf(signCert, signCertLen);
		if (!certBio)
		{
			ret = 5;
			DEBUG_PRINT("BIO_new_mem_buf err\n");
			break;
		}
		if (signCert[0] == '-' && signCert[1] == '-')
		{
			cert = PEM_read_bio_X509(certBio, NULL, 0, NULL);
			if (!cert)
			{
				ret = 6;
				DEBUG_PRINT("PEM_read_bio_X509 err\n");
				break;
			}
		}
		else
		{
			cert = d2i_X509_bio(certBio, NULL);
			if (!cert)
			{
				ret = 6;
				DEBUG_PRINT("d2i_X509_bio err\n");
				break;
			}
		}


		certs = sk_X509_new_null();
		if (!certs)
		{
			ret = 7;
			DEBUG_PRINT("sk_X509_new_null err\n");
			break;
		}

		ret = sk_X509_push(certs, cert);
		if (!ret)
		{
			ret = 8;
			DEBUG_PRINT("sk_X509_push err\n");
			break;
		}
		//验证P7签名	
		out_bio = BIO_new(BIO_s_mem());
		if (p7->d.sign->cert == NULL)
		{
			//p7->d.sign->cert = certs; //为了SM2做Z值计算，必须要有证书链，实际如果P7中没有证书链，可以使用外送的签名证书，但是那样需要改
		}
		ret = PKCS7_verify(p7, certs, st, dataBio, out_bio, flags);
		if (!ret)
		{
			getOpensslErrMsg();
			break;
		}
#ifdef _DEBUG
		DEBUG_PRINT("verify ret = %d\n", ret);
		//打印out_bio里面的数据，输出编码为16进制
		BUF_MEM* mem = NULL;
		BIO_get_mem_ptr(out_bio, &mem);
		for (int i = 0; i < mem->length; i++)
		{
			DEBUG_PRINT("%02x ", mem->data[i]);
		}
		DEBUG_PRINT("\n");

#endif // _DEBUG
		ret = 0;
	} while (0);

	//释放资源
	if (dataBio)
	{
		BIO_free(dataBio);
		dataBio = NULL;
	}
	/*if (caCertBio)
	{
		BIO_free(caCertBio);
		caCertBio = NULL;
	}*/
	if (certBio)
	{
		BIO_free(certBio);
		certBio = NULL;
	}
	if (out_bio)
	{
		BIO_free(out_bio);
		out_bio = NULL;
	}
	if (cert)
	{
		X509_free(cert);
		cert = NULL;
	}
	/*if (caCert)
	{
		X509_free(caCert);
		caCert=NULL
	}*/
	if (p7)
	{
		PKCS7_free(p7);
		p7 = NULL;
	}


	return ret;
}
void testP7()
{
	//smime -verify -inform DER -in signed.p7 -content data.txt -CAfile ./certs/CA.crt
	int ret = 0;
	const char* privKeyHex = "363ffcaa72c0c728e9b2c5d16f840258edb98d803b90395c4e77c44a2c7090fa";
	const char* pubKeyHex = "04e20234542883f1f007c1d008a5251c537e64aae2c456d4f2c44c1dfc15be1e19382e05792fba09d68e32e85cd8362d6233ccabba5a5e5426983747766921c35e";
	const char* data = "abc";
	size_t dataLen = strlen(data);
	unsigned char signData[4096] = { 0 };
	size_t signDataLen = 4096;
	unsigned char cert[4096] = { 0 };
	size_t certLen = 4096;
	unsigned char caCert[4096] = { 0 };
	size_t caCertLen = 4096;
	int flags = PKCS7_NOSMIMECAP | PKCS7_NOCERTS | PKCS7_DETACHED;// | PKCS7_NOATTR; //|  PKCS7_DETACHED  | PKCS7_NOCERTS| PKCS7_STREAM | PKCS7_NOCHAIN  | PKCS7_NOSMIMECAP | PKCS7_NOSMIMECAP:不包含加密算法能力集
	FILE* fp = fopen("./certs/SS.crt", "rb");
	certLen = fread(cert, 1, 4096, fp);
	fclose(fp);
	BIO* certBio = NULL;
	X509_STORE* st = NULL;
	st = X509_STORE_new();
	if (!st)
	{
		ret = 9;
		DEBUG_PRINT("X509_STORE_new err\n");
		return;
	}
	certBio = BIO_new_file("./certs/CA.crt", "r");//BIO_new_file("./certs/CA.crt", "r");
	if (!certBio)
	{
		ret = 9;
		DEBUG_PRINT("BIO_new_file err\n");
		X509_STORE_free(st);
		return;
	}
	caCertLen = BIO_read(certBio, caCert, 4096);
	BIO_free(certBio); certBio = NULL;
	st = addCertToStore(st, caCert, caCertLen);
	if (!st)
	{
		ret = 10;
		DEBUG_PRINT("addCertToStore err\n");
		X509_STORE_free(st);
		return;
	}
	//smime  -sign -in data.txt -outform der -signer "E:\vs2022workspace\testOpenssl\testOpenssl\certs\SS.crt" -inkey  "E:\vs2022workspace\testOpenssl\testOpenssl\certs\SS.key" -out signature.p7s
	//SM2 P7签名
	ret = sm2SignData(privKeyHex, (unsigned char*)data, dataLen, flags, cert, certLen, signData, &signDataLen);
	if (ret)
	{
		DEBUG_PRINT("sm2SignData err,ret:%08x\n", ret);
		X509_STORE_free(st);
		return;
	}
	flags = 0;// PKCS7_NOVERIFY;// PKCS7_DETACHED | PKCS7_NOCHAIN | PKCS7_NOSMIMECAP; //| PKCS7_STREAM
	//flags = PKCS7_NOCHAIN | PKCS7_NOCRL;
	//SM2 P7验签
	ret = sm2VerifySignData((unsigned char*)data, dataLen, flags, cert, certLen, signData, signDataLen, st);
	if (ret)
	{
		DEBUG_PRINT("sm2VerifySignData err,ret:%08x\n", ret);
		X509_STORE_free(st);
		return;
	}



	certBio = BIO_new_file("./certs/caroot.cer", "r");//BIO_new_file("./certs/CA.crt", "r");
	if (!certBio)
	{
		ret = 9;
		DEBUG_PRINT("BIO_new_file err\n");
		X509_STORE_free(st);
		return;
	}
	caCertLen = BIO_read(certBio, caCert, 4096);
	BIO_free(certBio); certBio = NULL;
	st = addCertToStore(st, caCert, caCertLen);
	if (!st)
	{
		ret = 10;
		DEBUG_PRINT("addCertToStore err\n");
		X509_STORE_free(st);
		return;
	}
	certBio = BIO_new_file("./certs/root.cer", "r");//BIO_new_file("./certs/CA.crt", "r");
	if (!certBio)
	{
		ret = 9;
		DEBUG_PRINT("BIO_new_file err\n");
		X509_STORE_free(st);
		return;
	}
	caCertLen = BIO_read(certBio, caCert, 4096);
	BIO_free(certBio); certBio = NULL;
	st = addCertToStore(st, caCert, caCertLen);
	if (!st)
	{
		ret = 10;
		DEBUG_PRINT("addCertToStore err\n");
		X509_STORE_free(st);
		return;
	}

	//
	fp = fopen("F:/桌面/030000001213.cer", "rb");
	certLen = fread(cert, 1, 4096, fp);
	fclose(fp);

	char dataStr[4096] = { 0 };
	int dataStrLen = 4096;
	fp = fopen("data.txt", "rb");
	dataStrLen = fread(dataStr, 1, 4096, fp);
	fclose(fp);
	fp = fopen("F:/桌面/p7byte1", "rb");
	signDataLen = fread(signData, 1, 4096, fp);
	fclose(fp);
	//SM2 P7验签

	ret = sm2VerifySignData((unsigned char*)dataStr, dataStrLen, flags, cert, certLen, signData, signDataLen, st);
	if (ret)
	{
		DEBUG_PRINT("sm2VerifySignData err,ret:%08x\n", ret);
		return;
	}

}


void testRsaP7()
{
	int ret = 0;
	const char* privKeyHex = "308204A50201000282010100DDAC43CD36CBF9565B2B1F6BA88EEBA83823B60F759136FF84682838CA5E51BA26B4BBA34AB00C2EA1D2CEE87DFEEEE8C5FEDA721E1B4C5C53A1BFB63F4819A8880AFE4919E9E8ACBCA9362DFB3AFBDC648B84E1A491DF13AC98DD1074331FA21D7CD73F609581C0E45710E15F7637B4C751945B80FAA5838DCD2610407EE7E3D067F0BC47FBD0DAEAAB7BF392FB04F689771F16CF18183B1826499767CEABA46210BAC673538536DFA2EB638E3505AEB7ED4A784DE52EC3BF04CB090CB9451C7BDF4D8F160EC5656A0A92B15E342DF113EFC74290C364C166CA4D479AFC24AE9D17263DE52E42A37564996376C8DBFC8054D9BC4A328CF8728796671F71ADDB02030100010282010100D21D7F06FD71CA1D78BD1F4344BA73D537A161E8B55FB7E9EAEF6F70A521520648B9F7418881E68A2D094CE642C76A5D698F702FCB29C4EF9EB62AA9ECC1C2D064634734B3436C308F8334BFD0EACFE0CFCD0F5F724672548BBD398D67172E5CD3E68980A1641561690EBE09621B04226EEB7CDC5F1D35D5C48B38111F912AEA99616A6320121FE7F6C997C985A3A11825D1E2ADAC6E1575D3B37ACDF4F63260EB4A2CD7E8E21F83AE693F059CA12667915DDA7C919C5ADA2C05818F350BC0018CC7F8CEB53BA20573DEE7753463525D1D7ACE418477EF7D36F68BF9D025EDF72C6310D73D78B8E2970C9D96C8AFA0D46A8E97DA9E395A60A91CC1F0B3D5BC8102818100FAEF81667B92416217DDC8E861623CAAC9BA98DF08DDCEEAF736672B5A14E40CB996A9B75536BFCBE052CCDBAD433BF4527429316ECD738922013D3F432399F7C7D8C84DF395B12D2DA636B1A622AF3E7512765506B7B7A7F6162A457FBBEB7F6F526FE9ADC892C9981208A9962186F0766AB42F5A71058006A7C86A01C0812902818100E22591D59B664BF1A87FA2CF772C0653B2E73FD50128E77AC0882C00721085B9A00E9F35DD6B7F88AD6E97BA3D4B515B7B2D51D4527A7C876F38D74167187FDDEEE69DF4078FA1E9E0EB6AD9CA1993CBB5CF95FA9DD218D1AC9FF2ACCCD1EB3160C2E90ED323EBF0596B45C658C3A5576C71E69BD8A0F4312984F6C7FAE2436302818100C2176CCC5AFA364E6C4D64AFB15B6DB7604F4F1CFC5BAC477BAD7DC13F6CF7338C7D278AA183B678386B72FEDB962C927F105028671ECCA59E42BD1FE88B69F50883F9F2A95CF86D0C690AD6FFBCC635961210AB158616ACF8A00E543147A610AC8763FEA82782BA214099A8AA7206508A1760855BFC1D97F80DE0EB75AD7379028180563B7936788133683C961EE0F952423F5C32ADB66D30C9C396F2D5C47DBA2B23B312A0470BDD57CE2843C97B6CAFF19FEE824377B0D39FF48CC6A1DE008FE902197CBAB238C7DE37AE5A566E21904B391C64C18DC4EC3E2685AAA000A041536B8AB807E26D447F4D30EBA4B993535712D4F941B41F90904CC6C63ACBDAB0B87D02818100CDE91D8793C1137F1AFDA608EC08AFCA65B6F7E8D02C65B4EF448AF81F4284E8FF68C270E1A509625253F257A63E3E4E52F03A475A58052E991270F9C95FA497258C9133A07547E1F82D68845B7ECFC17249CA491C34BBAD61C42CA88AAE750FE0A37FA870713FA04068E46DF0D5D42AF2DC1402539FCD1034BFDB0A6F70EE36";
	const char* pubKeyHex = "30820122300D06092A864886F70D01010105000382010F003082010A0282010100DDAC43CD36CBF9565B2B1F6BA88EEBA83823B60F759136FF84682838CA5E51BA26B4BBA34AB00C2EA1D2CEE87DFEEEE8C5FEDA721E1B4C5C53A1BFB63F4819A8880AFE4919E9E8ACBCA9362DFB3AFBDC648B84E1A491DF13AC98DD1074331FA21D7CD73F609581C0E45710E15F7637B4C751945B80FAA5838DCD2610407EE7E3D067F0BC47FBD0DAEAAB7BF392FB04F689771F16CF18183B1826499767CEABA46210BAC673538536DFA2EB638E3505AEB7ED4A784DE52EC3BF04CB090CB9451C7BDF4D8F160EC5656A0A92B15E342DF113EFC74290C364C166CA4D479AFC24AE9D17263DE52E42A37564996376C8DBFC8054D9BC4A328CF8728796671F71ADDB0203010001";
	const char* data = "abc";
	size_t dataLen = strlen(data);
	unsigned char signData[4096] = { 0 };
	size_t signDataLen = 4096;
	unsigned char cert[4096] = { 0 };
	size_t certLen = 4096;
	unsigned char caCert[4096] = { 0 };
	size_t caCertLen = 4096;
	int flags = PKCS7_NOSMIMECAP | PKCS7_NOCERTS | PKCS7_DETACHED;// | PKCS7_NOATTR; //|  PKCS7_DETACHED  | PKCS7_NOCERTS| PKCS7_STREAM | PKCS7_NOCHAIN  | PKCS7_NOSMIMECAP | PKCS7_NOSMIMECAP:不包含加密算法能力集
	FILE* fp = fopen("./certs/rsa2048.cer", "rb");
	certLen = fread(cert, 1, 4096, fp);
	fclose(fp);
	BIO* certBio = NULL;
	X509_STORE* st = NULL;
	st = X509_STORE_new();
	if (!st)
	{
		ret = 9;
		DEBUG_PRINT("X509_STORE_new err\n");
		return;
	}
	certBio = BIO_new_file("./certs/rsa2048.cer", "r");//BIO_new_file("./certs/CA.crt", "r");
	if (!certBio)
	{
		ret = 9;
		DEBUG_PRINT("BIO_new_file err\n");
		X509_STORE_free(st);
		return;
	}
	caCertLen = BIO_read(certBio, caCert, 4096);
	BIO_free(certBio); certBio = NULL;
	st = addCertToStore(st, caCert, caCertLen);
	if (!st)
	{
		ret = 10;
		DEBUG_PRINT("addCertToStore err\n");
		X509_STORE_free(st);
		return;
	}
	//smime  -sign -in data.txt -outform der -signer "E:\vs2022workspace\testOpenssl\testOpenssl\certs\SS.crt" -inkey  "E:\vs2022workspace\testOpenssl\testOpenssl\certs\SS.key" -out signature.p7s
	//RSA P7签名
	ret = rsaSignData(privKeyHex, (unsigned char*)data, dataLen, flags, cert, certLen, signData, &signDataLen);
	if (ret)
	{
		DEBUG_PRINT("rsaSignData err,ret:%08x\n", ret);
		X509_STORE_free(st);
		return;
	}
	flags = 0;// PKCS7_NOVERIFY;// PKCS7_DETACHED | PKCS7_NOCHAIN | PKCS7_NOSMIMECAP; //| PKCS7_STREAM
	//flags = PKCS7_NOCHAIN | PKCS7_NOCRL;
	//SM2 P7验签
	ret = rsaVerifySignData((unsigned char*)data, dataLen, flags, cert, certLen, signData, signDataLen, st);
	if (ret)
	{
		DEBUG_PRINT("rsaVerifySignData err,ret:%08x\n", ret);
		X509_STORE_free(st);
		st = NULL;
		return;
	}


	/*
	certBio = BIO_new_file("./certs/caroot.cer", "r");//BIO_new_file("./certs/CA.crt", "r");
	if (!certBio)
	{
		ret = 9;
		DEBUG_PRINT("BIO_new_file err\n");
		X509_STORE_free(st);
		return;
	}
	caCertLen = BIO_read(certBio, caCert, 4096);
	BIO_free(certBio); certBio = NULL;
	st = addCertToStore(st, caCert, caCertLen);
	if (!st)
	{
		ret = 10;
		DEBUG_PRINT("addCertToStore err\n");
		X509_STORE_free(st);
		return;
	}
	certBio = BIO_new_file("./certs/root.cer", "r");//BIO_new_file("./certs/CA.crt", "r");
	if (!certBio)
	{
		ret = 9;
		DEBUG_PRINT("BIO_new_file err\n");
		X509_STORE_free(st);
		return;
	}
	caCertLen = BIO_read(certBio, caCert, 4096);
	BIO_free(certBio); certBio = NULL;
	st = addCertToStore(st, caCert, caCertLen);
	if (!st)
	{
		ret = 10;
		DEBUG_PRINT("addCertToStore err\n");
		X509_STORE_free(st);
		return;
	}

	//
	fp = fopen("F:/桌面/030000001213.cer", "rb");
	certLen = fread(cert, 1, 4096, fp);
	fclose(fp);

	char dataStr[4096] = { 0 };
	int dataStrLen = 4096;
	fp = fopen("data.txt", "rb");
	dataStrLen = fread(dataStr, 1, 4096, fp);
	fclose(fp);
	fp = fopen("F:/桌面/p7byte1", "rb");
	signDataLen = fread(signData, 1, 4096, fp);
	fclose(fp);
	//SM2 P7验签

	ret = sm2VerifySignData(dataStr, dataStrLen, flags, cert, certLen, signData, signDataLen, st);
	if (ret)
	{
		DEBUG_PRINT("sm2VerifySignData err,ret:%08x\n", ret);
		return;
	}*/

}

void testEvpKey()
{
	int ret = 0;
	const char* privKeyHex = "30770201010420363FFCAA72C0C728E9B2C5D16F840258EDB98D803B90395C4E77C44A2C7090FAA00A06082A811CCF5501822DA14403420004E20234542883F1F007C1D008A5251C537E64AAE2C456D4F2C44C1DFC15BE1E19382E05792FBA09D68E32E85CD8362D6233CCABBA5A5E5426983747766921C35E";// "363ffcaa72c0c728e9b2c5d16f840258edb98d803b90395c4e77c44a2c7090fa";
	const char* pubKeyHex = "04e20234542883f1f007c1d008a5251c537e64aae2c456d4f2c44c1dfc15be1e19382e05792fba09d68e32e85cd8362d6233ccabba5a5e5426983747766921c35e";
	const char* data = "abc";
	size_t dataLen = strlen(data);
	unsigned char signData[4096] = { 0 };
	size_t signDataLen = 4096;
	EVP_PKEY* key = NULL;
	do
	{
		key = getEvpKey(privKeyHex);
		ret = sm2SignEx(key, (unsigned char*)data, dataLen, signData, &signDataLen);
		if (ret)
		{
			DEBUG_PRINT("sm2SignEx err,ret:%08x\n", ret);
			return;
		}
	} while (0);

	if (key)
	{
		EVP_PKEY_free(key); key = NULL;
	}
}
void getSM2Key()
{
	char sm2KeyPem[1024] = { 0 };
	size_t sm2KeyPemLen = 1024;
	unsigned char sm2Key[1024] = { 0 };
	size_t sm2KeyLen = 1024;
	BIO* pemFile = NULL;
	char* sm2HexStr = NULL;

	do
	{
		pemFile = BIO_new_file("./certs/SS.key", "r");
		if (!pemFile)
		{
			DEBUG_PRINT("BIO_new_file err\n");
			break;
		}
		//读取pemFile内容
		sm2KeyPemLen = BIO_read(pemFile, sm2KeyPem, 1024);



		if (pem2der(sm2KeyPem, sm2Key, &sm2KeyLen))
		{
			DEBUG_PRINT("pem2der err\n");
			break;
		}
		sm2HexStr = bin2hex(sm2Key, sm2KeyLen);
		DEBUG_PRINT("sm2HexStr:%s\n", sm2HexStr);
		memset(sm2KeyPem, 0, sizeof(sm2KeyPem));
		sm2KeyPemLen = 1024;
		if (der2pem(sm2Key, sm2KeyLen, sm2KeyPem, &sm2KeyPemLen))
		{
			DEBUG_PRINT("der2pem err\n");
			break;
		}
		DEBUG_PRINT("sm2KeyPem:%s\n", sm2KeyPem);

	} while (0);
	if (pemFile)
	{
		BIO_free(pemFile); pemFile = NULL;
	}
	if (sm2HexStr)
	{
		OPENSSL_free(sm2HexStr);
		sm2HexStr = NULL;
	}
	return;
}

#include <openssl/asn1t.h>
typedef struct my_struct_st
{
	ASN1_INTEGER* field1;
	ASN1_OCTET_STRING* field2;
	ASN1_UTCTIME* field3;
} my_struct;
ASN1_SEQUENCE(my_struct) = {
	ASN1_SIMPLE(my_struct, field1, ASN1_INTEGER),
	ASN1_OPT(my_struct, field2, ASN1_OCTET_STRING),
	ASN1_OPT(my_struct, field3, ASN1_UTCTIME)
} ASN1_SEQUENCE_END(my_struct);

DECLARE_ASN1_FUNCTIONS(my_struct);
IMPLEMENT_ASN1_FUNCTIONS(my_struct);

void testAsn1()
{
	//编一个测试数据的my_struct
	my_struct* my = NULL;
	my = my_struct_new();
	my->field1 = ASN1_INTEGER_new();
	ASN1_INTEGER_set(my->field1, 123);
	my->field2 = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(my->field2, (const unsigned char*)"abc", 3);
	my->field3 = ASN1_UTCTIME_new();
	ASN1_UTCTIME_set_string(my->field3, "2208141005Z");
	//编码
	unsigned char* der = NULL;
	int derLen = i2d_my_struct(my, &der);
	unsigned char buf[1024] = { 0 }; /* ASN.1 编码后的数据 */
	memcpy(buf, der, derLen);
	/*if (der)
	{
		OPENSSL_free(der); der = NULL;
	}*/
#ifdef _DEBUG
	BIO* fileBios = BIO_new_file("my_syruct.pin", "wb");
	if (!fileBios)
	{
		DEBUG_PRINT("BIO_new_file err\n");
		return;
	}
	BIO_write(fileBios, buf, derLen);
	BIO_free(fileBios); fileBios = NULL;
#endif // _DEBUG

	//解码
	my_struct* my2 = NULL;
	my2 = d2i_my_struct(NULL, (const unsigned char**)&der, derLen);
	//释放
	if (my)
	{
		my_struct_free(my); my = NULL;
	}
	if (my2)
	{
		my_struct_free(my2); my2 = NULL;
	}
	/*if (der) //无需释放
	{
		OPENSSL_free(der); der = NULL;
	}*/
	return;
}
#include "certIndex.h"
#include <openssl/x509v3.h>

int long2uchar(long num, unsigned char* buf, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		buf[i] = (num >> ((len - i - 1) * 8)) & 0xFF;
	}
	return len;
}

//根据不同的索引号，解析外送的DER、PEM格式的证书
//infoFlag:0:info为普通数据	1：info为DER编码数据	2：iInfo数据，即unsigned int 数据
static int getCertInfo(unsigned char* cert, size_t certLen, size_t index, long* iInfo, unsigned char* info, size_t* infoLen,size_t* infoFlag)
{
	int ret = 0;
	X509* x509Cert = NULL;
	unsigned char* der = NULL;
	unsigned char* buf = NULL;
	int derlen=0;
	do
	{
		//检查参数
		if (!cert || !certLen || !info || !infoLen)
		{
			ret = 1;
			DEBUG_PRINT("param err\n");
			break;
		}
		//判断signData是DER还是PEM格式
		if (cert[0] == '-' && cert[1] == '-')
		{
			//解析外送的PEM格式的证书
			BIO* bio = NULL;
			bio = BIO_new_mem_buf(cert, certLen);
			if (!bio)
			{
				ret = 2;
				DEBUG_PRINT("BIO_new_mem_buf err\n");
				break;
			}
			x509Cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
			if (!x509Cert)
			{
				ret = 3;
				DEBUG_PRINT("PEM_read_bio_X509 err\n");
				break;
			}
			BIO_free(bio); bio = NULL;
		}
		else
		{
			//解析外送的DER、PEM、Base64、Hex格式的证书
			x509Cert = d2i_X509(NULL, (const unsigned char**)&cert, certLen);
			if (!x509Cert)
			{
				ret = 4;
				DEBUG_PRINT("d2i_X509 err\n");
				break;
			}
		}

		der = (unsigned char*)OPENSSL_malloc(certLen);
		if (!der)
		{
			ret = 5;
			DEBUG_PRINT("OPENSSL_malloc err\n");
			break;
		}
		buf = der;

		//获取证书信息
		switch (index)
		{
		case DEC_INDEX_VERSION: //版本号
		{
			long version = 0;
			version = X509_get_version(x509Cert);
			if (version < 0)
			{
				ret = -1;
				DEBUG_PRINT("X509_get_version err\n");
				break;
			}
			*iInfo = version;
			derlen = long2uchar(version, buf,sizeof(long));
			if (derlen <= 0)
			{
				ret = -1;
				DEBUG_PRINT("long2uchar err\n");
				break;
			}
			*infoFlag = 2;
			break;
		}
		
		case DEC_INDEX_SERIALNUMBER: //Serial Number
		{
			ASN1_INTEGER* serialNumber = NULL;
			serialNumber = X509_get_serialNumber(x509Cert);
			if (!serialNumber)
			{
				ret = index;
				DEBUG_PRINT("X509_get_serialNumber err\n");
				break;
			}
			derlen = i2d_ASN1_INTEGER(serialNumber, &buf);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("i2d_ASN1_INTEGER err\n");
				break;
			}
			derlen -= 2;
			memmove(der, der + 2, derlen);//去除tl
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_INT_SIGNALGID: //int 值签名算法
		{
			const X509_ALGOR* sigAlg=NULL;
			const char* algorithm_name;
			// 获取签名算法
			sigAlg = X509_get0_tbs_sigalg(x509Cert);
			if (!sigAlg)
			{
				ret = index;
				DEBUG_PRINT("X509_get0_tbs_sigalg err\n");
				break;
			}
			algorithm_name = OBJ_nid2ln(OBJ_obj2nid(sigAlg->algorithm));
			if (!algorithm_name)
			{
				ret = index;
				DEBUG_PRINT("OBJ_nid2ln err\n");
				break;
			}
			*iInfo = OBJ_obj2nid(sigAlg->algorithm);
			derlen = 0; //无需复制
			*infoFlag = 2;
			break;
		}
		
		case DEC_INDEX_STRING_SIGNALGID: // str 签名算法
		{
			const X509_ALGOR* sigAlg = NULL;
			const char* algorithm_name;
			// 获取签名算法
			sigAlg = X509_get0_tbs_sigalg(x509Cert);
			if (!sigAlg)
			{
				ret = index;
				DEBUG_PRINT("X509_get0_tbs_sigalg err\n");
				break;
			}
			algorithm_name = OBJ_nid2ln(OBJ_obj2nid(sigAlg->algorithm));
			if (!algorithm_name)
			{
				ret = index;
				DEBUG_PRINT("OBJ_nid2ln err\n");
				break;
			}
			memcpy(buf,algorithm_name,strlen(algorithm_name));
			derlen = strlen(algorithm_name);
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_COUNTRYNAME: //颁发者国家名称
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_countryName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_ORGANIZATIONNAME: //颁发者组织机构名称
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_organizationName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_ORGANIZATIONUNITNAME: //颁发者组织机构单元名称
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_organizationalUnitName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_STATEORPROVINCENAME: //颁发者州或省名称
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_stateOrProvinceName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_COMMONNAME: //颁发者通用名称
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_commonName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_LOCALITYNAME: //颁发者地理位置名称
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_localityName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_TITLE: //颁发者头衔
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_title, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		
		case DEC_INDEX_ISSUER_SURNAME://颁发者姓
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_surname, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_GIVENNAME://颁发者名
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_givenName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_INITIALS://颁发者首字母
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_initials, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_EMAILADDRESS: //颁发者电子邮件地址
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_pkcs9_emailAddress, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_POSTALADDRESS: //颁发者邮政地址
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_postalAddress, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		
		case DEC_INDEX_ISSUER_POSTALBOX://颁发者信箱
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_pseudonym, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_POSTALCODE: //颁发者邮政编码
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_postalCode, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		
		case DEC_INDEX_ISSUER_TELEPHONENUMBER://颁发者电话号码
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = index;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_pkcs9_unstructuredName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_NOTBEFORE: //证书有效期起始时间
		{
			ASN1_TIME* notBefore = NULL;
			notBefore = X509_get_notBefore(x509Cert);
			if (!notBefore)
			{
				ret = index;
				DEBUG_PRINT("X509_get_notBefore err\n");
				break;
			}
			derlen = i2d_ASN1_TIME(notBefore, &buf);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("i2d_ASN1_TIME err\n");
				break;
			}
			derlen -= 2;
			memmove(der, der + 2, derlen);//去除tl
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_NOTAFTER://证书有效期截至时间
		{
			ASN1_TIME* notAfter = NULL;
			notAfter = X509_get_notAfter(x509Cert);
			if (!notAfter)
			{
				ret = index;
				DEBUG_PRINT("X509_get_notAfter err\n");
				break;
			}
			derlen = i2d_ASN1_TIME(notAfter, &buf);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("i2d_ASN1_TIME err\n");
				break;
			}
			derlen -= 2;
			memmove(der, der + 2, derlen); //去除tl
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_SUBJECT_COUNTRYNAME://主题国家
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_countryName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}

		case DEC_INDEX_SUBJECT_ORGANIZATIONNAME://主题组织名称
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_organizationName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}


		case DEC_INDEX_SUBJECT_STATEORPROVINCENAME://主题省份
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_stateOrProvinceName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_SUBJECT_ORGANIZATIONALUNITNAME://主题部门名称
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_organizationalUnitName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_SUBJECT_COMMONNAME://主题通用名称
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_commonName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_SUBJECT_LOCALITYNAME://主题地区名称
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_localityName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_SUBJECT_TITLE://主题标题，头衔
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_title, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		
		case DEC_INDEX_SUBJECT_SURNAME: //姓
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_surname, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_SUBJECT_GIVENNAME: //名
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_givenName, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_SUBJECT_INITIALS: //主题首字母
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_initials, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_SUBJECT_EMAIL:
		case DEC_INDEX_SUBJECT_EMAILADDRESS: //邮箱
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_pkcs9_emailAddress, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_SUBJECT_STREETADDRESS: //街道地址
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_streetAddress, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_SUBJECT_POSTALOFFICEBOX:
		{
			ret = DEC_INDEX_SUBJECT_POSTALOFFICEBOX;
			DEBUG_PRINT("DEC_INDEX_SUBJECT_POSTALOFFICEBOX err\n");
			break;
		}
		case DEC_INDEX_SUBJECT_POSTALCODE: //邮政编码
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = 17;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_postalCode, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = 17;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		
		case DEC_INDEX_SUBJECT_TELEPHONENUMBER: //电话号码
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_telephoneNumber, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		
		case DEC_INDEX_SUBJECT_FACSIMILETELEPHONENUMBER://传真号码
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_facsimileTelephoneNumber, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}		

		case DEC_INDEX_DERPUBKEY: //public key
		case DEC_INDEX_USRPUBKEY: //public key
		{
			/* 获取证书公钥 */
			X509_PUBKEY* pubkey = NULL;
			pubkey = X509_get_X509_PUBKEY(x509Cert);
			if (pubkey == NULL)
			{
				ret = 39;
				DEBUG_PRINT("Error: failed to get public key from certificate\n");
				break;
			}
			/* 将公钥转换为 DER 编码格式 */
			derlen = i2d_X509_PUBKEY(pubkey, &buf);
			if (derlen < 0)
			{
				ret = 39;
				DEBUG_PRINT("Error: failed to convert public key to DER format\n");
			}
			*infoFlag = 2;
			break;
		}
		////颁发者唯一ID
		//case DEC_INDEX_ISSUER_UNIQUEID:
		//{
		//	//获取证书颁发者唯一ID
		//	// 获取扩展 "authorityKeyIdentifier"
		//	X509_EXTENSION* extension = X509_get_ext(x509Cert, X509_get_ext_by_NID(x509Cert, NID_authority_key_identifier, -1));
		//	if (extension == NULL) 
		//	{
		//		ret = index;
		//		DEBUG_PRINT("找不到颁发者密钥标识符 (Authority Key Identifier) 扩展\n");
		//		break;
		//	}

		//	// 解析扩展数据
		//	ASN1_OCTET_STRING* akid_octet_str = X509_EXTENSION_get_data(extension);
		//	if (akid_octet_str == NULL) 
		//	{
		//		ret = index;
		//		DEBUG_PRINT("无法获取颁发者密钥标识符 (Authority Key Identifier) 扩展数据\n");
		//		break;
		//	}
		//	// 将证书颁发者唯一ID转换为 DER 编码格式 
		//	derlen = i2d_ASN1_OCTET_STRING(akid_octet_str, &buf);
		//	if (derlen < 0)
		//	{
		//		ret = index;
		//		DEBUG_PRINT("Error: failed to convert subject key identifier to DER format\n");
		//	}
		//	derlen -= 6;
		//	memmove(der, der + 6, derlen);//去除tl
		//	*infoFlag = 0;
		//	break;
		//	/*const ASN1_BIT_STRING* issuerUniqueId = NULL;
		//	const ASN1_BIT_STRING* subjectUniqueId = NULL;
		//	X509_NAME* issuer = NULL;
		//	issuer = X509_get_issuer_name(x509Cert);
		//	if (!issuer)
		//	{
		//		ret = index;
		//		DEBUG_PRINT("X509_get_issuer_name err\n");
		//		break;
		//	}
		//	// 获取颁发者唯一ID字段
		//	X509_get0_uids(x509Cert,&issuerUniqueId,&issuerUniqueId);
		//	if (issuerUniqueId != NULL)
		//	{
		//		derlen = ASN1_STRING_length(issuerUniqueId);
		//		if (derlen <= 0)
		//		{
		//			ret = index;
		//			DEBUG_PRINT("ASN1_STRING_length err\n");
		//			break;
		//		}
		//		memcpy(buf, ASN1_STRING_get0_data(issuerUniqueId), derlen);
		//	}
		//	else
		//	{
		//		ret = index;
		//		DEBUG_PRINT("X509_get0_uids err\n");
		//		break;
		//	}*/
		//}
		//
		//case DEC_INDEX_SUBJECT_UNIQUEID: //主题唯一ID
		//{
		//	/* 获取证书主题唯一ID */
		//	// 获取扩展 "NID_subject_key_identifier"
		//	X509_EXTENSION* extension = X509_get_ext(x509Cert, X509_get_ext_by_NID(x509Cert, NID_subject_key_identifier, -1));
		//	if (extension == NULL)
		//	{
		//		ret = index;
		//		DEBUG_PRINT("找不到持有者密钥标识符 (Authority Key Identifier) 扩展\n");
		//		break;
		//	}

		//	// 解析扩展数据
		//	ASN1_OCTET_STRING* akid_octet_str = X509_EXTENSION_get_data(extension);
		//	if (akid_octet_str == NULL)
		//	{
		//		ret = index;
		//		DEBUG_PRINT("无法获取持有者密钥标识符 (Authority Key Identifier) 扩展数据\n");
		//		break;
		//	}
		//	// 将证书颁发者唯一ID转换为 DER 编码格式 
		//	derlen = i2d_ASN1_OCTET_STRING(akid_octet_str, &buf);
		//	if (derlen < 0)
		//	{
		//		ret = index;
		//		DEBUG_PRINT("Error: failed to convert subject key identifier to DER format\n");
		//	}
		//	derlen -= 4;
		//	memmove(der, der + 4, derlen);//去除tl
		//	*infoFlag = 0;
		//	break;
		//	/*const ASN1_BIT_STRING* subjectUniqueId = NULL;
		//	X509_NAME* subject = NULL;
		//	subject = X509_get_subject_name(x509Cert);
		//	if (!subject)
		//	{
		//		ret = index;
		//		DEBUG_PRINT("X509_get_subject_name err\n");
		//		break;
		//	}
		//	// 获取主题唯一ID字段
		//	X509_get0_uids(x509Cert,&subjectUniqueId,&subjectUniqueId);
		//	if (subjectUniqueId != NULL)
		//	{
		//		derlen = ASN1_STRING_length(subjectUniqueId);
		//		if (derlen <= 0)
		//		{
		//			ret = index;
		//			DEBUG_PRINT("ASN1_STRING_length err\n");
		//			break;
		//		}
		//		memcpy(buf, ASN1_STRING_get0_data(subjectUniqueId), derlen);
		//	}
		//	else
		//	{
		//		ret = index;
		//		DEBUG_PRINT("X509_get0_uids err\n");
		//		break;
		//	}*/
		//}
		//密钥用法
		case DEC_INDEX_KEYUSAGE:
		{
			// 获取扩展 "keyUsage"
			X509_EXTENSION* extension = X509_get_ext(x509Cert, X509_get_ext_by_NID(x509Cert, NID_key_usage, -1));
			if (extension == NULL) 
			{
				ret = index;
				DEBUG_PRINT("找不到密钥用法 (Key Usage) 扩展\n");
				break;
			}

			// 解析扩展数据
			ASN1_BIT_STRING* key_usage_bitstr = X509_EXTENSION_get_data(extension);
			if (key_usage_bitstr == NULL) 
			{
				ret = index;
				DEBUG_PRINT("无法获取密钥用法 (Key Usage) 扩展数据\n");
				break;
			}

			// 将扩展数据解析为整数
			unsigned int UNUSED_BITS;
			unsigned long key_usage_flags = 0;
			//key_usage_flags = ASN1_BIT_STRING_get_bit(key_usage_bitstr, 0); //
			key_usage_flags = key_usage_bitstr->data[3];
			UNUSED_BITS= key_usage_bitstr->data[2]; //未使用的比特位数
			*iInfo = key_usage_flags;
			*infoFlag = 2;
#ifdef _DEBUG

			// 打印密钥用法
			printf("密钥用法 (Key Usage)：\n");
			if (key_usage_flags & KU_DIGITAL_SIGNATURE)
				DEBUG_PRINT("- 数字签名\n");
			if (key_usage_flags & KU_NON_REPUDIATION)
				DEBUG_PRINT("- 非否认\n");
			if (key_usage_flags & KU_KEY_ENCIPHERMENT)
				DEBUG_PRINT("- 密钥加密\n");
			if (key_usage_flags & KU_DATA_ENCIPHERMENT)
				DEBUG_PRINT("- 数据加密\n");
			if (key_usage_flags & KU_KEY_AGREEMENT)
				DEBUG_PRINT("- 密钥协商\n");
			if (key_usage_flags & KU_KEY_CERT_SIGN)
				DEBUG_PRINT("- 密钥证书签名\n");
			if (key_usage_flags & KU_CRL_SIGN)
				DEBUG_PRINT("- CRL 签名\n");
			if (key_usage_flags & KU_ENCIPHER_ONLY)
				DEBUG_PRINT("- 仅加密\n");
			if (key_usage_flags & KU_DECIPHER_ONLY)
				DEBUG_PRINT("- 仅解密\n");
#endif // _DEBUG
			break;
		}
		
		
		
		case DEC_INDEX_SUBJECT_GENERATIONQUALIFIER: //主题生成限定符
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = 15;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_generationQualifier, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = 15;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			break;
		}
		case DEC_INDEX_ISSUER_GENERATIONQUALIFIER://颁发者代际限定符
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = 1;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_generationQualifier, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = 1;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}

			break;
		}
		case DEC_INDEX_SUBJECT: //Subject
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = 2;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = i2d_X509_NAME(subject, &buf);
			if (derlen <= 0)
			{
				ret = 2;
				DEBUG_PRINT("i2d_X509_NAME err\n");
				break;
			}
			*infoFlag = 1;
			break;
		}
		case DEC_INDEX_ISSUER: //Issuer 
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = 1;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = i2d_X509_NAME(issuer, &buf);
			if (derlen <= 0)
			{
				ret = 1;
				DEBUG_PRINT("i2d_X509_NAME err\n");
				break;
			}
			*infoFlag = 1;
			break;
		}
		

		case DEC_INDEX_DEREXTENSION: //扩展
		{
			/* 获取证书扩展 */
			X509_EXTENSION* ext = NULL;
			ext = X509_get_ext(x509Cert, NULL);
			if (ext == NULL)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to get extension from certificate\n");
				break;
			}
			/* 将扩展转换为 DER 编码格式 */
			derlen = i2d_X509_EXTENSION(ext, &buf);
			if (derlen < 0)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to convert extension to DER format\n");
			}
			*infoFlag = 1;
			break;
		}
		case DEC_INDEX_AUTHORITYINFOACCESS: //颁发者信息访问地址 OCSP
		{
			/* 获取证书颁发者信息访问地址 */
			STACK_OF(ACCESS_DESCRIPTION)* authorityInfoAccess = NULL;
			authorityInfoAccess = (STACK_OF(ACCESS_DESCRIPTION)*)X509_get_ext_d2i(x509Cert, NID_info_access, NULL, NULL);
			if (authorityInfoAccess == NULL)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to get authority info access from certificate\n");
				break;
			}
			for (int i = 0; i < sk_ACCESS_DESCRIPTION_num((STACK_OF(ACCESS_DESCRIPTION)*)authorityInfoAccess); i++)
			{
				ACCESS_DESCRIPTION* accessDecription = sk_ACCESS_DESCRIPTION_value(authorityInfoAccess, i);
				/* 将颁发者信息访问地址转换为 DER 编码格式 */
				derlen = i2d_ACCESS_DESCRIPTION(accessDecription, &buf);
				if (derlen < 0)
				{
					ret = index;
					DEBUG_PRINT("Error: failed to convert authority info access to DER format\n");
				}
				buf = der + derlen;
			}
			*infoFlag = 1;
			break;
		}
		case DEC_INDEX_SUBJECT_UNIQUEID:
		case DEC_INDEX_SUBJECTKEYID:
		case DEC_INDEX_SUBJECTKEYIDENTIFIER: //主题密钥标识符
		{
			/* 获取证书主题密钥标识符 */
			ASN1_OCTET_STRING* subjectKeyIdentifier = NULL;
			subjectKeyIdentifier = (ASN1_OCTET_STRING*)X509_get_ext_d2i(x509Cert, NID_subject_key_identifier, NULL, NULL);
			if (subjectKeyIdentifier == NULL)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to get subject key identifier from certificate\n");
				break;
			}
			/* 将主题密钥标识符转换为 DER 编码格式 */
			derlen = i2d_ASN1_OCTET_STRING(subjectKeyIdentifier, &buf);
			if (derlen < 0)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to convert subject key identifier to DER format\n");
			}
			derlen -= 2;
			memmove(der, der + 2, derlen);//去除tl
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_UNIQUEID:
		case DEC_INDEX_AUTHORITYKEYIDENTIFIER: //颁发者密钥标识符
		{
			/* 获取证书颁发者密钥标识符 */
			AUTHORITY_KEYID* authorityKeyIdentifier = NULL;
			
			authorityKeyIdentifier = (AUTHORITY_KEYID*)X509_get_ext_d2i(x509Cert, NID_authority_key_identifier, NULL, NULL);
			if (authorityKeyIdentifier == NULL)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to get authority key identifier from certificate\n");
				break;
			}
			
			/* 将颁发者密钥标识符转换为 DER 编码格式 */
			derlen = i2d_AUTHORITY_KEYID(authorityKeyIdentifier, &buf);
			if (derlen < 0)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to convert authority key identifier to DER format\n");
			}
			derlen -= 4;
			memmove(der, der + 4, derlen);//去除tl
			*infoFlag = 0;
			break;
		}
		
		case DEC_INDEX_SUBJECTALTNAME://使用者可选名称
		case DEC_INDEX_SUBJECTALTERNATIVENAME: //主题备用名称
		{
			/* 获取证书主题备用名称 */
			GENERAL_NAMES* subjectAltName = NULL;
			subjectAltName = (GENERAL_NAMES*)X509_get_ext_d2i(x509Cert, NID_subject_alt_name, NULL, NULL);
			if (subjectAltName == NULL)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to get subject alt name from certificate\n");
				break;
			}
			/* 将主题备用名称转换为 DER 编码格式 */
			derlen = i2d_GENERAL_NAMES(subjectAltName, &buf);
			if (derlen < 0)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to convert subject alt name to DER format\n");
			}
			*infoFlag = 1;
			break;
		}
		case DEC_INDEX_BASICCONSTRAINTS: //基本约束
		{
			/* 获取证书基本约束 */
			BASIC_CONSTRAINTS* basicConstraints = NULL;
			basicConstraints = (BASIC_CONSTRAINTS*)X509_get_ext_d2i(x509Cert, NID_basic_constraints, NULL, NULL);
			if (basicConstraints == NULL)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to get basic constraints from certificate\n");
				break;
			}
			/* 将基本约束转换为 DER 编码格式 */
			derlen = i2d_BASIC_CONSTRAINTS(basicConstraints, &buf);
			if (derlen < 0)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to convert basic constraints to DER format\n");
			}
			*infoFlag = 0;
			break;
		}

		case DEC_INDEX_ISSUERALTERNATIVENAME: //颁发者备用名称
		{
			/* 获取证书颁发者备用名称 */
			GENERAL_NAMES* issuerAltName = NULL;
			issuerAltName = (GENERAL_NAMES*)X509_get_ext_d2i(x509Cert, NID_issuer_alt_name, NULL, NULL);
			if (issuerAltName == NULL)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to get issuer alt name from certificate\n");
				break;
			}
			/* 将颁发者备用名称转换为 DER 编码格式 */
			derlen = i2d_GENERAL_NAMES(issuerAltName, &buf);
			if (derlen < 0)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to convert issuer alt name to DER format\n");
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_CRLNUMBER: //CRL 号码
		{
			/* 获取证书 CRL 号码 */
			ASN1_INTEGER* crlNumber = NULL;
			crlNumber = (ASN1_INTEGER*)X509_get_ext_d2i(x509Cert, NID_crl_number, NULL, NULL);
			if (crlNumber == NULL)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to get crl number from certificate\n");
				break;
			}
			/* 将 CRL 号码转换为 DER 编码格式 */
			derlen = i2d_ASN1_INTEGER(crlNumber, &buf);
			if (derlen < 0)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to convert crl number to DER format\n");
			}
			break;
		}
		case DEC_INDEX_CRLREASON: //CRL 原因
		{
			/* 获取证书 CRL 原因 */
			ASN1_ENUMERATED* crlReason = NULL;
			crlReason = (ASN1_ENUMERATED*)X509_get_ext_d2i(x509Cert, NID_crl_reason, NULL, NULL);
			if (crlReason == NULL)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to get crl reason from certificate\n");
				break;
			}
			/* 将 CRL 原因转换为 DER 编码格式 */
			derlen = i2d_ASN1_ENUMERATED(crlReason, &buf);
			if (derlen < 0)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to convert crl reason to DER format\n");
			}
			break;
		}
		case DEC_INDEX_CRLDISTRIBUTIONPOINTS: //CRL 分发点
		{
			/*X509_EXTENSION* exts = NULL;
			//获取证书 CRL 分发点 
			STACK_OF(DIST_POINT)* crlDistributionPoints = NULL;
			crlDistributionPoints = (STACK_OF(DIST_POINT)*)X509_get_ext_d2i(x509Cert, NID_crl_distribution_points, NULL, NULL);
			if (crlDistributionPoints == NULL)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to get CRL distribution points from certificate\n");
				break;
			}
			derlen = 0;
			for (int i = 0; i < sk_DIST_POINT_num((STACK_OF(DIST_POINT)*)crlDistributionPoints); i++)
			{
				///buf = der + derlen;
				DIST_POINT* dp = sk_DIST_POINT_value(crlDistributionPoints, i);
				//derlen = i2d_DIST_POINT(dp, &buf); //这样只能一个一个写，而不是完整的DER
				GENERAL_NAMES* names = dp->distpoint->name.fullname;

				for (int j = 0; j < sk_GENERAL_NAME_num(names); j++)
				{
					GENERAL_NAME* name = sk_GENERAL_NAME_value(names, j);

					if (name->type == GEN_URI)
					{
						printf("CRL 分发点 URL: %s\n", name->d.uniformResourceIdentifier->data);
					}
				}
			}
			if (crlDistributionPoints)
			{
				sk_DIST_POINT_pop_free(crlDistributionPoints, DIST_POINT_free);
			}*/

			//以下实现和openssl内部实现差不多，都是匹配NID，返回完整的DER编码数据
			X509_CRL* crl = NULL;
			STACK_OF(X509_EXTENSION)* extensions=NULL;
			int idx;
			// 获取扩展列表
			extensions = (STACK_OF(X509_EXTENSION)*)X509_get0_extensions(x509Cert);
			if (extensions == NULL) 
			{
				printf("No extensions found in the certificate.\n");
				ret= index;
				break;
			}
			derlen = 0; //如果没有找到后续也不会赋值
			// 查找 CRL 分发点扩展
			for (idx = 0; idx < sk_X509_EXTENSION_num(extensions); idx++) 
			{
				X509_EXTENSION* ext = sk_X509_EXTENSION_value(extensions, idx);
				if (ext)
				{
					ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
					if (OBJ_obj2nid(obj) == NID_crl_distribution_points)
					{
						ASN1_OCTET_STRING* extoct = X509_EXTENSION_get_data(ext);
						//i2a_ASN1_OBJECT(bp, obj);
						//derlen = i2d_BASIC_CONSTRAINTS(ext, &buf);
						derlen= extoct->length;
						memcpy(buf, extoct->data, extoct->length);
						// 释放资源,不能释放，此指针实际是证书里的数据
						//X509_EXTENSION_free(ext);
						break;
					}
				}			
			}
			// 释放整个扩展堆栈,不能释放，此指针实际是证书里的数据
			//sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
			/*//以下和上述第一种实现类似，可打印具体的数据，但是不能合并DER编码数据
			int crl_dp_index;
			X509_EXTENSION* crl_dp_ext;
			STACK_OF(DIST_POINT)* crl_dp_stack;

			// Load the X509 certificate
			// ...

			// Get the index of the CRL distribution points extension
			crl_dp_index = X509_get_ext_by_NID(x509Cert, NID_crl_distribution_points,NULL);

			if (crl_dp_index == -1) {
				// The CRL distribution points extension is not present in the certificate
				// ...
			}
			else {
				// Get the CRL distribution points extension
				crl_dp_ext = X509_get_ext(x509Cert, crl_dp_index);

				if (crl_dp_ext == NULL) {
					// Error getting the CRL distribution points extension
					// ...
				}
				else {
					// Parse the CRL distribution points extension
					crl_dp_stack = (STACK_OF(DIST_POINT)*)X509V3_EXT_d2i(crl_dp_ext);

					if (crl_dp_stack == NULL) {
						// Error parsing the CRL distribution points extension
						// ...
					}
					else 
					{
						DIST_POINT* crl_dp;
						// Iterate over the CRL distribution points
						for (int i = 0; i < sk_DIST_POINT_num(crl_dp_stack); i++) {
							DIST_POINT* dp = sk_DIST_POINT_value(crl_dp_stack, i);
							GENERAL_NAMES* names = dp->distpoint->name.fullname;

							for (int j = 0; j < sk_GENERAL_NAME_num(names); j++) {
								GENERAL_NAME* name = sk_GENERAL_NAME_value(names, j);

								if (name->type == GEN_URI) {
									printf("CRL 分发点 URL: %s\n", name->d.uniformResourceIdentifier->data);
								}
							}
						}

						// Free the CRL distribution points stack
						sk_DIST_POINT_pop_free(crl_dp_stack, DIST_POINT_free);
					}
				}
			}
			*/
			* infoFlag = 1;
			break;
		}
		case DEC_INDEX_CERTIFICATEPOLICIES: //证书策略
		{
			/* 获取证书证书策略 */
			STACK_OF(POLICYINFO*) certificatePolicies = NULL;
			certificatePolicies = (STACK_OF(POLICYINFO*))X509_get_ext_d2i(x509Cert, NID_certificate_policies, NULL, NULL);
			if (certificatePolicies == NULL)
			{
				ret = index;
				DEBUG_PRINT("Error: failed to get certificate policies from certificate\n");
				break;
			}
			for (int i = 0; i < sk_POLICYINFO_num((const STACK_OF(POLICYINFO)*)certificatePolicies); i++)
			{
				POLICYINFO* certificatePolicie= sk_POLICYINFO_value((const STACK_OF(POLICYINFO)*)certificatePolicies, i);
				ASN1_OBJECT* policyIdentifier = certificatePolicie->policyid;
				/* 将证书策略转换为 DER 编码格式 */
				derlen = i2d_POLICYINFO(certificatePolicie, &buf);
				if (derlen < 0)
				{
					ret = index;
					DEBUG_PRINT("Error: failed to convert certificate policies to DER format\n");
				}			
				buf = der + derlen;
			}
			*infoFlag = 1;
			break;
		}
		

		case DEC_INDEX_ISSUER_FACSIMILETELEPHONENUMBER: //颁发者传真号码
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = 1;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_favouriteDrink, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = 1;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_ISSUER_BUSINESSCATEGORY: //颁发者商业类别
		{
			X509_NAME* issuer = NULL;
			issuer = X509_get_issuer_name(x509Cert);
			if (!issuer)
			{
				ret = 1;
				DEBUG_PRINT("X509_get_issuer_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(issuer, NID_businessCategory, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = 1;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		case DEC_INDEX_SUBJECT_BUSINESSCATEGORY: //商业类别
		{
			X509_NAME* subject = NULL;
			subject = X509_get_subject_name(x509Cert);
			if (!subject)
			{
				ret = index;
				DEBUG_PRINT("X509_get_subject_name err\n");
				break;
			}
			derlen = X509_NAME_get_text_by_NID(subject, NID_businessCategory, (char*)buf, certLen);
			if (derlen <= 0)
			{
				ret = index;
				DEBUG_PRINT("X509_NAME_get_text_by_NID err\n");
				break;
			}
			*infoFlag = 0;
			break;
		}
		default:
			ret = -1;
			//DEBUG_PRINT("Error: invalid index number\n");
			break;
		}
		if (!ret)
		{
#ifdef _DEBUG
			char* inofHexStr = bin2hex(der, derlen);
			if (inofHexStr)
			{
				der[derlen] = 0;
				DEBUG_PRINT("index:%d,info:%s\ninofHexStr:%s", index, (char*)der,inofHexStr);
				if (inofHexStr)
				{
					free(inofHexStr);
					inofHexStr = NULL;
				}
			}	
			else
			{
				DEBUG_PRINT("index:%d,iInfo:%d", index, *iInfo);
			}
#endif // _DEBUG
			if (*infoLen > derlen)
			{
				if (derlen>0)
				{
					memcpy(info, der, derlen);
					*infoLen = derlen;
				}		
			}
			else
			{
				ret = 2;
				DEBUG_PRINT("Error: failed to convert public key to DER format\n");
				break;
			}
		}
	} while (0);

	if (x509Cert)
	{
		X509_free(x509Cert);
		x509Cert = NULL;
	}
	if (der)
	{
		free(der);
		der = NULL;
	}

	return ret;
}
#include "crypto/asn1.h"
void parse_der_data2(const unsigned char* der_data, int der_length) 
{
	const unsigned char* p = der_data;
	long len;
	int tag, pclass;

	while (der_length > 0) 
	{
		int ret = ASN1_get_object(&p, &len, &tag, &pclass, der_length);

		if (ret < 0)//& 0x80) {
		{
			fprintf(stderr, "Error parsing DER data\n");
			return;
		}
		if (true)
		{

		}
		printf("值：");
		for (int i = 0; i < len; i++) {
			printf("%02X", p[i]);
		}
		printf("\n");

		p += len;
		der_length -= len;
	}
}


void traverse_der_data(const unsigned char* der_data, int der_length) 
{
	const unsigned char* p = der_data;
	long len;
	int tag, pclass;

	while (p - der_data < der_length) {
		int ret = ASN1_get_object(&p, &len, &tag, &pclass, der_length);

		if (ret & 0x80)
		{
			fprintf(stderr, "Error parsing DER data\n");
			return;
		}

		// 打印标签和长度
		printf("标签：%d，长度：%ld\n", tag, len);

		// 解析 CONSTRUCTED 类型
		if (pclass == V_ASN1_CONSTRUCTED) 
		{
			traverse_der_data(p, len);  // 递归解析值部分
		}
		else 
		{
			// 打印值部分
			printf("值：");
			for (int i = 0; i < len; i++) {
				printf("%02X ", p[i]);
			}
			printf("\n");
		}

		p += len;  // 移动指针到下一个对象
	}
}
void testGetCertInfo()
{
	//x509 -in ./certs/_.csdn.net.crt -text -noout
	unsigned char cert[4096] = { 0 };
	size_t certLen = 4096;
	FILE* fp = fopen("./certs/_.zhihu.com.crt", "rb");
	certLen = fread(cert, 1, 4096, fp);
	fclose(fp);
	unsigned char info[4096] = { 0 };
	size_t infoLen = 4096;
	long iInfo = 0;
	size_t flag;
	for (size_t i = 0; i < 600; i++)
	{
		iInfo = 0;
		int ret = getCertInfo(cert, certLen, i, &iInfo, info, &infoLen,&flag);
		if (ret)
		{
			DEBUG_PRINT("getCertInfo err\n");
		}
		else
		{
			DEBUG_PRINT("getCertInfo ok\n");
			//traverse_der_data(info, infoLen);

			
			printf("\n");
		}
	}

}

static X509_CRL* PEMorDER_to_x509_crl(const unsigned char* crlData, size_t crlDataLen)
{
	X509_CRL* crl = NULL;
	BIO* bio = NULL;
	do
	{
		if (crlData[0]=='-' && crlData[1]=='-')
		{
			// 将 PEM 格式的字节数组解码为字符串形式
			bio = BIO_new_mem_buf(crlData, crlDataLen);
			crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
		}
		else
		{
			// 将 DER 格式的字节数组解码为字符串形式
			const unsigned char* p = crlData;
			X509_CRL* crl = d2i_X509_CRL(NULL, &p, (long)crlDataLen);
			crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
		}
		
	} while (0);
	if (bio)
	{
		// 释放 BIO 对象
		BIO_free(bio); bio = NULL;
	}
	return crl;
}

int sm2Enveloped(const char* privKeyHex, unsigned char* data, size_t dataLen, size_t flags, size_t cipherFlag, unsigned char* signPemCert, size_t signPemCertLen ,unsigned char* envPemCert, size_t envPemCertLen, unsigned char* pemCrl, size_t pemCrlLen, unsigned char* enveloped, size_t* envelopedLen)
{
	//smime -sign -signer ./certs/SS.crt -inkey ./certs/SS.key -in ./certs/data.txt -encrypt  -sm4-ecb -outform PEM -out encrypt_signed.p7   ./certs/SE.crt
	int ret = -1;
	EVP_PKEY* pkey = NULL;
	X509* signX509Cert = NULL;
	X509* envX509Cert = NULL;
	X509_CRL* crl = NULL;
	BIO* signCertBio = NULL;	
	BIO* envCertBio = NULL;
	PKCS7* p7 = NULL;	
	STACK_OF(X509)* encerts = NULL;
	STACK_OF(X509)* signcerts = NULL;
	const EVP_CIPHER* cipher = NULL;
	BIO* in = NULL;
	unsigned char* buf = NULL;
	int len;
	do
	{
		//参数检查

		if (!privKeyHex || !data || !dataLen || !signPemCert || signPemCertLen <=0 || !envPemCert || envPemCertLen <= 0 || !enveloped || !envelopedLen)
		{
			ret = 1;
			DEBUG_PRINT("Error: invalid parameters\n");
			break;
		}
		//加载私钥
		pkey = getEvpKey(privKeyHex);
		if (!pkey)
		{
			ret = 2;
			DEBUG_PRINT("Error: failed to load private key\n");
			break;
		}
		signCertBio = BIO_new_mem_buf(signPemCert, signPemCertLen);
		if (!signCertBio)
		{
			ret = 3;
			DEBUG_PRINT("BIO_new_mem_buf failed.\n");
			break;
		}
		envCertBio = BIO_new_mem_buf(envPemCert, envPemCertLen);
		if (!envCertBio)
		{
			ret = 3;
			DEBUG_PRINT("BIO_new_mem_buf failed.\n");
			break;
		}
		signX509Cert = PEM_read_bio_X509(signCertBio, NULL, 0, NULL);
		if ( !signX509Cert)
		{
			ret = 4;
			DEBUG_PRINT("PEM_read_bio_X509 failed.\n");
			break;
		}
		envX509Cert = PEM_read_bio_X509(envCertBio, NULL, 0, NULL);
		if (!envX509Cert)
		{
			ret = 4;
			DEBUG_PRINT("PEM_read_bio_X509 failed.\n");
			break;
		}

		in = BIO_new_mem_buf(data, dataLen);
		if (!in)
		{
			ret = 5;
			DEBUG_PRINT("BIO_new_mem_buf err\n");
			break;
		}
		/*p7 = PKCS7_new();
		if (!p7)
		{
			ret = 6;
			DEBUG_PRINT("PKCS7_new err\n");
			break;
		}*/
		signcerts = sk_X509_new_null();
		encerts = sk_X509_new_null();
		if (!encerts ||!signcerts)
		{
			ret = 7;
			DEBUG_PRINT("sk_X509_new_null err\n");
			break;
		}
		if (sk_X509_push(encerts, envX509Cert) < 0)
		{
			ret = 8;
			DEBUG_PRINT("sk_X509_push envX509Cert err\n");
			break;
		}
		if (sk_X509_push(signcerts, signX509Cert) < 0)
		{
			ret = 8;
			DEBUG_PRINT("sk_X509_push signX509Cert err\n");
			break;
		}

		switch (cipherFlag)
		{
			case 0:
				cipher = EVP_sm4_ecb();
				break;
			case 1:
				cipher = EVP_sm4_cbc();
				break;
			case 2:
				cipher = EVP_sm4_ofb();
				break;
			case 3:
				cipher = EVP_sm4_cfb();
				break;
		default:
			ret = 9;
			DEBUG_PRINT("cipherFlag err\n");
			break;
		}
		crl=PEMorDER_to_x509_crl(pemCrl, pemCrlLen);
		if (flags & PKCS7_NOSIGS)
		{
			p7 = PKCS7_encrypt(encerts, in, cipher, flags);		
		}
		else
		{
			p7 = PKCS7_encryptEx(encerts, in, cipher, crl,signX509Cert, pkey, NULL, flags);
		}
		
		if (!p7)
		{
			ret = 9;
			DEBUG_PRINT("PKCS7_encrypt err\n");
			break;
		}
		len = i2d_PKCS7(p7, &buf); // 编码 PKCS7 对象为 DER 格式
		// 现在 buf 中包含编码后的数据，长度为 len
		if (len > *envelopedLen)
		{
			ret = 10;
			DEBUG_PRINT("signData buffer is too small.\n");
			break;
		}
		memcpy(enveloped, buf, len);
		*envelopedLen = len;


#ifdef _DEBUG
		//将p7转为PEM
		BIO* out = BIO_new(BIO_s_mem());
		if (!out)
		{
			ret = 7;
			DEBUG_PRINT("BIO_new error\n");
			break;
		}
		PEM_write_bio_PKCS7(out, p7);
		char* p7_pem = NULL;
		int p7_pem_len = BIO_get_mem_data(out, &p7_pem);
		p7_pem[p7_pem_len] = 0;
		DEBUG_PRINT("p7_pem_len = %d\n", p7_pem_len);
		DEBUG_PRINT("p7_pem = %s\n", p7_pem);
		BIO_free(out);
		// 保存P7签名数据到文件
		FILE* fp = fopen("sm2_enveloped.p7", "wb");
		i2d_PKCS7_fp(fp, p7);
		fclose(fp);
#endif // DEBUG	
		ret = 0;
	} while (0);
	//释放内存 
	if (pkey)
	{
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	if (signX509Cert)
	{
		X509_free(signX509Cert);
		signX509Cert = NULL;
	}
	if (envX509Cert)
	{
		X509_free(envX509Cert);
		envX509Cert = NULL;
	}
	if (signCertBio)
	{
		BIO_free(signCertBio);
		signCertBio = NULL;
	}
	if (envCertBio)
	{
		BIO_free(envCertBio);
		envCertBio = NULL;
	}
	if (in)
	{
		BIO_free(in);
		in = NULL;
	}
	if (encerts)
	{
		sk_X509_free(encerts);
		encerts = NULL;
	}
	if (p7)
	{
		PKCS7_free(p7);
		p7 = NULL;
	}
	if (crl)
	{
		X509_CRL_free(crl);
		crl = NULL;
	}
	return ret;
}



//制作SM2 数字信封
void testEnveloped()
{
	int ret = 0;
	const char* privKeyHex = "30770201010420363FFCAA72C0C728E9B2C5D16F840258EDB98D803B90395C4E77C44A2C7090FAA00A06082A811CCF5501822DA14403420004E20234542883F1F007C1D008A5251C537E64AAE2C456D4F2C44C1DFC15BE1E19382E05792FBA09D68E32E85CD8362D6233CCABBA5A5E5426983747766921C35E";
	const char* pubKeyHex = "04e20234542883f1f007c1d008a5251c537e64aae2c456d4f2c44c1dfc15be1e19382e05792fba09d68e32e85cd8362d6233ccabba5a5e5426983747766921c35e";
	const char* data = "abc";
	size_t dataLen = strlen(data);
	unsigned char enveloped[4096*2] = { 0 };
	size_t envelopedLen = 4096*2;
	unsigned char cert[4096] = { 0 };
	size_t certLen = 4096;
	unsigned char signCert[4096] = { 0 };
	size_t signCertLen = 4096;
	unsigned char caCert[4096] = { 0 };
	size_t caCertLen = 4096;
	int flags;// = PKCS7_NOCERTS | PKCS7_DETACHED;// | PKCS7_NOATTR; //|  PKCS7_DETACHED  | PKCS7_NOCERTS| PKCS7_STREAM | PKCS7_NOCHAIN  | PKCS7_NOSMIMECAP | PKCS7_NOSMIMECAP:不包含加密算法能力集
	FILE* fp = fopen("./certs/SE.crt", "rb");
	certLen = fread(cert, 1, 4096, fp);
	fclose(fp);
	BIO* certBio = NULL;
	X509_STORE* st = NULL;
	st = X509_STORE_new();
	if (!st)
	{
		ret = 9;
		DEBUG_PRINT("X509_STORE_new err\n");
		return;
	}
	certBio = BIO_new_file("./certs/CA.crt", "r");//BIO_new_file("./certs/CA.crt", "r");
	if (!certBio)
	{
		ret = 9;
		DEBUG_PRINT("BIO_new_file err\n");
		X509_STORE_free(st);
		return;
	}
	caCertLen = BIO_read(certBio, caCert, 4096);
	BIO_free(certBio); certBio = NULL;

	certBio = BIO_new_file("./certs/SS.crt", "r");//BIO_new_file("./certs/CA.crt", "r");
	if (!certBio)
	{
		ret = 9;
		DEBUG_PRINT("BIO_new_file err\n");
		X509_STORE_free(st);
		return;
	}
	signCertLen = BIO_read(certBio, signCert, 4096);
	BIO_free(certBio); certBio = NULL;

	st = addCertToStore(st, caCert, caCertLen);
	if (!st)
	{
		ret = 10;
		DEBUG_PRINT("addCertToStore err\n");
		X509_STORE_free(st);
		return;
	}
	flags = PKCS7_DETACHED | PKCS7_SM2_GMT0010;
	//SM2 P7签名
	ret = sm2Enveloped(privKeyHex, (unsigned char*)data, dataLen, flags,0,signCert, signCertLen, cert, certLen, NULL, 0, enveloped, &envelopedLen);
	if (ret)
	{
		DEBUG_PRINT("sm2SignData err,ret:%08x\n", ret);
		X509_STORE_free(st);
		return;
	}
	//flags = 0;// PKCS7_NOVERIFY;// PKCS7_DETACHED | PKCS7_NOCHAIN | PKCS7_NOSMIMECAP; //| PKCS7_STREAM
	////flags = PKCS7_NOCHAIN | PKCS7_NOCRL;
	////SM2 P7验签
	//ret = sm2VerifySignData((unsigned char*)data, dataLen, flags, cert, certLen, signData, signDataLen, st);
	//if (ret)
	//{
	//	DEBUG_PRINT("sm2VerifySignData err,ret:%08x\n", ret);
	//	X509_STORE_free(st);
	//	return;
	//}
}

int main(int argc, char* argv[])
{
	ERR_load_ERR_strings();
	ERR_load_crypto_strings();
	testEnveloped();
	//-s 127.0.0.1:4433 --gmssl --verify -ca ./certs/CA.crt
	//testVerifyP7();
	//testAsn1();
	testGetCertInfo();
	getSM2Key();
	testEvpKey();
	testRsaP7();
	testP7();
	int ret = 0;
	const char* privKeyHex = "b82282531fc2ba3598a18b390dae160e0653e49676f2a570eeebcd97a8fa0b4f";
	const char* pubKeyHex = "042e953b399f27ac62e74fb4f54db3afbaa255d0a2f0cbe906f108a8856c1217a39a22599cf1bdd21c7da57025a1d5dfbff9c6dc42a17a1716cf3867a03bf62069";
	const char* data = "abc";
	size_t dataLen = strlen(data);
	unsigned char sign[128] = { 0 };
	size_t signLen = 128;

	unsigned char privKey[64] = { 0 };
	size_t privKeyLen = 64;
	unsigned char pubKey[65] = { 0 };
	size_t pubKeyLen = 65;


	unsigned char enData[512] = { 0 };
	size_t enDataLen = 512;

	unsigned char deData[512] = { 0 };
	size_t deDataLen = 512;

	char* privKeyHexStr = NULL;
	char* pubKeyHexStr = NULL;
	//生成SM2密钥  
	ret = sm2GenKey(privKey, &privKeyLen, pubKey, &pubKeyLen);
	if (ret)
	{
		DEBUG_PRINT("sm2GenKey err\n");
		return 1;
	}
	//私钥二进制转十六进制字符串
	privKeyHexStr = bin2hex(privKey, privKeyLen);

	pubKeyHexStr = bin2hex(pubKey, pubKeyLen);


	ret = sm2Encrypt(pubKeyHex, data, dataLen, enData, &enDataLen);
#ifdef _DEBUG
	FILE* fp = fopen("sm2Encrypt.bin", "wb");
	fwrite(enData,1, enDataLen,fp);
	fclose(fp);
#endif // DEBUG	
	ret = sm2Decrypt(privKeyHex, enData, enDataLen, deData, &deDataLen);

	ret = sm2Sign(privKeyHex, (unsigned char*)data, dataLen, sign, &signLen);

	ret = sm2VerifySign(pubKeyHex, (unsigned char*)data, dataLen, sign, signLen);

	if (privKeyHex)
	{
		OPENSSL_free(privKeyHexStr);
		privKeyHexStr = NULL;
	}
	if (pubKeyHexStr)
	{
		OPENSSL_free(pubKeyHexStr);
		pubKeyHexStr = NULL;
	}
	system("pause");
}

/*实现一个基于openssl 的SKF的引擎*/


