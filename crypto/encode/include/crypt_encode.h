/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_ENCODE_H
#define CRYPT_ENCODE_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_ENCODE

#include "crypt_bn.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

typedef struct {
    BN_BigNum *r;
    BN_BigNum *s;
} DSA_Sign;
// encode signature data
int32_t ASN1_SignDataEncode(const DSA_Sign *s, uint8_t *sign, uint32_t *signLen);

// decode signature data
int32_t ASN1_SignDataDecode(DSA_Sign *s, const uint8_t *sign, uint32_t signLen);

// Obtain the required length of the signature data.
uint32_t ASN1_SignEnCodeLen(uint32_t rLen, uint32_t sLen);

// Stream length for encoding a BigNum.
uint32_t ASN1_SignStringLenOfBn(const BN_BigNum *num);

int32_t ASN1_Sm2EncryptDataEncode(const uint8_t *input, uint32_t inputLen, uint8_t *encode, uint32_t *encodeLen);

int32_t ASN1_Sm2EncryptDataDecode(const uint8_t *eData, uint32_t eLen, uint8_t *decode, uint32_t *decodeLen);

uint64_t ASN1_Sm2GetEnCodeLen(uint32_t dataLen);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_ENCODE

#endif // CRYPT_ENCODE_H
