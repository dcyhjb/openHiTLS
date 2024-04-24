/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef HITLS_X509_ADAPT_LOCAL_H
#define HITLS_X509_ADAPT_LOCAL_H

#include <stdint.h>
#include "hitls_type.h"
#include "hitls_cert.h"
#include "hitls_crypt_type.h"
#include "hitls_cert_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PASS_LEN 64

HITLS_CERT_Store *HITLS_X509_Adapt_StoreNew(void);
HITLS_CERT_Store *HITLS_X509_Adapt_StoreDup(HITLS_CERT_Store *store);
void HITLS_X509_Adapt_StoreFree(HITLS_CERT_Store *store);
int32_t HITLS_X509_Adapt_StoreCtrl(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output);
int32_t HITLS_X509_Adapt_BuildCertChain(HITLS_Config *config, HITLS_CERT_Store *store, HITLS_CERT_X509 *cert,
    HITLS_CERT_X509 **list, uint32_t *num);

int32_t HITLS_X509_Adapt_VerifyCertChain(HITLS_Ctx *ctx, HITLS_CERT_Store *store, HITLS_CERT_X509 **list, uint32_t num);

int32_t HITLS_X509_Adapt_CertEncode(HITLS_Ctx *ctx, HITLS_CERT_X509 *cert, uint8_t *buf, uint32_t len,
    uint32_t *usedLen);

HITLS_CERT_X509 *HITLS_X509_Adapt_CertParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);
HITLS_CERT_X509 *HITLS_X509_Adapt_CertDup(HITLS_CERT_X509 *cert);
HITLS_CERT_X509 *HITLS_X509_Adapt_CertRef(HITLS_CERT_X509 *cert);
void HITLS_X509_Adapt_CertFree(HITLS_CERT_X509 *cert);
int32_t HITLS_X509_Adapt_CertCtrl(HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output);

HITLS_CERT_Key *HITLS_X509_Adapt_KeyParse(HITLS_Config *config, const uint8_t *buf, uint32_t len,
    HITLS_ParseType type, HITLS_ParseFormat format);
HITLS_CERT_Key *HITLS_X509_Adapt_KeyDup(HITLS_CERT_Key *key);
void HITLS_X509_Adapt_KeyFree(HITLS_CERT_Key *key);
int32_t HITLS_X509_Adapt_KeyCtrl(HITLS_Config *config, HITLS_CERT_Key *key, HITLS_CERT_CtrlCmd cmd,
    void *input, void *output);

int32_t HITLS_X509_Adapt_CreateSign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, HITLS_SignAlgo signAlgo,
    HITLS_HashAlgo hashAlgo, const uint8_t *data, uint32_t dataLen, uint8_t *sign, uint32_t *signLen);
int32_t HITLS_X509_Adapt_VerifySign(HITLS_Ctx *ctx, HITLS_CERT_Key *key, HITLS_SignAlgo signAlgo,
    HITLS_HashAlgo hashAlgo, const uint8_t *data, uint32_t dataLen, const uint8_t *sign, uint32_t signLen);
int32_t HITLS_X509_Adapt_Encrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);
int32_t HITLS_X509_Adapt_Decrypt(HITLS_Ctx *ctx, HITLS_CERT_Key *key, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen);
int32_t HITLS_X509_Adapt_CheckPrivateKey(const HITLS_Config *config, HITLS_CERT_X509 *cert, HITLS_CERT_Key *key);

int32_t GetPassByCb(HITLS_PasswordCb passWordCb, void *passWordCbUserData, char *pass, int32_t *passLen);

#ifdef __cplusplus
}
#endif

#endif // HITLS_X509_ADAPT_LOCAL_H