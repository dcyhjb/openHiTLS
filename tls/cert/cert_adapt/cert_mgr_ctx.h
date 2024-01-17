/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef CERT_MGR_CTX_H
#define CERT_MGR_CTX_H

#include <stdint.h>
#include "hitls_cert_reg.h"
#include "cert.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_DEFAULT_VERIFY_DEPTH 20u

struct CertVerifyParamInner {
    uint32_t verifyDepth;   /* depth of verify */
    uint32_t purpose;       /* purpose to check untrusted certificates */
    uint32_t trust;         /* trust setting to check */
};

struct CertPairInner {
    HITLS_CERT_X509 *cert;      /* device certificate */
    /* encrypted device cert. Currently this field is used only when the peer-end encrypted certificate is stored. */
    HITLS_CERT_X509 *encCert;
    HITLS_CERT_Key *privateKey; /* private key corresponding to the certificate */
    HITLS_CERT_Chain *chain;    /* certificate chain */
};

struct CertMgrCtxInner {
    uint32_t currentCertIndex;                  /* points to the certificate in use. */
    /* Indicates the certificate resources on the link. Only one certificate of a type can be loaded. */
    CERT_Pair certPair[TLS_CERT_KEY_TYPE_NUM];
    HITLS_CERT_Chain *extraChain;
    HITLS_CERT_Store *verifyStore;              /* Verifies the store, which is used to verify the certificate chain. */
    HITLS_CERT_Store *chainStore;               /* Certificate chain store, used to assemble the certificate chain */
    HITLS_CERT_Store *certStore;                /* Default CA store */
    HITLS_CertVerifyParam verifyParam;          /* Verification Parameters */
    HITLS_CERT_MgrMethod method;                /* callback function */
    HITLS_PasswordCb defaultPasswdCb;           /* Default password callback, used in loading certificate. */
    void *defaultPasswdCbUserData;              /* Set the userData used by the default password callback.  */
    HITLS_VerifyCb verifyCb;                    /* Certificate verification callback function */
};

CERT_Type CertKeyType2CertType(HITLS_CERT_KeyType keyType);

HITLS_CERT_KeyType SignScheme2CertKeyType(HITLS_SignHashAlgo signScheme);

int32_t CheckSignScheme(HITLS_Ctx *ctx, const uint16_t *signSchemeList, uint32_t signSchemeNum,
    HITLS_CERT_KeyType checkedKeyType, bool isNegotiateSignAlgo);

int32_t CheckCurveName(HITLS_Config *config, const uint16_t *curveList, uint32_t curveNum, HITLS_CERT_Key *pubkey);

int32_t CheckPointFormat(HITLS_Config *config, const uint8_t *ecPointFormatList, uint32_t listSize,
    HITLS_CERT_Key *pubkey);

/* These functions can be stored in a separate header file. */
HITLS_CERT_Chain *SAL_CERT_ChainNew(void);
int32_t SAL_CERT_ChainAppend(HITLS_CERT_Chain *chain, HITLS_CERT_X509 *cert);
void SAL_CERT_ChainFree(HITLS_CERT_Chain *chain);
HITLS_CERT_Chain *SAL_CERT_ChainDup(CERT_MgrCtx *mgrCtx, HITLS_CERT_Chain *chain);

#ifdef __cplusplus
}
#endif
#endif