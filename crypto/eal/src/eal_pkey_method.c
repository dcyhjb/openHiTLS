/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_EAL) && defined(HITLS_CRYPTO_PKEY)

#include "securec.h"
#include "crypt_method.h"
#include "crypt_local_types.h"
#include "crypt_algid.h"
#include "eal_pkey_local.h"
#ifdef HITLS_CRYPTO_RSA
#include "crypt_rsa.h"
#endif
#ifdef HITLS_CRYPTO_DSA
#include "crypt_dsa.h"
#endif
#ifdef HITLS_CRYPTO_CURVE25519
#include "crypt_curve25519.h"
#endif
#ifdef HITLS_CRYPTO_CURVE448
#include "crypt_curve448.h"
#endif
#ifdef HITLS_CRYPTO_DH
#include "crypt_dh.h"
#endif
#ifdef HITLS_CRYPTO_ECDH
#include "crypt_ecdh.h"
#endif
#ifdef HITLS_CRYPTO_ECDSA
#include "crypt_ecdsa.h"
#endif
#ifdef HITLS_CRYPTO_SM2
#include "crypt_sm2.h"
#endif
#include "bsl_err_internal.h"
#include "crypt_types.h"
#include "eal_common.h"
#include "bsl_sal.h"

#define EAL_PKEY_METHOD_DEFINE(id, newCtx, dupCtx, freeCtx, setPara, getPara, gen, bits, signLen, ctrl, newParaById, \
    getParaId, freePara, newPara, setPub, setPrv, getPub, getPrv, sign, verify, computeShareKey, encrypt, \
    decrypt, check, cmp) { \
    id, (PkeyNew)(newCtx), (PkeyDup)(dupCtx), (PkeyFree)(freeCtx), (PkeySetPara)(setPara), (PkeyGetPara)(getPara), \
    (PkeyGen)(gen), (PkeyBits)(bits), (PkeyGetSignLen)(signLen), (PkeyCtrl)(ctrl), (PkeyNewParaById)(newParaById), \
    (PkeyGetParaId)(getParaId), (PkeyFreePara)(freePara), (PkeyNewPara)(newPara), (PkeySetPub)(setPub), \
    (PkeySetPrv)(setPrv), (PkeyGetPub)(getPub), (PkeyGetPrv)(getPrv), (PkeySign)(sign), \
    (PkeyVerify)(verify), (PkeyComputeShareKey)(computeShareKey), (PkeyCrypt)(encrypt), \
    (PkeyCrypt)(decrypt), (PkeyCheck)(check), (PkeyCmp)(cmp)}

static const EAL_PkeyMethod METHODS[] = {
#ifdef HITLS_CRYPTO_DSA
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_DSA,
        CRYPT_DSA_NewCtx,
        CRYPT_DSA_DupCtx,
        CRYPT_DSA_FreeCtx,
        CRYPT_DSA_SetPara,
        CRYPT_DSA_GetPara,
        CRYPT_DSA_Gen,
        CRYPT_DSA_GetBits,
        CRYPT_DSA_GetSignLen,
        CRYPT_DSA_Ctrl,
        NULL, // newParaById
        NULL, // getParaId
        CRYPT_DSA_FreePara,
        CRYPT_DSA_NewPara,
        CRYPT_DSA_SetPubKey,
        CRYPT_DSA_SetPrvKey,
        CRYPT_DSA_GetPubKey,
        CRYPT_DSA_GetPrvKey,
        CRYPT_DSA_Sign,
        CRYPT_DSA_Verify,
        NULL,
        NULL,
        NULL,
        NULL,
        CRYPT_DSA_Cmp
    ), // CRYPT_PKEY_DSA
#endif
#ifdef HITLS_CRYPTO_ED25519
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_ED25519,
        CRYPT_CURVE25519_NewCtx,
        CRYPT_CURVE25519_DupCtx,
        CRYPT_CURVE25519_FreeCtx,
        NULL,
        NULL,
        CRYPT_ED25519_GenKey,
        CRYPT_CURVE25519_GetBits,
        CRYPT_CURVE25519_GetSignLen,
        CRYPT_CURVE25519_Ctrl,
        NULL, // newParaById
        NULL, // getParaId
        NULL,
        NULL,
        CRYPT_CURVE25519_SetPubKey,
        CRYPT_CURVE25519_SetPrvKey,
        CRYPT_CURVE25519_GetPubKey,
        CRYPT_CURVE25519_GetPrvKey,
        CRYPT_CURVE25519_Sign,
        CRYPT_CURVE25519_Verify,
        NULL,
        NULL,
        NULL,
        NULL,
        CRYPT_CURVE25519_Cmp
    ), // CRYPT_PKEY_ED25519
#endif
#ifdef HITLS_CRYPTO_X25519
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_X25519,
        CRYPT_CURVE25519_NewCtx,
        CRYPT_CURVE25519_DupCtx,
        CRYPT_CURVE25519_FreeCtx,
        NULL,
        NULL,
        CRYPT_X25519_GenKey,
        CRYPT_CURVE25519_GetBits,
        NULL,
        CRYPT_CURVE25519_Ctrl,
        NULL, // newParaById
        NULL, // getParaId
        NULL,
        NULL,
        CRYPT_CURVE25519_SetPubKey,
        CRYPT_CURVE25519_SetPrvKey,
        CRYPT_CURVE25519_GetPubKey,
        CRYPT_CURVE25519_GetPrvKey,
        NULL,
        NULL,
        CRYPT_CURVE25519_ComputeSharedKey,
        NULL,
        NULL,
        NULL,
        CRYPT_CURVE25519_Cmp
    ), // CRYPT_PKEY_X25519
#endif
#ifdef HITLS_CRYPTO_RSA
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_RSA,
        CRYPT_RSA_NewCtx,
        CRYPT_RSA_DupCtx,
        CRYPT_RSA_FreeCtx,
        CRYPT_RSA_SetPara,
        NULL,
        CRYPT_RSA_Gen,
        CRYPT_RSA_GetBits,
        CRYPT_RSA_GetSignLen,
        CRYPT_RSA_Ctrl,
        NULL, // newParaById
        NULL, // getParaId
        CRYPT_RSA_FreePara,
        CRYPT_RSA_NewPara,
        CRYPT_RSA_SetPubKey,
        CRYPT_RSA_SetPrvKey,
        CRYPT_RSA_GetPubKey,
        CRYPT_RSA_GetPrvKey,
        CRYPT_RSA_Sign,
        CRYPT_RSA_Verify,
        NULL,
        CRYPT_RSA_Encrypt,
        CRYPT_RSA_Decrypt,
        NULL,
        CRYPT_RSA_Cmp
    ), // CRYPT_PKEY_RSA
#endif
#ifdef HITLS_CRYPTO_DH
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_DH,
        CRYPT_DH_NewCtx,
        CRYPT_DH_DupCtx,
        CRYPT_DH_FreeCtx,
        CRYPT_DH_SetPara,
        CRYPT_DH_GetPara,
        CRYPT_DH_Gen,
        CRYPT_DH_GetBits,
        NULL,
        CRYPT_DH_Ctrl,
        CRYPT_DH_NewParaById,
        CRYPT_DH_GetParaId,
        CRYPT_DH_FreePara,
        CRYPT_DH_NewPara,
        CRYPT_DH_SetPubKey,
        CRYPT_DH_SetPrvKey,
        CRYPT_DH_GetPubKey,
        CRYPT_DH_GetPrvKey,
        NULL,
        NULL,
        CRYPT_DH_ComputeShareKey,
        NULL,
        NULL,
        CRYPT_DH_Check,
        CRYPT_DH_Cmp
    ), // CRYPT_PKEY_DH
#endif
#ifdef HITLS_CRYPTO_ECDSA
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_ECDSA,
        CRYPT_ECDSA_NewCtx,
        CRYPT_ECDSA_DupCtx,
        CRYPT_ECDSA_FreeCtx,
        CRYPT_ECDSA_SetPara,
        CRYPT_ECDSA_GetPara,
        CRYPT_ECDSA_Gen,
        CRYPT_ECDSA_GetBits,
        CRYPT_ECDSA_GetSignLen,
        CRYPT_ECDSA_Ctrl,
        CRYPT_ECDSA_NewParaById,
        CRYPT_ECDSA_GetParaId,
        CRYPT_ECDSA_FreePara,
        CRYPT_ECDSA_NewPara,
        CRYPT_ECDSA_SetPubKey,
        CRYPT_ECDSA_SetPrvKey,
        CRYPT_ECDSA_GetPubKey,
        CRYPT_ECDSA_GetPrvKey,
        CRYPT_ECDSA_Sign,
        CRYPT_ECDSA_Verify,
        NULL,   // compute share key
        NULL,   // encrypt
        NULL,   // decrypt
        NULL,
        CRYPT_ECDSA_Cmp
    ), // CRYPT_PKEY_ECDSA
#endif
#ifdef HITLS_CRYPTO_ECDH
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_ECDH,
        CRYPT_ECDH_NewCtx,
        CRYPT_ECDH_DupCtx,
        CRYPT_ECDH_FreeCtx,
        CRYPT_ECDH_SetPara,
        CRYPT_ECDH_GetPara,
        CRYPT_ECDH_Gen,
        CRYPT_ECDH_GetBits,
        NULL,   // get sign len
        CRYPT_ECDH_Ctrl,
        CRYPT_ECDH_NewParaById,
        CRYPT_ECDH_GetParaId,
        CRYPT_ECDH_FreePara,
        CRYPT_ECDH_NewPara,
        CRYPT_ECDH_SetPubKey,
        CRYPT_ECDH_SetPrvKey,
        CRYPT_ECDH_GetPubKey,
        CRYPT_ECDH_GetPrvKey,
        NULL,   // sign
        NULL,   // verify
        CRYPT_ECDH_ComputeShareKey,
        NULL,   // encrypt
        NULL,   // decrypt
        NULL,
        CRYPT_ECDH_Cmp
    ), // CRYPT_PKEY_ECDH
#endif
#ifdef HITLS_CRYPTO_SM2
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_SM2,
        CRYPT_SM2_NewCtx,
        CRYPT_SM2_DupCtx,
        CRYPT_SM2_FreeCtx,
        NULL,
        NULL,
        CRYPT_SM2_Gen,
        CRYPT_SM2_GetBits,
#ifdef HITLS_CRYPTO_SM2_SIGN
        CRYPT_SM2_GetSignLen,
#else
        NULL,
#endif
        CRYPT_SM2_Ctrl,
        NULL,
        NULL,
        NULL,
        NULL,
        CRYPT_SM2_SetPubKey,
        CRYPT_SM2_SetPrvKey,
        CRYPT_SM2_GetPubKey,
        CRYPT_SM2_GetPrvKey,
#ifdef HITLS_CRYPTO_SM2_SIGN
        CRYPT_SM2_Sign,
        CRYPT_SM2_Verify,
#else
        NULL,
        NULL,
#endif
#ifdef HITLS_CRYPTO_SM2_EXCH
        CRYPT_SM2_KapComputeKey,   // compute share key
#else
        NULL,
#endif
#ifdef HITLS_CRYPTO_SM2_CRYPT
        CRYPT_SM2_Encrypt,   // encrypt
        CRYPT_SM2_Decrypt,   // decrypt
#else
        NULL,
        NULL,
#endif
        NULL,
        CRYPT_SM2_Cmp
    ), // CRYPT_PKEY_SM2
#endif
#ifdef HITLS_CRYPTO_ED448
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_ED448,
        CRYPT_CURVE448_NewCtx,
        CRYPT_CURVE448_DupCtx,
        CRYPT_CURVE448_FreeCtx,
        NULL,
        NULL,
        CRYPT_ED448_GenKey,
        CRYPT_ED448_GetBits,
        CRYPT_ED448_GetSignLen,
        CRYPT_CURVE448_Ctrl,
        NULL,
        NULL,
        NULL,
        NULL,
        CRYPT_ED448_SetPubKey,
        CRYPT_ED448_SetPrvKey,
        CRYPT_ED448_GetPubKey,
        CRYPT_ED448_GetPrvKey,
        CRYPT_CURVE448_Sign,
        CRYPT_CURVE448_Verify,
        NULL,
        NULL,
        NULL,
        NULL,
        CRYPT_CURVE448_Cmp
    ), // CRYPT_PKEY_ED448
#endif
#ifdef HITLS_CRYPTO_X448
    EAL_PKEY_METHOD_DEFINE(
        CRYPT_PKEY_X448,
        CRYPT_CURVE448_NewCtx,
        CRYPT_CURVE448_DupCtx,
        CRYPT_CURVE448_FreeCtx,
        NULL,
        NULL,
        CRYPT_X448_GenKey,
        CRYPT_X448_GetBits,
        NULL,
        CRYPT_CURVE448_Ctrl,
        NULL,
        NULL,
        NULL,
        NULL,
        CRYPT_X448_SetPubKey,
        CRYPT_X448_SetPrvKey,
        CRYPT_X448_GetPubKey,
        CRYPT_X448_GetPrvKey,
        NULL,
        NULL,
        CRYPT_X448_ComputeSharedKey,
        NULL,
        NULL,
        NULL,
        CRYPT_CURVE448_Cmp
    ), // CRYPT_PKEY_X448
#endif
};

const EAL_PkeyMethod *CRYPT_EAL_PkeyFindMethod(CRYPT_PKEY_AlgId id)
{
    uint32_t num = sizeof(METHODS) / sizeof(METHODS[0]);
    const EAL_PkeyMethod *pkeyMeth = NULL;

    for (uint32_t i = 0; i < num; i++) {
        if (METHODS[i].id == id) {
            pkeyMeth = &METHODS[i];
            return pkeyMeth;
        }
    }

    return NULL;
}
#endif
