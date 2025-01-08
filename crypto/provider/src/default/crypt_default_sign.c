/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_PROVIDER

#include "crypt_eal_implprovider.h"
#include "crypt_dsa.h"
#include "crypt_rsa.h"
#include "crypt_ecdsa.h"
#include "crypt_sm2.h"
#include "crypt_curve25519.h"

const CRYPT_EAL_Func g_defSignDsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_DSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, CRYPT_DSA_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_DSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, CRYPT_DSA_VerifyData},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defSignEd25519[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_CURVE25519_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, NULL},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_CURVE25519_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, NULL},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defSignRsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_RSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, CRYPT_RSA_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_RSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, CRYPT_RSA_VerifyData},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defSignEcdsa[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_ECDSA_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, CRYPT_ECDSA_SignData},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_ECDSA_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, CRYPT_ECDSA_VerifyData},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_defSignSm2[] = {
    {CRYPT_EAL_IMPLPKEYSIGN_SIGN, CRYPT_SM2_Sign},
    {CRYPT_EAL_IMPLPKEYSIGN_SIGNDATA, NULL},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFY, CRYPT_SM2_Verify},
    {CRYPT_EAL_IMPLPKEYSIGN_VERIFYDATA, NULL},
    CRYPT_EAL_FUNC_END,
};

#endif /* HITLS_CRYPTO_PROVIDER */