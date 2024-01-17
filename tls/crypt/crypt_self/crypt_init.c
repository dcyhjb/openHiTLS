/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#include "hitls_crypt_reg.h"
#include "crypt_default.h"

void HITLS_CryptMethodInit(void)
{
    HITLS_CRYPT_BaseMethod baseMethod = {0};
    baseMethod.randBytes = CRYPT_DEFAULT_RandomBytes;
    baseMethod.hmacSize = CRYPT_DEFAULT_HMAC_Size;
    baseMethod.hmacInit = CRYPT_DEFAULT_HMAC_Init;
    baseMethod.hmacFree = CRYPT_DEFAULT_HMAC_Free;
    baseMethod.hmacUpdate = CRYPT_DEFAULT_HMAC_Update;
    baseMethod.hmacFinal = CRYPT_DEFAULT_HMAC_Final;
    baseMethod.hmac = CRYPT_DEFAULT_HMAC;
    baseMethod.digestSize = CRYPT_DEFAULT_DigestSize;
    baseMethod.digestInit = CRYPT_DEFAULT_DigestInit;
    baseMethod.digestCopy = CRYPT_DEFAULT_DigestCopy;
    baseMethod.digestFree = CRYPT_DEFAULT_DigestFree;
    baseMethod.digestUpdate = CRYPT_DEFAULT_DigestUpdate;
    baseMethod.digestFinal = CRYPT_DEFAULT_DigestFinal;
    baseMethod.digest = CRYPT_DEFAULT_Digest;
    baseMethod.encrypt = CRYPT_DEFAULT_Encrypt;
    baseMethod.decrypt = CRYPT_DEFAULT_Decrypt;
    HITLS_CRYPT_RegisterBaseMethod(&baseMethod);

    HITLS_CRYPT_EcdhMethod ecdhMethod = {0};
    ecdhMethod.generateEcdhKeyPair = CRYPT_DEFAULT_GenerateEcdhKey;
    ecdhMethod.dupEcdhKey = CRYPT_DEFAULT_DupKey;
    ecdhMethod.freeEcdhKey = CRYPT_DEFAULT_FreeKey;
    ecdhMethod.getEcdhPubKey = CRYPT_DEFAULT_GetPubKey;
    ecdhMethod.calcEcdhSharedSecret = CRYPT_DEFAULT_CalcSharedSecret;
    ecdhMethod.sm2CalEcdhSharedSecret = CRYPT_DEFAULT_CalcSM2SharedSecret;
    HITLS_CRYPT_RegisterEcdhMethod(&ecdhMethod);

    HITLS_CRYPT_DhMethod dhMethod = {0};
    dhMethod.generateDhKeyBySecbits = CRYPT_DEFAULT_GenerateDhKeyBySecbits;
    dhMethod.generateDhKeyByParams = CRYPT_DEFAULT_GenerateDhKeyByParameters;
    dhMethod.dupDhKey = CRYPT_DEFAULT_DupKey;
    dhMethod.freeDhKey = CRYPT_DEFAULT_FreeKey;
    dhMethod.getDhParameters = CRYPT_DEFAULT_GetDhParameters;
    dhMethod.getDhPubKey = CRYPT_DEFAULT_GetPubKey;
    dhMethod.calcDhSharedSecret = CRYPT_DEFAULT_CalcSharedSecret;
    HITLS_CRYPT_RegisterDhMethod(&dhMethod);

    HITLS_CRYPT_KdfMethod hkdfMethod = {0};
    hkdfMethod.hkdfExtract = CRYPT_DEFAULT_HkdfExtract;
    hkdfMethod.hkdfExpand = CRYPT_DEFAULT_HkdfExpand;
    HITLS_CRYPT_RegisterHkdfMethod(&hkdfMethod);

    return;
}