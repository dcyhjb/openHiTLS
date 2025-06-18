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
#ifdef HITLS_CRYPTO_CMVP

#include "cmvp_iso19790.h"
#include "cmvp_common.h"
#include "crypt_errno.h"
#include "crypt_cmvp_selftest.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "cmvp_integrity_hmac.h"
#include "crypt_params_key.h"
#include "securec.h"
#include "bsl_sal.h"
#include "iso19790.h"

int32_t ISO19790_DefaultEntryPoint(void)
{
    return CMVP_CheckIntegrity(CRYPT_MAC_HMAC_SHA256);
}

int32_t ISO19790_ModeSet(CRYPT_CMVP_MODE mode)
{
    // ISO/IEC 19790:2012 AS02.22
    // If the CSP already exists in the memory, the mode cannot be switched.
    // The mode can be switched again only after the CSP is restarted.
    if (CMVP_CspFlagGet() == true) {
        return CRYPT_CMVP_ERR_CSP_EXIST;
    }

    CMVP_ModeSet(mode);
    return CRYPT_SUCCESS;
}

void ISO19790_EventProcess(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err)
{
    // ISO/IEC 19790:2012 AS09.33
    // The module shall provide an output status indication when zeroing is complete
    if (oper == CRYPT_EVENT_ZERO && err == CRYPT_SUCCESS) {
        CMVP_WriteSyslog("HiTLS", LOG_INFO, "SSP already zeroisation - algorithm type : %d, id : %d", type, id);
    }

    /*
        ISO/IEC 19790:2012 AS06.26
        The following events of the cryptographic module should be recorded by the OS audit mechanism:
        ● Attempted to provide invalid input for the cryptographic officer function;
    */
    if (err != CRYPT_SUCCESS) {
        CMVP_WriteSyslog("HiTLS", LOG_ERR, "Occur error - algorithm type : %d, id : %d, operate : %d, errcode : %x",
            type, id, oper, err);
    }
    /*
        ISO/IEC 19790:2012 AS06.26
        The following events of the cryptographic module should be recorded by the OS audit mechanism:
        ● Modify, access, delete, and add encrypted data and SSPs；
        ● Use security-related encryption features
        ISO/IEC 19790:2012 AS02.24
        When a service uses approved encryption algorithms, security functions or processes,
        and specified services or processes in an approved manner,
        the service shall provide corresponding status indications.
    */
    CMVP_WriteSyslog("HiTLS", LOG_INFO, "Excute - algorithm type : %d, id : %d, operate : %d", type, id, oper);
}

typedef struct {
    uint32_t id;
    bool signValid;
    bool verifyValid;
} ASYM_MD_MAP;

static const ASYM_MD_MAP ASYM_MD_LIST[] = {
    { CRYPT_MD_SHA1, false, true },
    { CRYPT_MD_SHA224, true, true },
    { CRYPT_MD_SHA256, true, true },
    { CRYPT_MD_SHA384, true, true },
    { CRYPT_MD_SHA512, true, true },
};

static bool GetVaildFlag(uint32_t id, bool isSign)
{
    for (uint32_t i = 0; i < sizeof(ASYM_MD_LIST) / sizeof(ASYM_MD_LIST[0]); i++) {
        if (isSign == true && id == ASYM_MD_LIST[i].id) {
            return ASYM_MD_LIST[i].signValid;
        } else if (isSign == false && id == ASYM_MD_LIST[i].id) {
            return ASYM_MD_LIST[i].verifyValid;
        }
    }
    return false;
}

// Check whether the RSA parameter is approved.
static bool RsaParamCheck(const CRYPT_EAL_PkeyC2Data *data)
{
    if (data->para != NULL) {
        CRYPT_RsaPara para = data->para->para.rsaPara;
        // The length of the RSA key must be at least 2048 bits.
        GOTO_EXIT_IF(para.bits < 2048, CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->pub != NULL) {
        CRYPT_RsaPub pub = data->pub->key.rsaPub;
        // The length of the RSA public key must be at least 2048 bits. 8 bits are 1 byte.
        GOTO_EXIT_IF(pub.nLen < (2048 / 8), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->prv != NULL) {
        CRYPT_RsaPrv prv = data->prv->key.rsaPrv;
        // The length of the RS private key must be at least 2048 bits. 8 bits are 1 byte.
        GOTO_EXIT_IF(prv.dLen < (2048 / 8), CRYPT_CMVP_ERR_PARAM_CHECK);
        GOTO_EXIT_IF(prv.nLen < (2048 / 8), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->pkcsv15 != CRYPT_MD_MAX) {
        GOTO_EXIT_IF((GetVaildFlag(data->pkcsv15->mdId, false) == false), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->pss != NULL) {
        BSL_Param *mdParam = BSL_PARAM_FindParam(data->pss, CRYPT_PARAM_RSA_MD_ID);
        GOTO_EXIT_IF(mdParam == NULL, CRYPT_CMVP_ERR_PARAM_CHECK);
        BSL_Param *mgfParam = BSL_PARAM_FindParam(data->pss, CRYPT_PARAM_RSA_MGF1_ID);
        GOTO_EXIT_IF(mgfParam == NULL, CRYPT_CMVP_ERR_PARAM_CHECK);
        GOTO_EXIT_IF((GetVaildFlag(*(uint32_t *)(mdParam->value), false) == false), CRYPT_CMVP_ERR_PARAM_CHECK);
        GOTO_EXIT_IF((GetVaildFlag(*(uint32_t *)(mgfParam->value), false) == false), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->oaep != NULL) {
        BSL_Param *mdParam = BSL_PARAM_FindParam(data->oaep, CRYPT_PARAM_RSA_MD_ID);
        GOTO_EXIT_IF(mdParam == NULL, CRYPT_CMVP_ERR_PARAM_CHECK);
        BSL_Param *mgfParam = BSL_PARAM_FindParam(data->oaep, CRYPT_PARAM_RSA_MGF1_ID);
        GOTO_EXIT_IF(mgfParam == NULL, CRYPT_CMVP_ERR_PARAM_CHECK);
        GOTO_EXIT_IF((GetVaildFlag(*(uint32_t *)(mdParam->value), false) == false), CRYPT_CMVP_ERR_PARAM_CHECK);
        GOTO_EXIT_IF((GetVaildFlag(*(uint32_t *)(mgfParam->value), false) == false), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    return true;
EXIT:
    return false;
}

// Check whether the DSA parameter is approved
static bool DsaParamCheck(const CRYPT_EAL_PkeyC2Data *data)
{
    if (data->para == NULL) {
        return true;
    }
    uint32_t pLen = data->para->para.dsaPara.pLen;
    uint32_t qLen = data->para->para.dsaPara.qLen;
    // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapter 3
    // (L, N) = (2048, 224)，(2048, 256), 8 bits: 1 byte
    if ((pLen != 2048 / 8 || qLen != 224 / 8) && (pLen != 2048 / 8 || qLen != 256 / 8) &&
        // (L, N) = (3072, 256)
        (pLen != 3072 / 8 || qLen != 256 / 8)) {
        return false;
    }
    return true;
}

// Check whether the dh parameter is approved
static bool DhParamCheck(const CRYPT_EAL_PkeyC2Data *data)
{
    static const uint32_t list[] = {
        CRYPT_DH_RFC2409_768,
        CRYPT_DH_RFC2409_1024,
        CRYPT_DH_RFC3526_1536,
    };
    if (data->para != NULL) {
        uint32_t pLen = data->para->para.dhPara.pLen;
        uint32_t qLen = data->para->para.dhPara.qLen;
        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapter 5
        // (len(p), len(q)) = (2048, 224)
        // The length of p must be at least 2048 bits, and the length of q must be at least 224 bits.
        GOTO_EXIT_IF(((pLen != 2048 / 8 || qLen != 224 / 8) &&
            // (len(p), len(q)) = (2048, 256)
            (pLen != 2048 / 8 || qLen != 256 / 8)), CRYPT_CMVP_ERR_PARAM_CHECK);
    }
    if (data->paraId != CRYPT_PKEY_PARAID_MAX) {
        // The length of p must be at least 2048 bits, and the length of q must be at least 224 bits.
        for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
            GOTO_EXIT_IF((data->paraId == list[i]), CRYPT_CMVP_ERR_PARAM_CHECK);
        }
    }
    return true;
EXIT:
    return false;
}

static bool EccParamCheck(const CRYPT_EAL_PkeyC2Data *data)
{
    // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapters 3 and 5
    // Requires curve specified using SP 800-56A
    static const uint32_t list[] = {
        CRYPT_ECC_NISTP224,
        CRYPT_ECC_NISTP256,
        CRYPT_ECC_NISTP384,
        CRYPT_ECC_NISTP521,
        CRYPT_PKEY_PARAID_MAX,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (data->paraId == list[i]) {
            return true;
        }
    }
    return false;
}

bool ISO19790_AsymParamCheck(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data)
{
    // If the value is NULL, the interface does not need to check the algorithm parameters
    // and directly returns a success message.
    if (data == NULL) {
        return true;
    }

    switch (id) {
        case CRYPT_PKEY_DSA:
            GOTO_EXIT_IF(DsaParamCheck(data) != true, CRYPT_CMVP_ERR_PARAM_CHECK);
            break;
        case CRYPT_PKEY_RSA:
            GOTO_EXIT_IF(RsaParamCheck(data) != true, CRYPT_CMVP_ERR_PARAM_CHECK);
            break;
        case CRYPT_PKEY_DH:
            GOTO_EXIT_IF(DhParamCheck(data) != true, CRYPT_CMVP_ERR_PARAM_CHECK);
            break;
        case CRYPT_PKEY_ECDH:
        case CRYPT_PKEY_ECDSA:
            GOTO_EXIT_IF(EccParamCheck(data) != true, CRYPT_CMVP_ERR_PARAM_CHECK);
            break;
        default:
            break;
    }
    if (data->oper == CRYPT_EVENT_SIGN) {
        GOTO_EXIT_IF((GetVaildFlag(data->mdId, true) == false), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    if (data->oper == CRYPT_EVENT_VERIFY) {
        GOTO_EXIT_IF((GetVaildFlag(data->mdId, false) == false), CRYPT_CMVP_ERR_PARAM_CHECK);
        return true;
    }
    return true;
EXIT:
    return false;
}

bool ISO19790_MdParamCheck(CRYPT_MD_AlgId id)
{
    static const uint32_t list[] = {
        CRYPT_MD_SHA1,
        CRYPT_MD_SHA224,
        CRYPT_MD_SHA256,
        CRYPT_MD_SHA384,
        CRYPT_MD_SHA512,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (id == list[i]) {
            return true;
        }
    }
    return false;
}

bool ISO19790_CipherParamCheck(CRYPT_CIPHER_AlgId id)
{
    static const uint32_t list[] = {
        CRYPT_CIPHER_AES128_CBC, CRYPT_CIPHER_AES192_CBC, CRYPT_CIPHER_AES256_CBC,
        CRYPT_CIPHER_AES128_CTR, CRYPT_CIPHER_AES192_CTR, CRYPT_CIPHER_AES256_CTR,
        CRYPT_CIPHER_AES128_ECB, CRYPT_CIPHER_AES192_ECB, CRYPT_CIPHER_AES256_ECB,
        CRYPT_CIPHER_AES128_XTS, CRYPT_CIPHER_AES256_XTS,
        CRYPT_CIPHER_AES128_CCM, CRYPT_CIPHER_AES192_CCM, CRYPT_CIPHER_AES256_CCM,
        CRYPT_CIPHER_AES128_GCM, CRYPT_CIPHER_AES192_GCM, CRYPT_CIPHER_AES256_GCM,
        CRYPT_CIPHER_AES128_CFB, CRYPT_CIPHER_AES192_CFB, CRYPT_CIPHER_AES256_CFB,
        CRYPT_CIPHER_AES128_OFB, CRYPT_CIPHER_AES192_OFB, CRYPT_CIPHER_AES256_OFB,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (id == list[i]) {
            return true;
        }
    }

    return false;
}

bool ISO19790_MacParamCheck(CRYPT_MAC_AlgId id, uint32_t keyLen)
{
    static const uint32_t list[] = {
        CRYPT_MAC_HMAC_SHA1,
        CRYPT_MAC_HMAC_SHA224,
        CRYPT_MAC_HMAC_SHA256,
        CRYPT_MAC_HMAC_SHA384,
        CRYPT_MAC_HMAC_SHA512,
        CRYPT_MAC_CMAC_AES128,
        CRYPT_MAC_CMAC_AES192,
        CRYPT_MAC_CMAC_AES256,
        CRYPT_MAC_GMAC_AES128,
        CRYPT_MAC_GMAC_AES192,
        CRYPT_MAC_GMAC_AES256,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapter 10
        // Key lengths ≥ 112 bits
        if (id == list[i] && (keyLen >= (112 / 8))) {
            return true;
        }
    }

    return false;
}

bool ISO19790_KdfTls12ParamCheck(CRYPT_MAC_AlgId id, uint32_t keyLen)
{
    static const uint32_t list[] = {
        CRYPT_MAC_HMAC_SHA256,
        CRYPT_MAC_HMAC_SHA384,
        CRYPT_MAC_HMAC_SHA512,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapter 8
        // Key lengths ≥ 112 bits
        if (id == list[i] && (keyLen >= (112 / 8))) {
            return true;
        }
    }
    return false;
}

bool ISO19790_HkdfParamCheck(CRYPT_MAC_AlgId id, uint32_t keyLen)
{
    static const uint32_t list[] = {
        CRYPT_MAC_HMAC_SHA1,
        CRYPT_MAC_HMAC_SHA224,
        CRYPT_MAC_HMAC_SHA256,
        CRYPT_MAC_HMAC_SHA384,
        CRYPT_MAC_HMAC_SHA512
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf Chapter 8
        // Key lengths ≥ 112 bits
        if (id == list[i] && (keyLen >= (112 / 8))) {
            return true;
        }
    }
    return false;
}

bool ISO19790_PbkdfParamCheck(const CRYPT_EAL_Pbkdf2Param *param)
{
    static const uint32_t list[] = {
        CRYPT_MAC_HMAC_SHA1,
        CRYPT_MAC_HMAC_SHA224,
        CRYPT_MAC_HMAC_SHA256,
        CRYPT_MAC_HMAC_SHA384,
        CRYPT_MAC_HMAC_SHA512,
    };

    bool ret = false;
    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (param->macId == list[i]) {
            ret = true;
            break;
        }
    }
    if (!ret) {
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return false;
    }
    if (param->saltLen < 16) { // FIPS SP800-132 section 5,The salt value must contain at least 16 bytes.
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return false;
    }
    if (param->iter < 1000) { // FIPS SP800-132 section 5,The number of iterations must be at least 1000.
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return false;
    }
    if (param->dkeyLen < 14) { // FIPS SP800-132 section 5,The length of the derived key must be at least 14 bytes.
        BSL_ERR_PUSH_ERROR(CRYPT_ERR_ALGID);
        return false;
    }
    return true;
}

bool ISO19790_RandParamCheck(CRYPT_RAND_AlgId id)
{
    static const uint32_t list[] = {
        CRYPT_RAND_SHA1,
        CRYPT_RAND_SHA224,
        CRYPT_RAND_SHA256,
        CRYPT_RAND_SHA384,
        CRYPT_RAND_SHA512,
        CRYPT_RAND_HMAC_SHA1,
        CRYPT_RAND_HMAC_SHA224,
        CRYPT_RAND_HMAC_SHA256,
        CRYPT_RAND_HMAC_SHA384,
        CRYPT_RAND_HMAC_SHA512,
        CRYPT_RAND_AES128_CTR,
        CRYPT_RAND_AES192_CTR,
        CRYPT_RAND_AES256_CTR,
        CRYPT_RAND_AES128_CTR_DF,
        CRYPT_RAND_AES192_CTR_DF,
        CRYPT_RAND_AES256_CTR_DF,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (id == list[i]) {
            return true;
        }
    }

    return false;
}

#endif
