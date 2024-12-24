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

#ifndef HITLS_X509_LOCAL_H
#define HITLS_X509_LOCAL_H

#include <stdint.h>
#include "bsl_asn1.h"
#include "bsl_obj.h"
#include "bsl_uio.h"
#include "hitls_pki.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "sal_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RFC 5280: section 4.1.2.5.1
 */
#define BSL_TIME_UTC_MAX_YEAR 2049

#define BSL_TIME_BEFORE_SET         0x01
#define BSL_TIME_AFTER_SET          0x02
#define BSL_TIME_BEFORE_IS_UTC      0x04
#define BSL_TIME_AFTER_IS_UTC       0x08

/* Identifies the current ext as a parsed state */
#define HITLS_X509_EXT_FLAG_PARSE (1 << 0)
/* Identifies the current ext as a generated state */
#define HITLS_X509_EXT_FLAG_GEN (1 << 1)

/* Identifies the keyusage extension in the current structure */
#define HITLS_X509_EXT_FLAG_KUSAGE (1 << 0)
/* Identifies the basic constraints extension in the current structure */
#define HITLS_X509_EXT_FLAG_BCONS (1 << 1)

#define HITLS_X509_GN_OTHER (HITLS_X509_GN_IP + 1)
#define HITLS_X509_GN_X400  (HITLS_X509_GN_OTHER + 1)
#define HITLS_X509_GN_EDI   (HITLS_X509_GN_X400 + 1)
#define HITLS_X509_GN_RID   (HITLS_X509_GN_EDI + 1)

typedef struct _HITLS_X509_NameNode {
    BSL_ASN1_Buffer nameType;
    BSL_ASN1_Buffer nameValue;
    uint8_t layer;
} HITLS_X509_NameNode;

typedef struct _HITLS_X509_ExtEntry {
    BslCid cid;
    BSL_ASN1_Buffer extnId;
    bool critical;
    BSL_ASN1_Buffer extnValue;
} HITLS_X509_ExtEntry;

typedef struct _HITLS_X509_CertExt {
    uint32_t extFlags; // Indicates which extensions exist
    // basic usage ext
    bool isCa;
    // -1 no check, 0 no intermediate certificate
    int32_t maxPathLen;
    // key usage ext
    uint32_t keyUsage;
} HITLS_X509_CertExt;

typedef enum {
    HITLS_X509_EXT_TYPE_CERT = 1,
    HITLS_X509_EXT_TYPE_CRL,
} HITLS_X509_ExtInnerType;

typedef struct _HITLS_X509_Ext {
    uint32_t flag; // Identifies the status of the current ext, generate or parse
    BslList *extList;
    uint32_t type;
    void *extData;
} HITLS_X509_Ext;

typedef struct _HITLS_X509_AttrEntry {
    BslCid cid;
    BSL_ASN1_Buffer attrId;
    BSL_ASN1_Buffer attrValue;
} HITLS_X509_AttrEntry;

typedef int32_t (*HITLS_X509_ParseAttrItemCb)(BslList *attrList, HITLS_X509_AttrEntry *attrEntry);

typedef int32_t (*HITLS_X509_EncodeAttrItemCb)(void *attrNode, HITLS_X509_AttrEntry *attrEntry);

typedef void *(*HITLS_X509_DupAttrItemCb)(const void *item);

typedef void (*HITLS_X509_FreeAttrItemCb)(void *item);
typedef struct _HITLS_X509_Attrs {
    uint8_t flag;
    BslList *list; // The list of HITLS_X509_AttrEntry
} HITLS_X509_Attrs;

typedef struct _HITLS_X509_ValidTime {
    uint8_t flag;
    BSL_TIME start;
    BSL_TIME end;
} HITLS_X509_ValidTime;

typedef struct _HITLS_X509_Asn1AlgId {
    BslCid algId;
    union {
        CRYPT_RSA_PssPara rsaPssParam;
        BSL_Buffer sm2UserId;
    };
} HITLS_X509_Asn1AlgId;

typedef int32_t (*HITLS_X509_Asn1Parse)(uint8_t **encode, uint32_t *encodeLen, void *out);
typedef void *(*HITLS_X509_New)(void);
typedef void (*HITLS_X509_Free)(void *elem);

typedef struct {
    HITLS_X509_Asn1Parse asn1Parse;
    HITLS_X509_New x509New;
    HITLS_X509_Free x509Free;
} X509_ParseFuncCbk;

int32_t HITLS_X509_ParseTbsRawData(uint8_t *encode, uint32_t encodeLen, uint8_t **tbsRawData, uint32_t *tbsRawDataLen);

// The public key  parsing is more complex, and the crypto module completes it
int32_t HITLS_X509_ParseSignAlgInfo(BSL_ASN1_Buffer *algId, BSL_ASN1_Buffer *param, HITLS_X509_Asn1AlgId *x509Alg);

int32_t HITLS_X509_EncodeSignAlgInfo(HITLS_X509_Asn1AlgId *x509Alg, BSL_ASN1_Buffer *asn);

void HITLS_X509_FreeNameNode(HITLS_X509_NameNode *node);

int32_t HITLS_X509_SetNameList(BslList **dest, void *val, int32_t valLen);

int32_t HITLS_X509_ParseNameList(BSL_ASN1_Buffer *name, BSL_ASN1_List *list);

int32_t HITLS_X509_EncodeNameList(BSL_ASN1_List *list, BSL_ASN1_Buffer *name);

int32_t HITLS_X509_ParseGeneralNames(uint8_t *encode, uint32_t encLen, BslList *list);

void HITLS_X509_FreeGeneralName(HITLS_X509_GeneralName *data);

void HITLS_X509_ClearGeneralNames(BslList *names);

int32_t HITLS_X509_ParseAuthorityKeyId(HITLS_X509_ExtEntry *extEntry, HITLS_X509_ExtAki *aki);

int32_t HITLS_X509_ParseSubjectKeyId(HITLS_X509_ExtEntry *extEntry, HITLS_X509_ExtSki *ski);

int32_t HITLS_X509_ParseExtendedKeyUsage(HITLS_X509_ExtEntry *extEntry, HITLS_X509_ExtExKeyUsage *exku);

void HITLS_X509_ClearExtendedKeyUsage(HITLS_X509_ExtExKeyUsage *exku);

int32_t HITLS_X509_ParseSubjectAltName(HITLS_X509_ExtEntry *extEntry,  HITLS_X509_ExtSan *san);

void HITLS_X509_ClearSubjectAltName(HITLS_X509_ExtSan *san);

HITLS_X509_Ext *X509_ExtNew(HITLS_X509_Ext *ext, int32_t type);

void X509_ExtFree(HITLS_X509_Ext *ext, bool isFreeOut);

int32_t HITLS_X509_ParseExt(BSL_ASN1_Buffer *ext, HITLS_X509_Ext *certExt);

int32_t HITLS_X509_EncodeExt(uint8_t tag, BSL_ASN1_List *list, BSL_ASN1_Buffer *ext);

int32_t HITLS_X509_ParseExtItem(BSL_ASN1_Buffer *extItem, HITLS_X509_ExtEntry *extEntry);

void HITLS_X509_ExtEntryFree(HITLS_X509_ExtEntry *entry);

int32_t HITLS_X509_AddListItemDefault(void *item, uint32_t len, BSL_ASN1_List *list);

int32_t HITLS_X509_ParseTime(BSL_ASN1_Buffer *before, BSL_ASN1_Buffer *after, HITLS_X509_ValidTime *time);

int32_t HITLS_X509_ParseX509(int32_t format, const BSL_Buffer *encode, bool isCert, X509_ParseFuncCbk *parsefun,
    HITLS_X509_List *list);
int32_t HITLS_X509_CmpNameNode(BSL_ASN1_List *nameOri, BSL_ASN1_List *name);

int32_t HITLS_X509_CheckAlg(CRYPT_EAL_PkeyCtx *pubkey, const HITLS_X509_Asn1AlgId *subAlg);

int32_t HITLS_X509_ParseAttrList(BSL_ASN1_Buffer *attrBuff, HITLS_X509_Attrs *attrs, HITLS_X509_ParseAttrItemCb parseCb,
    HITLS_X509_FreeAttrItemCb freeItem);

HITLS_X509_Attrs *HITLS_X509_AttrsDup(const HITLS_X509_Attrs *src, HITLS_X509_DupAttrItemCb dupCb,
    HITLS_X509_FreeAttrItemCb freeCb);

void HITLS_X509_AttrEntryFree(HITLS_X509_AttrEntry *attr);

int32_t HITLS_X509_SignAsn1Data(CRYPT_EAL_PkeyCtx *priv, CRYPT_MD_AlgId mdId,
    BSL_ASN1_Buffer *asn1Buff, BSL_Buffer *rawSignBuff, BSL_ASN1_BitString *sign);

HITLS_X509_Attrs *HITLS_X509_AttrsNew(void);

void HITLS_X509_AttrsFree(HITLS_X509_Attrs *attrs, HITLS_X509_FreeAttrItemCb freeItem);

int32_t HITLS_X509_EncodeAttrList(uint8_t tag, HITLS_X509_Attrs *attrs, HITLS_X509_EncodeAttrItemCb encodeCb,
    BSL_ASN1_Buffer *attrAsn1);

int32_t HITLS_X509_CheckSignature(const CRYPT_EAL_PkeyCtx *pubKey, uint8_t *rawData, uint32_t rawDataLen,
    const HITLS_X509_Asn1AlgId *alg, const BSL_ASN1_BitString *signature);

int32_t HITLS_X509_SetSm2UserId(BSL_Buffer *sm2UserId, void *val, int32_t valLen);

int32_t HITLS_X509_RefUp(BSL_SAL_RefCount *references, int32_t *val, int32_t valLen);

int32_t HITLS_X509_GetList(BslList *list, void *val, int32_t valLen);

int32_t HITLS_X509_GetPubKey(void *ealPubKey, void **val);

int32_t HITLS_X509_GetSignAlg(BslCid signAlgId, int32_t *val, int32_t valLen);

int32_t HITLS_X509_GetEncodeLen(uint32_t encodeLen, uint32_t *val, int32_t valLen);

int32_t HITLS_X509_GetEncodeData(uint8_t *rawData, uint8_t **val);

int32_t HITLS_X509_SetPkey(void **pkey, void *val);

int32_t HITLS_X509_ExtReplace(HITLS_X509_Ext *dest, HITLS_X509_Ext *src);

int32_t HITLS_X509_SetSerial(BSL_ASN1_Buffer *serial, const void *val, int32_t valLen);

int32_t HITLS_X509_GetSerial(BSL_ASN1_Buffer *serial, void *val, int32_t valLen);

typedef int32_t (*EncodeExtCb)(void *, HITLS_X509_ExtEntry *, const void *);

int32_t HITLS_X509_SetExtList(void *param, BslList *extList, BslCid cid, BSL_Buffer *val, EncodeExtCb encodeExt);

typedef int32_t (*DecodeExtCb)(HITLS_X509_ExtEntry *, void *);

int32_t HITLS_X509_GetExt(BslList *ext, BslCid cid, BSL_Buffer *val, uint32_t expectLen, DecodeExtCb decodeExt);

HITLS_X509_ExtEntry *X509_DupExtEntry(const HITLS_X509_ExtEntry *src);

bool X509_IsValidHashAlg(CRYPT_MD_AlgId id);

int32_t HITLS_X509_EncodeExtEntry(BSL_ASN1_List *list, BSL_ASN1_Buffer *ext);

int32_t HITLS_X509_CheckAki(HITLS_X509_Ext *issueExt, HITLS_X509_Ext *subjectExt, BSL_ASN1_List *subName,
    BSL_ASN1_Buffer *serialNum);

bool X509_CheckCmdVaild(int32_t *cmdSet, uint32_t cmdSize, int32_t cmd);

int32_t X509_ExtCtrl(HITLS_X509_Ext *ext, int32_t cmd, void *val, int32_t valLen);

typedef int32_t (*HITLS_X509_SignCb)(uint32_t mdId, CRYPT_EAL_PkeyCtx *prvKey, HITLS_X509_Asn1AlgId *signAlgId,
    void *obj);

int32_t HITLS_X509_Sign(uint32_t mdId, const CRYPT_EAL_PkeyCtx *prvKey, const HITLS_X509_SignAlgParam *algParam,
    void *obj, HITLS_X509_SignCb signCb);

#ifdef __cplusplus
}
#endif

#endif // HITLS_X509_LOCAL_H