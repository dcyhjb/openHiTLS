/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include "crypt_eal_pkey.h"
#include "hlt_type.h"
#include "hitls_cert_type.h"
#include "hitls_cert.h"
#include "hitls_type.h"
#include "hitls_cert_reg.h"
#include "hitls_config.h"
#include "hitls_cert.h"
#include "hitls_cert_init.h"
#include "hlt_type.h"
#include "bsl_sal.h"
#include "bsl_log.h"
#include "bsl_err.h"
#include "logger.h"
#include "tls_config.h"
#include "tls.h"
#include "bsl_list.h"
#include "hitls_x509_adapter.h"

#define SUCCESS 0
#define ERROR (-1)
#define SINGLE_CERT_LEN (512)
#define CERT_FILE_LEN (4 * 1024)

int32_t RegCertCallback(CertCallbackType type)
{
    switch (type) {
        case CERT_CALLBACK_DEFAULT:
            HITLS_CertMethodInit();
            break;
        default:
            return ERROR;
    }
    return SUCCESS;
}

void BinLogFixLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType,
    void *format, void *para1, void *para2, void *para3, void *para4)
{
    (void)logLevel;
    (void)logType;
    printf("logId:%u\t", logId);
    printf(format, para1, para2, para3, para4);
    printf("\n");
    return;
}

void BinLogVarLenFunc(uint32_t logId, uint32_t logLevel, uint32_t logType, void *format, void *para)
{
    (void)logLevel;
    (void)logType;
    printf("logId:%u\t", logId);
    printf(format, para);
    printf("\n");
    return;
}

void RegDefaultMemCallback(void)
{
    BSL_SAL_MemCallback memMthod = {(void *(*)(uint32_t size))(uintptr_t)malloc, free};
    BSL_SAL_RegMemCallback(&memMthod);
    BSL_ERR_Init();
    BSL_LOG_SetBinLogLevel(BSL_LOG_LEVEL_DEBUG);
#ifdef TLS_DEBUG
    BSL_LOG_BinLogFuncs logFunc = { BinLogFixLenFunc, BinLogVarLenFunc };
    BSL_LOG_RegBinLogFunc(&logFunc);
#endif
    LOG_DEBUG("HiTLS RegDefaultMemCallback");
    return;
}

int32_t RegMemCallback(MemCallbackType type)
{
    switch (type) {
        case MEM_CALLBACK_DEFAULT : RegDefaultMemCallback(); break;
        default:
            return ERROR;
    }
    return SUCCESS;
}


typedef struct _HITLS_X509_Cert {
    bool isCopy;
    uint8_t *rawData;
    uint32_t rawDataLen;
    BSL_SAL_RefCount references;
} HITLS_X509_Cert;

#define HITLS_X509_List BslList

typedef struct _HITLS_X509_VerifyParam {
    int32_t maxDepth;
    uint64_t time;
    uint64_t flags;
} HITLS_X509_VerifyParam;

typedef struct _HITLS_X509_StoreCtx {
    HITLS_X509_List *store;
    HITLS_X509_List *crls;
    BSL_SAL_RefCount references;
    HITLS_X509_VerifyParam verifyParam;
} HITLS_X509_StoreCtx;

int32_t HiTLS_X509_CertAddCert(HITLS_CERT_Store *store, HITLS_CERT_X509 *cert)
{
    if (store == NULL) {
        return ERROR;
    }
    HITLS_X509_StoreCtx *tmpStore = (HITLS_X509_StoreCtx *)store;
    if (tmpStore->store == NULL) {
            tmpStore->store = BSL_LIST_New(sizeof(HITLS_X509_Cert));
            if (tmpStore->store == NULL) {
                return ERROR;
            }
        }
    if (cert != NULL) {
        if (BSL_LIST_AddElement(tmpStore->store, cert, BSL_LIST_POS_AFTER) != BSL_SUCCESS) {
            HITLS_X509_Adapt_StoreFree(tmpStore);
            return ERROR;
        }
    }
    return SUCCESS;
}

HITLS_CERT_X509 *HiTLS_X509_LoadCertFile(const char *file)
{
    FILE *f = fopen(file, "r");
    char fileContent[CERT_FILE_LEN] = {0};
    int c;
    if (f == NULL) {
        LOG_ERROR("fopen Error");
        return NULL;
    }

    for (int i = 0; i < CERT_FILE_LEN; i++) {
        c = fgetc(f);
        if (c != EOF) {
            fileContent[i] = c;
        } else {
            break;
        }
    }
    HITLS_CERT_X509 *cert = NULL; // load file content to cert
    (void)fclose(f);
    return cert;
}

void *HiTLS_X509_LoadCertListToStore(const char *fileList)
{
    int32_t ret;
    char certList[MAX_CERT_LEN] = {0};
    char certPath[SINGLE_CERT_LEN] = {0};

    ret = memcpy_s(certList, MAX_CERT_LEN, fileList, strlen(fileList));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error");
        return NULL;
    }

    void *store = HITLS_X509_Adapt_StoreNew();
    if(store == NULL){
        return NULL;
    }

    char *rest = NULL;
    char *token = strtok_s(certList, ":", &rest);
    do {
        (void)memset_s(certPath, SINGLE_CERT_LEN, 0, SINGLE_CERT_LEN);
        ret = sprintf_s(certPath, SINGLE_CERT_LEN, "%s%s", DEFAULT_CERT_PATH, token);
        if (ret <= 0) {
            LOG_ERROR("sprintf_s Error");
            HITLS_X509_Adapt_StoreFree(store);
            return NULL;
        }
        LOG_DEBUG("Load Cert Path is %s", certPath);

        HITLS_CERT_X509 *cert = HiTLS_X509_LoadCertFile(certPath);
        if (HiTLS_X509_CertAddCert(store, cert) != SUCCESS) {
            LOG_ERROR("X509_STORE_add_cert Error: path = %s.", certPath);
            HITLS_X509_Adapt_StoreFree(store);
            return NULL;
        }
        token = strtok_s(NULL, ":", &rest);
    } while (token != NULL);
    return store;
}

int32_t HITLS_X509_LoadEECertList(HITLS_Config *tlsCfg, const char *eeFileList, bool isEnc)
{
    int32_t ret;
    HITLS_CERT_X509 *cert = NULL;
    char certList[MAX_CERT_LEN] = {0};
    char certPath[SINGLE_CERT_LEN] = {0};

    ret = memcpy_s(certList, MAX_CERT_LEN, eeFileList, strlen(eeFileList));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error");
        return ERROR;
    }

    char *rest = NULL;
    char *token = strtok_s(certList, ":", &rest);
    do {
        (void)memset_s(certPath, SINGLE_CERT_LEN, 0, SINGLE_CERT_LEN);
        ret = sprintf_s(certPath, SINGLE_CERT_LEN, "%s%s", DEFAULT_CERT_PATH, token);
        if (ret <= 0) {
            LOG_ERROR("sprintf_s Error");
            return ERROR;
        }
        LOG_DEBUG("Load Cert Path is %s", certPath);

        cert = HiTLS_X509_LoadCertFile(certPath);
        if (cert == NULL) {
            LOG_ERROR("LoadCert Error: path = %s", certPath);
            return ERROR;
        }
        if (isEnc == true) {
#ifndef HITLS_NO_TLCP11
            ret = HITLS_CFG_SetTlcpCertificate(tlsCfg, cert, 0, isEnc);
#endif
        } else {
            ret = HITLS_CFG_SetCertificate(tlsCfg, cert, 0);
        }
        if (ret != SUCCESS) {
            LOG_ERROR("HITLS_CFG_SetCertificate Error: path = %s.", certPath);
            HITLS_X509_Adapt_CertFree(cert);
            return ERROR;
        }
        token = strtok_s(NULL, ":", &rest);
    } while (token != NULL);
    return SUCCESS;
}

int32_t HITLS_X509_LoadPrivateKeyList(HITLS_Config *tlsCfg, const char *keyFileList, bool isEnc)
{
    int32_t ret;
    HITLS_CERT_Key *key = NULL;
    char fileList[MAX_CERT_LEN] = {0};
    char filePath[SINGLE_CERT_LEN] = {0};

    ret = memcpy_s(fileList, MAX_CERT_LEN, keyFileList, strlen(keyFileList));
    if (ret != EOK) {
        LOG_ERROR("memcpy_s Error");
        return ERROR;
    }

    char *rest = NULL;
    char *token = strtok_s(fileList, ":", &rest);
    do {
        (void)memset_s(filePath, SINGLE_CERT_LEN, 0, SINGLE_CERT_LEN);
        ret = sprintf_s(filePath, SINGLE_CERT_LEN, "%s%s", DEFAULT_CERT_PATH, token);
        if (ret <= 0) {
            LOG_ERROR("sprintf_s Error");
            return ERROR;
        }
        LOG_DEBUG("Load Cert Path is %s", filePath);

        key = HITLS_X509_Adapt_KeyParse(tlsCfg, filePath, strlen(filePath), TLS_PARSE_TYPE_FILE, TLS_PARSE_FORMAT_PEM);
        if (key == NULL) {
            LOG_ERROR("LoadCert Error: path = %s.", filePath);
            return ERROR;
        }
        if (isEnc == true) {
#ifndef HITLS_NO_TLCP11
            ret = HITLS_CFG_SetTlcpPrivateKey(tlsCfg, key, 0, isEnc);
#endif
        } else {
            ret = HITLS_CFG_SetPrivateKey(tlsCfg, key, 0);
        }
        if (ret != SUCCESS) {
            LOG_ERROR("HITLS_CFG_SetCertificate Error: path = %s.", filePath);
            CRYPT_EAL_PkeyFreeCtx(key);
            return ERROR;
        }
        token = strtok_s(NULL, ":", &rest);
    } while (token != NULL);
    return SUCCESS;
}

void HITLS_X509_FreeCert(HITLS_CERT_Store *caStore, HITLS_CERT_Store *chainStore)
{
    if (caStore != NULL) {
        HITLS_X509_Adapt_StoreFree(caStore);
    }
    if (chainStore != NULL) {
        HITLS_X509_Adapt_StoreFree(chainStore);
    }
    return;
}

int32_t HiTLS_X509_LoadCertAndKey(HITLS_Config *tlsCfg, const char *caFile, const char *chainFile,
    const char *eeFile, const char *signFile, const char *privateKeyFile, const char *signPrivateKeyFile)
{
    int32_t ret;
    if ((caFile != NULL) && (strncmp(caFile, "NULL", strlen(caFile)) != 0)) {
        HITLS_CERT_Store *caStore = HiTLS_X509_LoadCertListToStore(caFile);
        if (caStore == NULL) {
            return ERROR;
        }
        ret = HITLS_CFG_SetCertStore(tlsCfg, caStore, 0);
        if (ret != SUCCESS) {
            HITLS_X509_Adapt_StoreFree(caStore);
            return ret;
        }
    }

    if ((chainFile != NULL) && (strncmp(chainFile, "NULL", strlen(chainFile)) != 0)) {
        HITLS_CERT_Store *chainStore = HiTLS_X509_LoadCertListToStore(chainFile);
        if (chainStore == NULL) {
            return ERROR;
        }
        ret = HITLS_CFG_SetChainStore(tlsCfg, chainStore, 0);
        if (ret != SUCCESS) {
            HITLS_X509_Adapt_StoreFree(chainStore);
            return ret;
        }
    }

    bool hasTlcpSignCert = ((signFile != NULL) && (strncmp(signFile, "NULL", strlen(signFile)) != 0));
    if (hasTlcpSignCert) {
        ret = HITLS_X509_LoadEECertList(tlsCfg, signFile, false);
        if (ret != SUCCESS) {
            return ret;
        }
    }

	if ((eeFile != NULL) && (strncmp(eeFile, "NULL", strlen(eeFile)) != 0)) {
            ret = HITLS_X509_LoadEECertList(tlsCfg, eeFile, hasTlcpSignCert);
            if (ret != SUCCESS) {
                return ret;
            }
	}

    if ((signPrivateKeyFile != NULL) && (strncmp(signPrivateKeyFile, "NULL", strlen(signPrivateKeyFile)) != 0)) {
        ret = HITLS_X509_LoadPrivateKeyList(tlsCfg, signPrivateKeyFile, false);
        if (ret != SUCCESS) {
            return ret;
        }
        if ((privateKeyFile != NULL) && (strncmp(privateKeyFile, "NULL", strlen(eeFile)) != 0)) {
            ret = HITLS_X509_LoadPrivateKeyList(tlsCfg, privateKeyFile, true);
            if (ret != SUCCESS) {
                return ret;
            }
        }
    } else {
        if ((privateKeyFile != NULL) && (strncmp(privateKeyFile, "NULL", strlen(eeFile)) != 0)) {
            ret = HITLS_X509_LoadPrivateKeyList(tlsCfg, privateKeyFile, false);
            if (ret != SUCCESS) {
                return ret;
            }
        }
    }
    return SUCCESS;
}