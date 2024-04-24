/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef COMMON_FUNC_H
#define COMMON_FUNC_H

#include "hlt_type.h"
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EE_CERT,
    PRIVE_KEY,
    CA_CERT,
    CHAIN_CERT
} CERT_TYPE;

typedef struct {
    atomic_int mallocCnt;
    atomic_int freeCnt;
    atomic_int mallocSize;
    atomic_int freeSize;
    atomic_int maxMemSize;
} MemCnt;

/**
* @brief Load a certificate from a file.
*/
int LoadCertFromFile(void *ctx, char *pCert, CERT_TYPE certType);

/**
* @brief Memory application that contains the count
*/
void *CountMalloc(uint32_t len);

/**
* @brief Memory release that contains the count
*/
void CountFree(void *addr);

/**
* @brief Clear the memory count.
*/
void ClearMemCntData(void);

/**
* @brief Obtain the memory count.
*/
MemCnt *GetMemCntData(void);

int32_t ExampleSetPsk(char *psk);

uint32_t ExampleClientCb(HITLS_Ctx *ctx, const uint8_t *hint, uint8_t *identity, uint32_t maxIdentityLen,
    uint8_t *psk, uint32_t maxPskLen);

uint32_t ExampleServerCb(HITLS_Ctx *ctx, const uint8_t *identity, uint8_t *psk, uint32_t maxPskLen);

int32_t ExampleTicketKeySuccessCb(uint8_t *keyName, uint32_t keyNameSize, void *cipher, uint8_t isEncrypt);
int32_t ExampleTicketKeyRenewCb(uint8_t *keyName, uint32_t keyNameSize, void *cipher, uint8_t isEncrypt);
void *GetTicketKeyCb(char *str);

void *GetExtensionCb(const char *str);
void *GetExampleData(const char *str);

int32_t NoSecRenegotiationCb_Success(HITLS_Ctx *ctx);
int32_t NoSecRenegotiationCb_Fail(HITLS_Ctx *ctx);
void *GetNoSecRenegotiationCb(const char *str);

#ifdef __cplusplus
}
#endif

#endif // COMMON_FUNC_H