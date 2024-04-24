/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2024 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef HITLS_FUNC_H
#define HITLS_FUNC_H

#include "hlt_type.h"
#include "hitls_config.h"
#include "bsl_uio.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Hitls initialization
*/
int HitlsInit(void);

/**
* @brief HiTLS Create connection management resources.
*/
void* HitlsNewCtx(TLS_VERSION tlsVersion);

/**
* @brief HiTLS Releases connection management resources.
*/
void HitlsFreeCtx(void *ctx);

/**
* @brief HiTLS Setting connection information
*/
int HitlsSetCtx(HITLS_Config *config, HLT_Ctx_Config *ctxConfig);

/**
* @brief HiTLS Creating an SSL resource
*/
void* HitlsNewSsl(void *ctx);

/**
* @brief HiTLS Releases SSL resources.
*/
void HitlsFreeSsl(void *ssl);

/**
* @brief HiTLS Set TLS information.
*/
int HitlsSetSsl(void *ssl, HLT_Ssl_Config *sslConfig);

/**
* @brief HiTLS waits for a TLS connection.
*/
int HitlsAccept(void *ssl);

/**
* @brief The HiTLS initiates a TLS connection.
*/
int HitlsConnect(void *ssl);

/**
* @brief HiTLS writes data through the TLS connection.
*/
int HitlsWrite(void *ssl, uint8_t *data, uint32_t dataLen);

/**
* @brief HiTLS reads data through the TLS connection.
*/
int HitlsRead(void *ssl, uint8_t *data, uint32_t bufSize, uint32_t *readLen);

/**
* @brief HiTLS Disables the TLS connection.
*/
int HitlsClose(void *ssl);

/**
* @brief HiTLS supports renegotiation through TLS connection.
*/
int HitlsRenegotiate(void *ssl);

int HitlsSetMtu(void *ssl, uint16_t mtu);

int HitlsSetSession(void *ssl, void *session);
int HitlsSessionReused(void *ssl);
void *HitlsGet1Session(void *ssl);
int HitlsSessionHasTicket(void *session);
int HitlsSessionIsResumable(void *session);
void HitlsFreeSession(void *session);
int HitlsGetErrorCode(void *ssl);

/**
* @brief Obtaining method based on the connection type
*/
BSL_UIO_Method *GetDefaultMethod(BSL_UIO_TransportType type);

#ifdef __cplusplus
}
#endif

#endif // HITLS_FUNC_H
