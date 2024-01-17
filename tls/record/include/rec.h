/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef REC_H
#define REC_H

#include <stdbool.h>
#include <stdint.h>
#include "hitls_crypt_type.h"
#include "tls.h"

#ifdef __cplusplus
extern "C" {
#endif

#define REC_MAX_PLAIN_LENGTH 16384          /* Maximum plain length */
/* TLS13 Maximum MAC address padding */
#define REC_MAX_TLS13_ENCRYPTED_OVERHEAD  256u
/* TLS13 Maximum ciphertext length */
#define REC_MAX_TLS13_ENCRYPTED_LEN (REC_MAX_PLAIN_LENGTH + REC_MAX_TLS13_ENCRYPTED_OVERHEAD)

#define REC_MASTER_SECRET_LEN 48
#define REC_RANDOM_LEN  32

#define RECORD_HEADER 0x100
#define RECORD_INNER_CONTENT_TYPE 0x101
/**
 * record type
 */
typedef enum {
    REC_TYPE_CHANGE_CIPHER_SPEC = 20,
    REC_TYPE_ALERT = 21,
    REC_TYPE_HANDSHAKE = 22,
    REC_TYPE_APP = 23,
    REC_TYPE_UNKNOWN = 255
} REC_Type;

/**
 * SecurityParameters, used to generate keys and initialize the connect state
 */
typedef struct {
    bool isClient;                  /* Connection Endpoint */
    bool isClientTrafficSecret;     /* TrafficSecret type */
    HITLS_HashAlgo prfAlg;          /* prf_algorithm */
    HITLS_MacAlgo macAlg;           /* mac algorithm */
    HITLS_CipherAlgo cipherAlg;     /* symmetric encryption algorithm */
    HITLS_CipherType cipherType;    /* encryption algorithm type */

    /* key length */
    uint8_t fixedIvLength;          /* iv length. In TLS1.2 AEAD algorithm is the implicit IV length */
    uint8_t encKeyLen;              /* Length of the symmetric key */
    uint8_t macKeyLen;              /* MAC key length: If the AEAD algorithm is used, the MAC key length is 0 */

    uint8_t blockLength;            /* If the block length is not zero, the alignment should be handled. */
    uint8_t recordIvLength;         /* The explicit IV needs to be sent to the peer */
    uint8_t macLen;                 /*  MAC length. For AEAD, it is the mark length */

    uint8_t masterSecret[MAX_DIGEST_SIZE];             /* tls1.2 master key. TLS1.3 carries the TrafficSecret */
    uint8_t clientRandom[REC_RANDOM_LEN];              /* Client random number */
    uint8_t serverRandom[REC_RANDOM_LEN];              /* service random number */
} REC_SecParameters;

/**
 * @ingroup record
 * @brief   Record initialization
 *
 * @param   ctx [IN] TLS object
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 *
 */
int32_t REC_Init(TLS_Ctx *ctx);

/**
 * @ingroup record
 * @brief   record deinitialize
 *
 * @param   ctx [IN] TLS object
 */
void REC_DeInit(TLS_Ctx *ctx);

/**
 * @ingroup record
 * @brief   Check whether data exists in the read buffer of the reocrd
 *
 * @param   ctx [IN] TLS object
 * @return  whether data exists in the read buffer
 */
bool REC_ReadHasPending(const TLS_Ctx *ctx);

/**
 * @ingroup record
 * @brief   Reads a message in the unit of a record. Data is read from the uio of the CTX to the data pointer
 *
 * @attention recordType indicates the expected record type (app or handshake)
 *            readLen indicates the length of read data. The maximum length is REC_MAX_PLAIN_LENGTH (16384)
 * @param   ctx [IN] TLS object
 * @param   recordType [IN] Expected record type(app or handshake)
 * @param   data [OUT] Read buffer
 * @param   readLen [OUT] Length of the read data
 * @param   num [IN] The size of read buffer, which must be greater than or equal to the maximum size of the record
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION,Invalid null pointer
 * @retval  HITLS_REC_ERR_BUFFER_NOT_ENOUGH The buffer space is insufficient
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY indicates that the buffer is empty and needs to be read again
 * @retval  HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval  HITLS_REC_NORMAL_RECV_UNEXPECT_MSG An unexpected message is received and needs to be processed
 * @retval  HITLS_REC_ERR_SN_WRAPPING Sequence number wrap
 */
int32_t REC_Read(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *readLen, uint32_t num);

/**
 * @ingroup record
 * @brief   Write a record in the unit of record
 *
 * @attention If the value of num exceeds the maximum length of the record, return error
 *
 * @param   ctx [IN] TLS object
 * @param   recordType [IN] record type
 * @param   data [IN] Write data
 * @param   num [IN] Attempt to write num bytes of plaintext data
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 * @retval  HITLS_REC_ERR_BUFFER_NOT_ENOUGH The buffer space is insufficient
 * @retval  HITLS_MEMCPY_FAIL Memory copy failed
 * @retval  HITLS_REC_PMTU_TOO_SMALL The PMTU is too small
 * @retval  HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval  HITLS_REC_NORMAL_IO_BUSY I/O busy
 * @retval  HITLS_REC_ERR_TOO_BIG_LENGTH The length of the plaintext data written by the upper layer exceeds the
* maximum length of the plaintext data that can be written by a single record
 * @retval  HITLS_REC_ERR_NOT_SUPPORT_CIPHER The key algorithm is not supported
 * @retval  HITLS_REC_ERR_SN_WRAPPING Sequence number wrap
 */
int32_t REC_Write(TLS_Ctx *ctx, REC_Type recordType, const uint8_t *data, uint32_t num);

/**
 * @ingroup record
 * @brief   Initialize the pending state
 *
 * @param   ctx [IN] TLS object
 * @param   param [IN] Security parameter
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 *
 */
int32_t REC_InitPendingState(const TLS_Ctx *ctx, const REC_SecParameters *param);

/**
 * @ingroup record
 * @brief    Activate the pending state, switch the pending state to the current state
 *
 * @attention ctx cannot be empty
 * @param   ctx [IN] TLS object
 * @param   isOut [IN] Indicates whether is the output type
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 *
 */
int32_t REC_ActivePendingState(TLS_Ctx *ctx, bool isOut);

/**
 * @brief   Obtain the maximum writable plaintext length of a single record
 *
 * @param   ctx [IN] TLS_Ctx context
 * @param   len [OUT] Maximum length of the plaintext
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 * @retval  HITLS_REC_PMTU_TOO_SMALL The PMTU is too small
 */
int32_t REC_GetMaxWriteSize(const TLS_Ctx *ctx, uint32_t *len);

/**
 * @ingroup record
 * @brief   TLS13 Initialize the pending state
 *
 * @param   ctx [IN] TLS object
 * @param   param [IN] Security parameter
 * @param   isOut [IN] Indicates whether is the output type
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMALLOC_FAIL Memory allocated failed
 * @retval  HITLS_INTERNAL_EXCEPTION Invalid null pointer
 *
 */
int32_t REC_TLS13InitPendingState(const TLS_Ctx *ctx, const REC_SecParameters *param, bool isOut);

/**
 * @brief   read N bytes from tls record layer
 * @attention Currently, this interface is used only at the handshake layer
 and cannot process handshake message fragments.
 * @param   ctx [IN] TLS connection handle.
 * @param   recordType [IN] Buffer data
 * @param   buf [IN] Read data
 * @param   num [IN] Number of bytes expected to be read
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_MEMCPY_FAIL Memory Copy Failed
 * @retval  For details about other error codes, see hitls_error.h
 */
int32_t REC_TlsReadNbytes(TLS_Ctx *ctx, REC_Type recordType, uint8_t *buf, uint32_t num);

#ifdef __cplusplus
}
#endif

#endif /* REC_H */
