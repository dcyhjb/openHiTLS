/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */
#ifndef REC_READ_H
#define REC_READ_H

#include <stdint.h>
#include "rec.h"
#include "rec_buf.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HITLS_NO_DTLS12

/**
 * @brief   Read a record in the DTLS protocol
 *
 * @param   ctx [IN] TLS context
 * @param   recordType [IN] Record type
 * @param   data [OUT] Read data
 * @param   len [OUT] Read data length
 * @param   bufSize [IN] buffer length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY needs to be read again
 * @retval  HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval  HITLS_REC_NORMAL_RECV_UNEXPECT_MSG Unexpected message received
 * @retval  HITLS_REC_NORMAL_RECV_DISORDER_MSG Receives out-of-order messages
 *
 */
int32_t DtlsRecordRead(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *len, uint32_t bufSize);

#endif

/**
 * @brief   Read a record in the TLS protocol
 *
 * @param   ctx [IN] TLS context
 * @param   recordType [IN] Record type
 * @param   data [OUT] Read data
 * @param   len [OUT] Read data length
 * @param   bufSize [IN] buffer length
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY needs to be read again
 * @retval  HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval  HITLS_REC_ERR_SN_WRAPPING Sequence number wrap
 * @retval  HITLS_REC_NORMAL_RECV_UNEXPECT_MSG Unexpected message received
 *
 */
int32_t TlsRecordRead(TLS_Ctx *ctx, REC_Type recordType, uint8_t *data, uint32_t *len, uint32_t bufSize);

/**
 * @brief   Read data from the UIO of the TLS context to the inBuf
 *
 * @param   ctx [IN] TLS context
 * @param   inBuf [IN]
 * @param   len [IN] len Length to be read
 *
 * @retval  HITLS_SUCCESS
 * @retval  HITLS_REC_ERR_IO_EXCEPTION I/O error
 * @retval  HITLS_REC_NORMAL_RECV_BUF_EMPTY needs to be read again
 */
int32_t StreamRead(TLS_Ctx *ctx, RecBuf *inBuf, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif