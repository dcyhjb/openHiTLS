/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_SM4_H
#define CRYPT_SM4_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_SM4

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "crypt_types.h"
#include "crypt_local_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CRYPT_SM4_BLOCKSIZE     16
#define CRYPT_SM4_BLOCKSIZE_16  256
#define CRYPT_SM4_ROUNDS 32

typedef struct {
    uint8_t iv[CRYPT_SM4_BLOCKSIZE];
    uint32_t rk[CRYPT_SM4_ROUNDS];
    bool safeMode; // Side channel security
} CRYPT_SM4_Ctx;

/**
 * TE(a,b,c,d) = LE(SBOX[a],SBOX[b],SBOX[c],SBOX[d])
 *             = LE(SBOX[a],0,0,0)⊕LE(0,SBOX[b],0,0)⊕LE(0,0,SBOX[c],0)⊕LE(0,0,0,SBOX[d])
 *             = LE(SBOX[a] << 24)⊕LE(SBOX[b] << 16)⊕LE(SBOX[c] << 8)⊕LE(SBOX[d])
 *             = LE(SBOX[a] <<< 24)⊕LE(SBOX[b] <<< 16)⊕LE(SBOX[c] <<< 8)⊕LE(SBOX[d])
 *             = (LE(SBOX[a]) <<< 24)⊕(LE(SBOX[b]) <<< 16)⊕(LE(SBOX[c]) <<< 8)⊕LE(SBOX[d])
 *             = (XBOX_0[a] <<< 24)⊕(XBOX_0[b] <<< 16)⊕(XBOX_0[c] <<< 8)⊕XBOX_0[d]
 *             = XBOX_3[a]⊕XBOX_2[b]⊕XBOX_1[c]⊕XBOX_0[d]
 * F(Xi,Xi+1,Xi+2,Xi+3,rki) = Xi⊕TE(Xi+1⊕Xi+2⊕Xi+3⊕rki)
 */
#define ROUND(t, x0, x1, x2, x3, rk, sbox)   \
    do {                                     \
        (t) = (x1) ^ (x2) ^ (x3) ^ (rk);     \
        (x0) ^= (sbox##_3)[((t) >> 24) & 0xff]; \
        (x0) ^= (sbox##_2)[((t) >> 16) & 0xff]; \
        (x0) ^= (sbox##_1)[((t) >> 8) & 0xff];  \
        (x0) ^= (sbox##_0)[(t) & 0xff];       \
    } while (0)

/**
 * @brief SM4 Set the encryption and decryption key.
 *
 * @param [IN] ctx       SM4 context
 * @param [IN] key       Key
 * @param [IN] keyLen    Key length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_SetKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t keyLen);

/**
 * @brief SM4 encryption. The data length must be an integer multiple of 16.
 *
 * @param [IN] ctx      SM4 context
 * @param [IN] in       Data to be encrypted
 * @param [OUT] out     Encrypted data
 * @param [IN] length   Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t length);

/**
 * @brief SM4 decryption. The data length must be an integer multiple of 16.
 *
 * @param [IN] ctx      SM4 context
 * @param [IN] in       Data to be decrypted
 * @param [OUT] out     Decrypted Data
 * @param [IN] length   Data length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t length);

/**
 * @brief Clear the SM4 context
 *
 * @param [IN] ctx sm4 context
 */
void CRYPT_SM4_Clean(CRYPT_SM4_Ctx *ctx);

/**
 * @brief SM4 Set the encryption key (optimized).
 *
 * @param [IN] ctx      SM4 context
 * @param [IN] key      Key
 * @param [IN] len      Key length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_SetEncryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief SM4 Set the decryption key (optimized).
 *
 * @param [IN] ctx      SM4 context
 * @param [IN] key      Key
 * @param [IN] len      Key length
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_SetDecryptKey(CRYPT_SM4_Ctx *ctx, const uint8_t *key, uint32_t len);

/**
 * @brief SM4 CBC mode encryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN] Length of the encrypted data
 * @param iv [IN] Set IV
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_CBC_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);

/**
 * @brief SM4 CBC mode decryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be decrypted
 * @param out [OUT] decrypted data
 * @param len [IN] Length of the decrypted data
 * @param iv [IN] Set IV
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_CBC_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);

/**
 * @brief SM4 CTR mode encryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be encrypted
 * @param out [OUT] Encrypted data
 * @param len [IN] Length of the encrypted data
 * @param iv [IN] Set IV
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_CTR_Encrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);

/**
 * @brief SM4 CTR mode decryption (optimized).
 * @param ctx [IN] sm4 Context
 * @param in [IN] Data to be decrypted
 * @param out [OUT] decrypted data
 * @param len [IN] Length of the decrypted data
 * @param iv [IN] Set IV
 *
 * @return Success: CRYPT_SUCCESS
 *         Other error codes are returned if the operation fails.
 */
int32_t CRYPT_SM4_CTR_Decrypt(CRYPT_SM4_Ctx *ctx, const uint8_t *in, uint8_t *out, uint32_t len, uint8_t *iv);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // HITLS_CRYPTO_SM4

#endif // CRYPT_SM4_H