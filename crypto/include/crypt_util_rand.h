/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

#ifndef CRYPT_UTIL_RAND_H
#define CRYPT_UTIL_RAND_H

#include "hitls_build.h"
#if defined(HITLS_CRYPTO_DRBG) || defined(HITLS_CRYPTO_CURVE448) || defined(HITLS_CRYPTO_CURVE25519) || \
    defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_BN)

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*CRYPT_RandFunc)(uint8_t *rand, uint32_t randLen);

/**
 * @brief   Random number registration
 *
 * @param   func [IN] Interface for obtaining random numbers
 */
void CRYPT_RandRegist(CRYPT_RandFunc func);

/**
 * @brief   Generate a random number
 *
 * @param   rand [OUT] buffer of random number
 * @param   randLen [IN] length of random number
 *
 * @retval  CRYPT_SUCCESS           A random number is generated successfully.
 * @retval  CRYPT_NO_REGIST_RAND    The random number function is not registered.
 * @retval  Error returned when the registered random number fails during the generate.
 */
int32_t CRYPT_Rand(uint8_t *rand, uint32_t randLen);

#ifdef __cplusplus
}
#endif

#endif

#endif