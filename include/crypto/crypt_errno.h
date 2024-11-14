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

/**
 * @defgroup crypt_errno
 * @ingroup crypt
 * @brief error number module of crypto module
 */

#ifndef CRYPT_ERRNO_H
#define CRYPT_ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup crypt_errno
 * @brief   Return success
 */
#define CRYPT_SUCCESS 0

/**
 * @ingroup crypt_errno
 *
 * CRYPTO module return value.
 */
enum CRYPT_ERROR {
    CRYPT_NULL_INPUT = 0x01010001,      /**< Null pointer input error, bufferLen is 0. */
    CRYPT_SECUREC_FAIL,                 /**< Security function  returns an error. */
    CRYPT_MEM_ALLOC_FAIL,               /**< Failed to apply for memory. */
    CRYPT_NO_REGIST_RAND,               /**< The global random number is not registered.*/
    CRYPT_ERR_ALGID,                    /**< Incorrect algorithm ID. */
    CRYPT_INVALID_ARG,                  /**< Invalid input parameter. */
    CRYPT_NOT_SUPPORT,

    CRYPT_BN_BUFF_LEN_NOT_ENOUGH = 0x01020001, /**< Insufficient buffer length. */
    CRYPT_BN_SPACE_NOT_ENOUGH,          /**< Insufficient big number space. */
    CRYPT_BN_BITS_TOO_MAX,              /**< The maximum bit limit is exceeded of the big number. */
    CRYPT_BN_RAND_GEN_FAIL,             /**< Failed to generate the random number. */
    CRYPT_BN_OPTIMIZER_STACK_FULL,      /**< Optimizer stack is full. */
    CRYPT_BN_NO_NEGATIVE_ZERO,          /**< The big number is set to a positive number only. */
    CRYPT_BN_ERR_RAND_ZERO,             /**< Generates a random number smaller than 0. */
    CRYPT_BN_ERR_RAND_NEGATIVE,         /**< Generate a negative random number. */
    CRYPT_BN_ERR_RAND_TOP_BOTTOM,       /**< The top or bottom is invalid during random number generation. */
    CRYPT_BN_ERR_RAND_BITS_NOT_ENOUGH,  /**< The bit is too small during random number generation. */
    CRYPT_BN_OPTIMIZER_GET_FAIL,        /**< Failed to obtain the space from the optimizer. */
    CRYPT_BN_ERR_DIVISOR_ZERO,          /**< The divisor cannot be 0. */
    CRYPT_BN_ERR_EXP_NO_NEGATIVE,       /**< The value of exponent cannot be negative. */
    CRYPT_BN_MONT_BASE_TOO_MAX,         /**< Montgomery module exponentiation base is too large. */
    CRYPT_BN_NOR_GEN_PRIME,             /**< Prime Number Generation Failure. */
    CRYPT_BN_NOR_CHECK_PRIME,           /**< prime number check failed. */
    CRYPT_BN_ERR_GCD_NO_ZERO,           /**< The maximum common divisor cannot contain 0. */
    CRYPT_BN_ERR_NO_INVERSE,            /**< Cannot obtain the inverse module. */
    CRYPT_BN_ERR_SQRT_PARA,             /**< The parameter is incorrect when modulus square root. */
    CRYPT_BN_ERR_LEGENDE_DATA,          /**< Failed to find a specific number for z to p's Legendre sign (z|p)
                                             equal to -1 when calculating the square root. */
    CRYPT_BN_ERR_NO_SQUARE_ROOT,        /**< The square root cannot be found. */
    CRYPT_BN_ERR_MASKCOPY_LEN,          /**< Data lengths are inconsistent when data is copied with masks. */
    CRYPT_BN_ERR_QUICK_MODDATA,         /**< Uses the BN_ModNistEccMul and BN_ModNistEccSqr interfaces,
                                             the module data is not supported. */
    CRYPT_BN_BITS_INVALID,              /**< The bits of the big number exceeds the limit. */

    CRYPT_RSA_BUFF_LEN_NOT_ENOUGH = 0x01030001, /**< The buffer length is insufficient. */
    CRYPT_RSA_NO_KEY_INFO,              /**< Lacks valid key information. */
    CRYPT_RSA_ERR_KEY_BITS,             /**< Incorrect key length. */
    CRYPT_RSA_ERR_E_VALUE,              /**< The value of parameter e is incorrect. */
    CRYPT_RSA_NOR_KEYGEN_FAIL,          /**< Key generation failure, it's normal error. */
    CRYPT_RSA_NOR_VERIFY_FAIL,          /**< Failed to verify the signature. it's normal error. */
    CRYPT_RSA_ERR_ENC_BITS,             /**< Incorrect length of the encrypted plaintext of the public key. */
    CRYPT_RSA_ERR_DEC_BITS,             /**< Incorrect length of the decrypted ciphertext of the private key. */
    CRYPT_RSA_ERR_PSS_SALT_LEN,         /**< Incorrect salt length of the PSS operation. */
    CRYPT_RSA_ERR_PSS_SALT_DATA,        /**< PSS operation salt data error, failed to compare the salt extracted
                                             during signature verification with the user's input. */
    CRYPT_RSA_ERR_INPUT_VALUE,          /**< Some special values, which are used as input errors. */
    CRYPT_RSA_ERR_MD_ALGID,             /**< The hash ID of the input parameter is incorrect when
                                             the pkcs1.5 padding mode is set. */
    CRYPT_RSA_PAD_NO_SET_ERROR,         /**< Padding information is not set when using RSA key for
                                             signature verification. */
    CRYPT_RSA_CTRL_NOT_SUPPORT_ERROR,   /**< The Ctrl type is not supported When RSA is used for Ctrl. */
    CRYPT_RSA_SET_SALT_NOT_PSS_ERROR,   /**< When the padding type of the key is not pss, and set the salt
                                             information, return failure. */
    CRYPT_RSA_SET_EMS_PKCSV15_LEN_ERROR,/**< Sets the PKCSV15 padding information, the length of the input data
                                             is incorrect and return failure. */
    CRYPT_RSA_SET_EMS_PSS_LEN_ERROR,    /**< Sets the PSS padding information, the length of the input data is
                                             incorrect, and return failure. */
    CRYPT_RSA_SET_RSAES_OAEP_LEN_ERROR, /**< Sets the OAEP padding information, the length of the input data
                                             is incorrect and return failure. */
    CRYPT_RSA_SET_FLAG_LEN_ERROR,       /**< The length of the input data is incorrect and return failure When
                                             sets the flag. */
    CRYPT_RSA_FLAG_NOT_SUPPORT_ERROR,   /**< Unsupported flag. */
    CRYPT_RSA_ERR_SALT_LEN,             /**< Salt length error. */
    CRYPT_RSA_ERR_ALGID,                /**< The hash ID of the input parameter is incorrect or conflict occurs when
                                             sets the signature, signature verification, and padding parameters. */
    CRYPT_RSA_ERR_GEN_SALT,             /**< An error is returned when salt information fails to be generated
                                             during PSS signature. */
    CRYPT_RSA_ERR_ENC_INPUT_NOT_ENOUGH, /**< The plaintext length is too short for RSA NO PAD encryption. */
    CRYPT_RSA_PUBKEY_NOT_EQUAL,         /**< RSA public keys are not equal. */

    CRYPT_EAL_BUFF_LEN_NOT_ENOUGH = 0x01040001, /**< Insufficient buffer length. */
    CRYPT_EAL_ERR_ALGID,                /**< Incorrect algorithm ID. */
    CRYPT_EAL_ALG_NOT_SUPPORT,          /**< Algorithm not supported, algorithm behavior not supported. */
    CRYPT_EAL_ERR_NEW_PARA_FAIL,        /**< Failed to generate parameters. */
    CRYPT_EAL_ERR_RAND_WORKING,         /**< DRBG is in the working state. */
    CRYPT_EAL_ERR_RAND_NO_WORKING,      /**< DRBG is not working. */
    CRYPT_EAL_ERR_METH_NULL_NUMBER,     /**< The method variable member is NULL. */
    CRYPT_EAL_ERR_GLOBAL_DRBG_NULL,     /**< The global DRBG is null. */
    CRYPT_EAL_ERR_DRBG_REPEAT_INIT,     /**< DRBG is initialized repeatedly. */
    CRYPT_EAL_ERR_DRBG_INIT_FAIL,       /**< DRBG initialization failure. */
    CRYPT_EAL_ERR_STATE,                /**< The usage process is incorrect. For example, run the update
                                             command without running the init command.
                                             For details, see related algorithms. */
    CRYPT_EAL_CIPHER_DATA_ERROR,        /**< Data error occurs when unpadding the decrypted data.
                                             For X923, the last bit is the length of the original data, and the
                                             rest data is 0, if this requirement is not met, an error is reported.
                                             For pkcs, all padding data is
                                             (the length of the padding data - the length of the original data),
                                             if this requirement is not met,an error will be reported.
                                             For ISO7816, the first bit of padding data is 0x80, and the other bits
                                             are 0, if this requirement is not met, an error will be reported. */
    CRYPT_EAL_PADDING_NOT_SUPPORT,      /**< Unsupported padding. */
    CRYPT_EAL_CIPHER_CTRL_ERROR,        /**< CRYPT_EAL_CipherCtrl interface unsupported CTRL type. */
    CRYPT_EAL_CIPHER_FIANL_WITH_AEAD_ERROR,  /**< An error occurs when the final operation is performed on the
                                                  AEAD algorithm. */
    CRYPT_EAL_PKEY_CTRL_ERROR,          /**< When the CRYPT_EAL_PkeyCtrl interface performs CTRL,
                                             the function is not supported or the input length is incorrect. */
    CRYPT_EAL_PKEY_DUP_ERROR,           /**< Pkey context duplicate failure. */
    CRYPT_EAL_PKEY_CMP_DIFF_KEY_TYPE,   /**< Pkey comparison failure: different algorithm types. */
    CRYPT_EAL_ERR_PART_OVERLAP,         /**< Some memory overlap. */
    CRYPT_EAL_INTO_TYPE_NOT_SUPPORT,    /**< The info type is not supported. */
	CRYPT_EAL_ALG_ASM_NOT_SUPPORT,      /**< Algorithm assembly is not supported. */

    CRYPT_SHA2_INPUT_OVERFLOW = 0x01050001, /**< The length of the input data exceeds the maximum
                                                     processing range of SHA2. */
    CRYPT_SHA2_OUT_BUFF_LEN_NOT_ENOUGH,     /**< The length of the buffer that storing the output
                                             result is insufficient. */

    CRYPT_DRBG_ERR_STATE = 0x01060001,  /**< DRBG status error. */
    CRYPT_DRBG_FAIL_GET_ENTROPY,        /**< Failed to obtain the entropy. */
    CRYPT_DRBG_FAIL_GET_NONCE,          /**< Failed to obtain the nonce. */
    CRYPT_DRBG_ALG_NOT_SUPPORT,         /**< Does not support the given algorithm. */
    CRYPT_DRBG_INVALID_LEN,             /**< Incorrect data length. */

    CRYPT_CURVE25519_NO_PUBKEY = 0x01070001,         /**< No public key. */
    CRYPT_CURVE25519_NO_PRVKEY,                      /**< No private key. */
    CRYPT_CURVE25519_KEYLEN_ERROR,                   /**< Incorrect key length. */
    CRYPT_CURVE25519_SIGNLEN_ERROR,                  /**< Incorrect signature length. */
    CRYPT_CURVE25519_HASH_METH_ERROR,                /**< Hash method is not SHA512. */
    CRYPT_CURVE25519_VERIFY_FAIL,                    /**< Signature verification fails due to incorrect signature. */
    CRYPT_CURVE25519_NO_HASH_METHOD,                 /**< Hash method not set. */
    CRYPT_CURVE25519_UNSUPPORTED_CTRL_OPTION,        /**< Unsupported mode of operation. */
    CRYPT_CURVE25519_KEY_COMPUTE_FAILED,             /**< Failed to generate the shared key. */
    CRYPT_CURVE25519_INVALID_PUBKEY,                 /**< Invalid public key. */
    CRYPT_CURVE25519_PUBKEY_NOT_EQUAL,               /**< Public keys are not equal. */

    CRYPT_SHA1_INPUT_OVERFLOW = 0x01080001,          /**< The length of the input data exceeds the
                                                           maximum processing range of SHA1. */
    CRYPT_SHA1_OUT_BUFF_LEN_NOT_ENOUGH,              /**< The length of the buffer that storing
                                                          the output result is insufficient. */

    CRYPT_ENTROPY_CONDITION_FAILURE = 0x01090001,    /**< Processing method error after invoking. */
    CRYPT_ENTROPY_RANGE_ERROR,                       /**< Entropy source generation range error */
    CRYPT_ENTROPY_ECF_ALG_ERROR,                     /**< Entropy source conditioning algorithm is incorrect. */

    CRYPT_DSA_BUFF_LEN_NOT_ENOUGH = 0x010A0001, /**< Insufficient buffer length. */
    CRYPT_DSA_ERR_KEY_PARA,                     /**< Incorrect key parameter data. */
    CRYPT_DSA_ERR_KEY_INFO,                     /**< Incorrect key information. */
    CRYPT_DSA_VERIFY_FAIL,                      /**< Verification failure. */
    CRYPT_DSA_ERR_TRY_CNT,                      /**< Key generation and signature fail to be
                                                     generated within the specified number of attempts. */
    CRYPT_DSA_DECODE_FAIL,                      /**< Data decoding fails, the data does not meet
                                                     the decoding requirements. */
    CRYPT_DSA_PARA_ERROR,                       /**< The value of the key parameter does not meet
                                                     the requirements. The ctx command does not
                                                     contain necessary parameter information. */
    CRYPT_DSA_PUBKEY_NOT_EQUAL,                 /**< Public keys are not equal. */
    CRYPT_DSA_PARA_NOT_EQUAL,                   /**< Key parameters are not equal. */
    CRYPT_DSA_UNSUPPORTED_CTRL_OPTION,          /**< Unsupported mode of operation. */

    CRYPT_HMAC_OUT_BUFF_LEN_NOT_ENOUGH = 0x010B0001, /**< The length of the buffer that storing
                                                          the output result is insufficient. */

    CRYPT_DH_BUFF_LEN_NOT_ENOUGH = 0x010C0001,   /**< The buffer length is insufficient. */
    CRYPT_DH_PARA_ERROR,                         /**< The value of the key parameter does not meet
                                                      the requirements, the ctx command does not
                                                      contain necessary parameter information. */
    CRYPT_DH_KEYINFO_ERROR,                      /**< The value of the public and private keys do
                                                      not meet the requirements, the ctx does not
                                                      contain the necessary public and private keys. */
    CRYPT_DH_RAND_GENERATE_ERROR,                /**< Key generation fails within the specified
                                                      number of attempts. */
    CRYPT_DH_PAIRWISE_CHECK_FAIL,                /**< The public and private keys are inconsistent. */
    CRYPT_DH_CREATE_PARA_FAIL,                   /**< Failed to create the p, q, and g parameters
                                                      of the DH algorithm. */
    CRYPT_DH_PUBKEY_NOT_EQUAL,                   /**< Public keys are not equal. */
    CRYPT_DH_PARA_NOT_EQUAL,                     /**< DH key parameters are not equal. */
    CRYPT_DH_UNSUPPORTED_CTRL_OPTION,            /**< Unsupported mode of operation. */

    CRYPT_CHACHA20_KEYLEN_ERROR = 0x010D0001,        /**< The key length input is incorrect during key setting. */
    CRYPT_CHACHA20_NONCELEN_ERROR,                   /**< The length of the input nounce is incorrect when you
                                                          set the nounce. */
    CRYPT_CHACHA20_COUNTLEN_ERROR,                   /**< The length of the input count is incorrect when you
                                                          set the count. */
    CRYPT_CHACHA20_NO_KEYINFO,                       /**< Lack of valid key information during
                                                          encryption and decryption. */
    CRYPT_CHACHA20_NO_NONCEINFO,                     /**< Lack of valid nounce information during
                                                          encryption and decryption. */
    CRYPT_CHACHA20_CTRLTYPE_ERROR,                   /**< The input type is not supported when the
                                                          ctrl interface is used. */

    CRYPT_AES_ERR_KEYLEN = 0x010E0001,               /**< Incorrect key length. */

    CRYPT_MODES_TAGLEN_ERROR = 0x010F0001,           /**< In AEAD mode, the length of the TAG
                                                          is incorrect when the tag is obtained and verified. */
    CRYPT_MODES_IVLEN_ERROR,                         /**< The length of the input IV is incorrect
                                                          when setting the IV. */
    CRYPT_MODES_KEYUSE_TOOMANY_TIME,                 /**< In GCM mode, the number of times that a key
                                                          can be used for encryption and decryption is limited.
                                                          When the number of times that a key is used exceeds
                                                          the limit, an error is reported. */
    CRYPT_MODES_CRYPTLEN_OVERFLOW,                   /**< In AEAD mode, the length of the plaintext
                                                          or ciphertext input for a single
                                                          encryption exceeds the limit. */
    CRYPT_MODES_CTRL_TAGLEN_ERROR,                   /**< In GCM or CCM mode, the length of the input
                                                          parameter or the length of the input
                                                          parameter data is incorrect when the ctrl
                                                          interface is used to set the tag length. */
    CRYPT_MODES_AAD_REPEAT_SET_ERROR,                /**< In the AEAD mode, the AAD information
                                                          is set repeatedly. */
    CRYPT_MODE_BUFF_LEN_NOT_ENOUGH,                  /**< The buffer length is insufficient. */
    CRYPT_MODE_ERR_INPUT_LEN,                        /**< The function input length is not the
                                                          expected length. */
    CRYPT_MODES_CTRL_TYPE_ERROR,                     /**< The input type is not supported when the ctrl
                                                          interface is used. */
    CRYPT_MODES_AAD_IS_SET_ERROR,                    /**< In ccm mode, an error is returned when the tagLen and
                                                          msgLen are set after the aad is set. */
    CRYPT_MODES_MSGLEN_OVERFLOW,                     /**< In ccm mode, the length of the input message during
                                                          encryption and decryption exceeds the set msgLen. */
    CRYPT_MODES_CTRL_MSGLEN_ERROR,                   /**< In ccm mode, When the ctrl interface is used to set the
                                                          msg length, the input parameter length or the input
                                                          parameter data length is incorrect. (This
                                                          specification is affected by ivLen.) */
    CRYPT_MODES_MSGLEN_LEFT_ERROR,                   /**< In ccm mode, when the ctrl interface is used to
                                                          obtain the tag, the length of the encrypted and
                                                          decrypted messages does not reach the configured
                                                          number. As a result, an error occurs. */
    CRYPT_MODES_ERR_KEYLEN,                          /**< Incorrect key length set. */
    CRYPT_MODES_ERR_KEY,                             /**< Incorrect key set. */
    CRYPT_MODES_ERR_FEEDBACKSIZE,                    /**< The operation are not support by the algorithm
                                                          on which the pattern depends on. */
    CRYPT_MODES_METHODS_NOT_SUPPORT,                 /**< Mode depends does not support the behavior. */
	CRYPT_MODES_FEEDBACKSIZE_NOT_SUPPORT,            /**< The algorithm does not support the setting of feedbacksize. */

    CRYPT_HKDF_DKLEN_OVERFLOW = 0x01100001,          /**< The length of the derived key exceeds the maximum. */
    CRYPT_HKDF_NOT_SUPPORTED,                        /**< Unsupport HKDF algorithm. */
    CRYPT_HKDF_PARAM_ERROR,                          /**< Incorrect input parameter. */

    CRYPT_SCRYPT_PARAM_ERROR = 0x01110001,           /**< Incorrect input parameter. */
    CRYPT_SCRYPT_NOT_SUPPORTED,                      /**< Unsupport the SCRYPT algorithm. */
    CRYPT_SCRYPT_DATA_TOO_MAX,                       /**< The data calculated by the SCRYPT algorithm is too large. */

    CRYPT_PBKDF2_PARAM_ERROR = 0x01120001,           /**< Incorrect input parameter. */
    CRYPT_PBKDF2_NOT_SUPPORTED,                      /**< Does not support the PBKDF2 algorithm. */

    CRYPT_ECC_POINT_AT_INFINITY = 0x01130001,         /**< Point at infinity. */
    CRYPT_ECC_POINT_NOT_ON_CURVE,                    /**< Point is not on the curve. */
    CRYPT_ECC_POINT_ERR_CURVE_ID,                    /**< Curve ID is inconsistent or incorrect. */
    CRYPT_ECC_POINT_WINDOW_TOO_MAX,                  /**< Window is too max. */
    CRYPT_ECC_POINT_NOT_EQUAL,                       /**< The two points are not equal. */
    CRYPT_ECC_POINT_BLIND_WITH_ZERO,                 /**< The random number generated during point salting is 0. */
    CRYPT_ECC_POINT_NOT_AFFINE,                      /**< Point is not affine coordinates. */
    CRYPT_ECC_NOT_SUPPORT,                           /**< This function is not supported. */
    CRYPT_ECC_BUFF_LEN_NOT_ENOUGH,                   /**< Insufficient buffer length. */
    CRYPT_ECC_ERR_POINT_FORMAT,                      /**< The encoding format input during point encoding
                                                          is incorrect. */
    CRYPT_ECC_ERR_POINT_CODE,                        /**< Incorrect point code information. */
    CRYPT_ECC_ERR_PARA,                              /**< Incorrect curve parameter. */
    CRYPT_ECC_PKEY_ERR_UNSUPPORTED_CTRL_OPTION,      /**< Unsupport the control type. */
    CRYPT_ECC_PKEY_ERR_EMPTY_KEY,                    /**< Key is null. */
    CRYPT_ECC_PKEY_ERR_INVALID_POINT_FORMAT,         /**< Invalid dot format. */
    CRYPT_ECC_PKEY_ERR_CTRL_LEN,                     /**< Control input parameter is incorrect. */
    CRYPT_ECC_PKEY_ERR_INVALID_PRIVATE_KEY,          /**< Invalid private key. */
    CRYPT_ECC_PKEY_ERR_INVALID_PUBLIC_KEY,           /**< Invalid public key. */
    CRYPT_ECC_PKEY_ERR_TRY_CNT,                      /**< Key generation or generater signature fail
                                                          within the specified number of attempts. */
    CRYPT_ECC_PKEY_ERR_SIGN_LEN,                     /**< Invalid sign length  */

    CRYPT_ECC_KEY_PUBKEY_NOT_EQUAL,                   /**< ECC public keys are not equal. */

    CRYPT_SHA3_OUT_BUFF_LEN_NOT_ENOUGH = 0x01140001,  /**< Insufficient buffer length for storing output results. */

    CRYPT_ECDH_ERR_EMPTY_KEY = 0x01150001,            /**< Key is null. */
    CRYPT_ECDH_ERR_INVALID_COFACTOR,                  /**< Invalid cofactor value. */

    CRYPT_ECDSA_ERR_EMPTY_KEY = 0x01160001,           /**< Key is NULL. */
    CRYPT_ECDSA_ERR_TRY_CNT,                          /**< Key generation and generate signature fail
                                                           within the specified number of attempts. */
    CRYPT_ECDSA_VERIFY_FAIL,                          /**< Verification failure. */
    CRYPT_ECDSA_ERR_UNSUPPORTED_CTRL_OPTION,          /**< Unsupport the control type. */
    CRYPT_ECDSA_BUFF_LEN_NOT_ENOUGH,                  /**< BUFF insufficient length. */

    CRYPT_SM3_INPUT_OVERFLOW = 0x01170001,             /**< The length of the input data exceeds the maximum
                                                           processing range of the SM3. */
    CRYPT_SM3_OUT_BUFF_LEN_NOT_ENOUGH,                /**< The length of the buffer that storing the output
                                                           result is insufficient. */

    CRYPT_SM4_KEYLEN_ERROR = 0x01180001,              /**< Wrong key length set. */
    CRYPT_SM4_DATALEN_ERROR,                          /**< Wrong data length is set. */
    CRYPT_SM4_ERR_KEY_LEN,                            /**< Wrong key length is set. */
    CRYPT_SM4_UNSAFE_KEY,                             /**< DataKey is the same as tweakKey. */

    CRYPT_MD5_INPUT_OVERFLOW = 0x01190001,             /**< The length of the input data exceeds the
                                                           maximum processing range of the MD5. */
    CRYPT_MD5_OUT_BUFF_LEN_NOT_ENOUGH,                /**< The length of the buffer that storing the
                                                           output result is insufficient. */

    CRYPT_SM2_BUFF_LEN_NOT_ENOUGH = 0x011B0001,       /**< Insufficient buffer length. */
    CRYPT_SM2_NO_PUBKEY,                              /**< SM2 the public key is not set. */
    CRYPT_SM2_NO_PRVKEY,                              /**< SM2 The private key is not set. */
    CRYPT_SM2_ERR_EMPTY_KEY,                          /**< SM2 key is null. */
    CRYPT_SM2_ERR_TRY_CNT,                            /**< Key generation and generate signature fail
                                                           within the specified number of attempts. */
    CRYPT_SM2_VERIFY_FAIL,                            /**< verification failure. */
    CRYPT_SM2_ERR_UNSUPPORTED_CTRL_OPTION,            /**< Unsupported control type. */
    CRYPT_SM2_ERR_NO_HASH_METHOD,                     /**< No hash method information. */
    CRYPT_SM2_USERID_NOT_SET,                         /**< Unset userID. */
    CRYPT_SM2_R_NOT_SET,                              /**< The peer R value is not set. */
    CRYPT_SM2_INVALID_SERVER_TYPE,                    /**< The user is neither the initiator nor the recipient. */
    CRYPT_SM2_ERR_CTRL_LEN,                           /**< Incorrect ctrl length. */
    CRYPT_SM2_DECRYPT_FAIL,                           /**< Decryption failure. */
    CRYPT_SM2_ERR_DATA_LEN,                           /**< Incorrect data length. */
    CRYPT_SM2_ERR_GET_S,                              /**< Failed to obtain the checksum. */
    CRYPT_SM2_ERR_S_NOT_SET,                          /**< Unset checksum. */
    CRYPT_SM2_EXCH_VERIFY_FAIL,                       /**< Key Negotiation Failure. */
    CRYPT_SM2_DECODE_FAIL,                            /**< Data decoding fails, the data does not meet
                                                            the decoding requirements. */
    CRYPT_SM2_ID_TOO_LARGE,                           /**< User id to large. */
    CRYPT_KDFTLS12_NOT_SUPPORTED = 0x011C0001,        /**< Unsupport the KDFTLS12 algorithm. */

    CRYPT_DECODE_ASN1_BUFF_NUM_NOT_ENOUGH = 0x011D0001,  /**< The input number of BSL_ANS1_Buffer is not enough. */
    CRYPT_DECODE_UNSUPPORTED_PUBKEY_TYPE,                /**< Unsupported pubkey type */
    CRYPT_DECODE_UNSUPPORTED_PKCS8_TYPE,                 /**< Unsupported pkcs8 type */
    CRYPT_DECODE_PKCS8_INVALID_ALGO_PARAM,               /**< pkcs8 has no valid algorithm parameters */
    CRYPT_DECODE_UNKNOWN_OID,                            /**< Unknown OID */
    CRYPT_DECODE_ASN1_BUFF_FAILED,                       /**< decode asn1 buffer failed. */
    CRYPT_DECODE_NO_SUPPORT_TYPE,                        /**< decode no support key type. */
    CRYPT_DECODE_NO_SUPPORT_FORMAT,                      /**< decode no support key format. */
    CRYPT_DECODE_PKCS8_INVALID_ITER,                     /**< pkcs8 invalid iter num */
    CRYPT_DECODE_PKCS8_INVALID_KEYLEN,                   /**< pkcs8 invalid keylen */
    CRYPT_DECODE_ERR_RSSPSS_GET_ANY_TAG,                 /**< decode rsapss param failed. */
    CRYPT_DECODE_ERR_RSSPSS,                             /**< decode rsapss param failed. */
    CRYPT_DECODE_ERR_RSSPSS_MD,                          /**< rsapss md is invalid. */
    CRYPT_DECODE_ERR_RSSPSS_MGF1MD,                      /**< rsapss mgf1md is invalid. */
    CRYPT_DECODE_ERR_RSSPSS_TRAILER,                     /**< rsapss trailer field is invalid. */
    CRYPT_DECODE_PKCS7_INVALIDE_ENCRYPTDATA_TYPE,        /**< Invaild pkcs7-encryptedData. */
    CRYPT_DECODE_UNSUPPORTED_PKCS7_TYPE,                 /**< Unsupported pkcs7 type */
    CRYPT_DECODE_UNSUPPORTED_ENCRYPT_TYPE,               /**< Unsupported encrypt type */

    CRYPT_ENCODE_NO_SUPPORT_TYPE = 0x011E0001,           /**< encode no support key type. */
    CRYPT_ENCODE_NO_SUPPORT_FORMAT,                      /**< encode no support key format. */
    CRYPT_ENCODE_ERR_RSA_PAD,                            /**< rsa pad err. */
    
    CRYPT_PAILLIER_BUFF_LEN_NOT_ENOUGH = 0x011F0001, /**< The buffer length is insufficient. */
    CRYPT_PAILLIER_NO_KEY_INFO,              /**< Lacks valid key information. */
    CRYPT_PAILLIER_ERR_KEY_BITS,             /**< Incorrect key length. */
    CRYPT_PAILLIER_ERR_ENC_BITS,             /**< Incorrect length of the encrypted plaintext of the public key. */
    CRYPT_PAILLIER_ERR_DEC_BITS,             /**< Incorrect length of the decrypted ciphertext of the private key. */
    CRYPT_PAILLIER_ERR_INPUT_VALUE,          /**< Some special values, which are used as input errors. */
};

#ifdef __cplusplus
}
#endif

#endif // CRYPT_ERRNO_H
