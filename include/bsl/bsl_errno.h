/*---------------------------------------------------------------------------------------------
 *  This file is part of the openHiTLS project.
 *  Copyright © 2023 Huawei Technologies Co.,Ltd. All rights reserved.
 *  Licensed under the openHiTLS Software license agreement 1.0. See LICENSE in the project root
 *  for license information.
 *---------------------------------------------------------------------------------------------
 */

/**
 * @defgroup bsl_errno
 * @ingroup bsl
 * @brief error number module
 */

#ifndef BSL_ERRNO_H
#define BSL_ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup bsl_errno
 * @brief   Return success
 */
#define BSL_SUCCESS 0

/**
 * @ingroup bsl_errno
 *
 * Return values of the BSL module range from 0x03000001 to 0x03ffffff.
 */
enum BSL_ERROR {
    /* Common return value start from 0x03000001. */
    BSL_NULL_INPUT = 0x03000001,            /**< NULL input. */
    BSL_INTERNAL_EXCEPTION,                 /**< Error occurs when calling internal BSL functions */
    BSL_MALLOC_FAIL,                        /**< Error occurs when allocating memory */
    BSL_MEMCPY_FAIL,                        /**< Error occurs when calling memcpy_s. */
    BSL_INVALID_ARG,                        /**< Invalid arguments. */

    /* The return value of the SAL submodule starts from 0x03010001. */
    BSL_SAL_ERR_UNKNOWN = 0x03010001,        /**< Unknown error. */
    BSL_SAL_ERR_BAD_PARAM,                   /**< Parameter incorrect. */
    BSL_SAL_ERR_FILE_OPEN,                   /**< Open file error. */
    BSL_SAL_ERR_FILE_READ,                   /**< File reading error. */
    BSL_SAL_ERR_FILE_WRITE,                  /**< File writing error. */
    BSL_SAL_ERR_FILE_LENGTH,                 /**< Obtaining the file length error. */
    BSL_SAL_ERR_FILE_TELL,                   /**< Error in obtaining the file pointer offset. */
    BSL_SAL_ERR_FILE_SEEK,                   /**< Failed to set pointer position of file. */
    BSL_SAL_ERR_FILE_SET_ATTR,               /**< Setting file attribute failed. */
    BSL_SAL_ERR_FILE_GET_ATTR,               /**< Error in obtaining file attributes. */
    BSL_SAL_ERR_NET_SOCKCLOSE,               /**< Error occured when closing a socket. */
    BSL_SAL_ERR_NET_SETSOCKOPT,              /**< Error occured when setting a socket option. */
    BSL_SAL_ERR_NET_GETSOCKOPT,              /**< Error occured when getting a socket option. */
    BSL_SAL_ERR_NET_LISTEN,                  /**< Error occured when listening a socket. */
    BSL_SAL_ERR_NET_BIND,                    /**< Error occured when binding a socket */
    BSL_SAL_ERR_NET_CONNECT,                 /**< Error occured when building a connection. */
    BSL_SAL_ERR_NET_IOCTL,                   /**< Error occured when calling ioctl. */

    /* The return value of the LOG submodule starts from 0x03020001. */
    BSL_LOG_ERR_BAD_PARAM = 0x03020001,      /**< Bad parameter. */

    /* The return value of the TLV submodule starts from 0x03030001. */
    BSL_TLV_ERR_BAD_PARAM = 0x03030001,      /**< Bad parameter. */
    BSL_TLV_ERR_NO_WANT_TYPE,                /**< No TLV found. */

    /* The return value of the ERR submodule starts from 0x03040001. */
    BSL_ERR_ERR_ACQUIRE_READ_LOCK_FAIL = 0x03040001,  /**< Failed to obtain the read lock. */
    BSL_ERR_ERR_ACQUIRE_WRITE_LOCK_FAIL,              /**< Failed to obtain the write lock. */
    BSL_ERR_ERR_NO_STACK,                             /**< Error stack is empty. */
    BSL_ERR_ERR_NO_ERROR,                             /**< Error stack is NULL.  */
    BSL_ERR_ERR_NO_MARK,                              /**< Error stack has no mark. */

    /* The return value of the UIO submodule starts from 0x03060001. */
    BSL_UIO_FAIL = 0x03050001,              /**< Invalid parameters. */
    BSL_UIO_IO_EXCEPTION,                   /**< I/O is abnormal. */
    BSL_UIO_IO_BUSY,                        /**< I/O is busy. */
    BSL_UIO_REF_MAX,                        /**< The number of UIO objects has reached the maximum. */
    BSL_UIO_IO_EOF,                         /**< I/O object has reached EOF */
    BSL_UIO_UNINITIALIZED,                  /**< UIO object is uninitialized */

    /* The return value of the LIST submodule starts from 0x03070001. */
    BSL_LIST_INVALID_LIST_CURRENT = 0x03060001, /**< Current node pointer is NULL */
    BSL_LIST_DATA_NOT_AVAILABLE,                /**< Data of current node is NULL */
    BSL_LIST_FULL,                              /**< Number of nodes has reached its limit */

    /* The return value of the BASE64 submodule starts from 0x030a0001. */
    BSL_BASE64_INVALID = 0x03070001,
    BSL_BASE64_BUF_NOT_ENOUGH,
    BSL_BASE64_DATA_NOT_ENOUGH,
    BSL_BASE64_WRITE_FAILED,
    BSL_BASE64_READ_FAILED,
    BSL_BASE64_DATA_AFTER_PADDING,
    BSL_BASE64_ILLEGALLY_MODIFIED,
    BSL_BASE64_ENCODE_FAILED,
    BSL_BASE64_DECODE_FAILED,
    BSL_BASE64_HEADER,
};

#ifdef __cplusplus
}
#endif

#endif // BSL_ERRNO_H
