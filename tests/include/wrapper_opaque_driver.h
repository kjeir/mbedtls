/**
 * \file wrapper_opaque_driver.h
 *
 * \brief   This file contains prototypes for the opaque driver implementation
 *          sample.
 */

/*
 *  Copyright (C) 2020, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#ifndef WRAPPER_OPAQUE_DRIVER_H
#define WRAPPER_OPAQUE_DRIVER_H

#include "psa/crypto.h"

#if defined(MBEDTLS_TEST_WRAPPER_OPAQUE_DRIVER_C)

#define OPAQUE_DRIVER_KEYHEADER "OPQTDKHEADER"
#define OPAQUE_DRIVER_KEYHEADER_SIZE 12U

/**
 * \brief Export a public key from an opaque key.
 *
 * The output of this function can be passed to opaque_driver_import_key() to
 * create an object that is equivalent to the public key.
 *
 * \param[in]  in           The opaque key to export.
 * \param[in]  in_length    The size of the opaque key.
 * \param[out] out          Buffer where the exported key data is to be written.
 * \param[in]  out_size     Size of the \p out data buffer in bytes.
 * \param[out] out_length   On success, the number of bytes that make up the
 *                          exported key data.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The \p in key is not recognized as an opaque key.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p out data buffer is too small.
 */
psa_status_t opaque_driver_export_public_key(const uint8_t *in,
                                             size_t        in_length,
                                             uint8_t       *out,
                                             size_t        out_size,
                                             size_t        *out_length);

/**
 * \brief Generate an opaque key.
 *
 * \param[in]  attributes   The attributes for the new key.
 * \param[out] key          Buffer where the key data is to be written.
 * \param[in]  key_size     Size of the \p key data buffer in bytes.
 * \param[out] key_length   On success, the number of bytes that make up the
 *                          key data.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         Zero length key.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         Key length or type not supported.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p key data buffer is too small.
 */
psa_status_t opaque_driver_generate_key(const psa_key_attributes_t *attributes,
                                        uint8_t                    *key,
                                        size_t                     key_size,
                                        size_t                     *key_length);

/**
 * \brief Import a key and create an opaque key.
 *
 * \param[in]  attributes   The attributes for the key.
 * \param[in]  in           The key to import.
 * \param[in]  in_length    The size of the key.
 * \param[out] out          Buffer where the opaque key data is to be written.
 * \param[in]  out_size     Size of the \p out data buffer in bytes.
 * \param[out] out_length   On success, the number of bytes that make up the
 *                          opaque key data.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The \p in key length is not matching \p attributes.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         Key length or type not supported.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p out data buffer is too small.
 */
psa_status_t opaque_driver_import_key(const psa_key_attributes_t *attributes,
                                      const uint8_t              *in,
                                      size_t                     in_length,
                                      uint8_t                    *out,
                                      size_t                     out_size,
                                      size_t                     *out_length);

/**
 * \brief Sign a hash or short message with an opaque key.
 *
 * \param[in]  attributes       The attributes for the key.
 * \param[in]  key              The key data to use.
 * \param[in]  key_length       The key length in bytes.
 * \param[in]  alg              A signature algorithm that is compatible with
 *                              the type of \p key.
 * \param[in]  hash             The hash or message to sign.
 * \param[in]  hash_length      Size of the \p hash buffer in bytes.
 * \param[out] signature        Buffer where the signature is to be written.
 * \param[in]  signature_size   Size of the \p signature buffer in bytes.
 * \param[out] signature_length On success, the number of bytes
 *                              that make up the returned signature value.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The \p in key is not recognized as an opaque key.
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p signature buffer is too small.
 */
psa_status_t opaque_driver_sign_hash(const psa_key_attributes_t *attributes,
                                     const uint8_t              *key,
                                     size_t                     key_length,
                                     psa_algorithm_t            alg,
                                     const uint8_t              *hash,
                                     size_t                     hash_length,
                                     uint8_t                    *signature,
                                     size_t                     signature_size,
                                     size_t                     *signature_length);

/**
 * \brief Verify the signature of a hash or short message using an opqaue key.
 *
 * \param[in]  attributes       The attributes for the key.
 * \param[in]  key              The key data to use.
 * \param[in]  key_length       The key length in bytes.
 * \param[in]  alg              A signature algorithm that is compatible with
 *                              the type of \p key.
 * \param[in]  hash             The hash or message to sign.
 * \param[in]  hash_length      Size of the \p hash buffer in bytes.
 * \param[in]  signature        Buffer containing the signature to verify.
 * \param[in]  signature_length Size of the \p signature buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The \p in key is not recognized as an opaque key.
 */
psa_status_t opaque_driver_verify_hash(const psa_key_attributes_t *attributes,
                                       const uint8_t              *key,
                                       size_t                     key_length,
                                       psa_algorithm_t            alg,
                                       const uint8_t              *hash,
                                       size_t                     hash_length,
                                       const uint8_t              *signature,
                                       size_t                     signature_length);

#endif // defined(MBEDTLS_TEST_WRAPPER_OPAQUE_DRIVER_C)
#endif // #ifndef WRAPPER_OPAQUE_DRIVER_H
