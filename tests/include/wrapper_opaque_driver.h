#ifndef WRAPPER_OPAQUE_DRIVER_H
#define WRAPPER_OPAQUE_DRIVER_H

#include "psa/crypto.h"

#if defined(MBEDTLS_TEST_WRAPPER_OPAQUE_DRIVER_C)
#ifndef MBEDTLS_TEST_OPAQUE_DRIVER
#define MBEDTLS_TEST_OPAQUE_DRIVER
#endif
#endif

#if defined(MBEDTLS_TEST_WRAPPER_OPAQUE_DRIVER_C)

#define OPAQUE_TEST_DRIVER_KEYHEADER "OPQTDKHEADER"
#define OPAQUE_TEST_DRIVER_KEYHEADER_SIZE 12U

psa_status_t opaque_driver_export_public_key(const uint8_t *in,
                                             size_t        in_length,
                                             uint8_t       *out,
                                             size_t        out_size,
                                             size_t        *out_length);

psa_status_t opaque_driver_generate_key(const psa_key_attributes_t *attributes,
                                        uint8_t                    *key,
                                        size_t                     key_size,
                                        size_t                     *key_length);

psa_status_t opaque_driver_import_key(const psa_key_attributes_t *attributes,
                                      const uint8_t              *in,
                                      size_t                     in_length,
                                      uint8_t                    *out,
                                      size_t                     out_size,
                                      size_t                     *out_length);

psa_status_t opaque_driver_sign_hash(const psa_key_attributes_t *attributes,
                                     const uint8_t              *key,
                                     size_t                     key_length,
                                     psa_algorithm_t            alg,
                                     const uint8_t              *hash,
                                     size_t                     hash_length,
                                     uint8_t                    *signature,
                                     size_t                     signature_size,
                                     size_t                     *signature_length);

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
