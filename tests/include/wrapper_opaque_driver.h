#include "psa/crypto.h"

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
