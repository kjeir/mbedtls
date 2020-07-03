#include "psa/crypto.h"

#define OPAQUE_TEST_DRIVER_KEYHEADER "OPQTDKHEADER"
#define OPAQUE_TEST_DRIVER_KEYHEADER_SIZE 12U

psa_status_t opaque_test_driver_export_public_key(const uint8_t *in,
                                                  size_t        in_length,
                                                  uint8_t       *out,
                                                  size_t        out_size,
                                                  size_t        *out_length);

psa_status_t opaque_test_driver_generate_key(const psa_key_attributes_t *attributes,
                                             uint8_t                    *data,
                                             size_t                     data_size,
                                             size_t                     *data_length);

psa_status_t opaque_test_driver_import_key(const psa_key_attributes_t *attributes,
                                           const uint8_t              *in,
                                           size_t                     in_length,
                                           uint8_t                    *out,
                                           size_t                     out_size,
                                           size_t                     *out_length);
