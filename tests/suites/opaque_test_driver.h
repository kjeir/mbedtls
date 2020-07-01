#include "psa/crypto.h"

#define OPAQUE_TEST_DRIVER_KEYHEADER "OPQTDKHEADER"

psa_status_t opaque_test_driver_import_key(const psa_key_attributes_t *attributes,
                                           const uint8_t *in_key,
                                           size_t        in_key_len,
                                           uint8_t       *out_key,
                                           size_t        out_key_bufsize,
                                           size_t        *out_key_len);
