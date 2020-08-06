/*
 *  Functions to delegate cryptographic operations to an available
 *  and appropriate accelerator.
 *  Warning: auto-generated file.
 */
/*  Copyright (C) 2020, ARM Limited, All Rights Reserved
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

#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers.h"
#include "mbedtls/platform.h"

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS)

/* Include test driver definition when running tests */
#if defined(PSA_CRYPTO_DRIVER_TEST)
#undef PSA_CRYPTO_DRIVER_PRESENT
#define PSA_CRYPTO_DRIVER_PRESENT
#undef PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#define PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#include "drivers/test_driver.h"
#endif /* PSA_CRYPTO_DRIVER_TEST */

/* Include driver definition file for each registered driver here */
#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS */

/* Support the 'old' SE interface when asked to */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
#undef PSA_CRYPTO_DRIVER_PRESENT
#define PSA_CRYPTO_DRIVER_PRESENT
#endif

#include "psa_crypto_se.h"
#include "psa_crypto_slot_management.h"


psa_status_t psa_validate_key_location( psa_key_lifetime_t lifetime,
                                        psa_se_drv_table_entry_t **p_drv )
{
    if ( psa_key_lifetime_is_external( lifetime ) )
    {
#if defined(PSA_CRYPTO_DRIVER_TEST)
        if( PSA_KEY_LIFETIME_GET_LOCATION(lifetime) ==
            PSA_CRYPTO_TEST_DRIVER_LOCATION )
            return( PSA_SUCCESS );
        else
#endif
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
        {
            psa_se_drv_table_entry_t *driver = psa_get_se_driver_entry( lifetime );
            if( driver == NULL )
                return( PSA_ERROR_INVALID_ARGUMENT );
            else
            {
                if (p_drv != NULL)
                    *p_drv = driver;
                return( PSA_SUCCESS );
            }
        }
#else
        {
            (void) p_drv;
            return( PSA_ERROR_INVALID_ARGUMENT );
        }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
    }
    else
        /* Local/internal keys are always valid */
        return( PSA_SUCCESS );
}

/* Start delegation functions */
psa_status_t psa_driver_wrapper_sign_hash( psa_key_slot_t *slot,
                                           psa_algorithm_t alg,
                                           const uint8_t *hash,
                                           size_t hash_length,
                                           uint8_t *signature,
                                           size_t signature_size,
                                           size_t *signature_length )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT)
    /* Try dynamically-registered SE interface first */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if( psa_get_se_driver( slot->attr.lifetime, &drv, &drv_context ) )
    {
        if( drv->asymmetric == NULL ||
            drv->asymmetric->p_sign == NULL )
        {
            /* Key is defined in SE, but we have no way to exercise it */
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return( drv->asymmetric->p_sign( drv_context,
                                         slot->data.se.slot_number,
                                         alg,
                                         hash, hash_length,
                                         signature, signature_size,
                                         signature_length ) );
    }
#endif /* PSA_CRYPTO_SE_C */

    /* Then try accelerator API */
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(PSA_CRYPTO_DRIVER_TEST)
            mbedtls_fprintf( stdout, " | | | Transp Sign-HASH\n" );
            status = test_transparent_signature_sign_hash( &attributes,
                                                           slot->data.key.data,
                                                           slot->data.key.bytes,
                                                           alg,
                                                           hash,
                                                           hash_length,
                                                           signature,
                                                           signature_size,
                                                           signature_length );
            /* Declared with fallback == true */
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return status;
#endif /* PSA_CRYPTO_DRIVER_TEST */
            /* Fell through, meaning no accelerator supports this operation */
            return PSA_ERROR_NOT_SUPPORTED;

        /* Add cases for opaque driver here */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LOCATION:
            status = test_opaque_signature_sign_hash( &attributes,
                                                      slot->data.key.data,
                                                      slot->data.key.bytes,
                                                      alg,
                                                      hash,
                                                      hash_length,
                                                      signature,
                                                      signature_size,
                                                      signature_length );
            mbedtls_fprintf( stdout, " | | | Opaque Sign-HASH %d\n", status );
            return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is declared with a lifetime not known to us */
            return status;
    }
#else /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
    return PSA_ERROR_NOT_SUPPORTED;
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void)slot;
    (void)alg;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_size;
    (void)signature_length;

    return PSA_ERROR_NOT_SUPPORTED;
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_verify_hash( psa_key_slot_t *slot,
                                             psa_algorithm_t alg,
                                             const uint8_t *hash,
                                             size_t hash_length,
                                             const uint8_t *signature,
                                             size_t signature_length )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT)
    /* Try dynamically-registered SE interface first */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if( psa_get_se_driver( slot->attr.lifetime, &drv, &drv_context ) )
    {
        if( drv->asymmetric == NULL ||
            drv->asymmetric->p_verify == NULL )
        {
            /* Key is defined in SE, but we have no way to exercise it */
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        return( drv->asymmetric->p_verify( drv_context,
                                           slot->data.se.slot_number,
                                           alg,
                                           hash, hash_length,
                                           signature, signature_length ) );
    }
#endif /* PSA_CRYPTO_SE_C */

    /* Then try accelerator API */
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(PSA_CRYPTO_DRIVER_TEST)
            status = test_transparent_signature_verify_hash( &attributes,
                                                             slot->data.key.data,
                                                             slot->data.key.bytes,
                                                             alg,
                                                             hash,
                                                             hash_length,
                                                             signature,
                                                             signature_length );
            /* Declared with fallback == true */
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return status;
#endif /* PSA_CRYPTO_DRIVER_TEST */
            /* Fell through, meaning no accelerator supports this operation */
            return PSA_ERROR_NOT_SUPPORTED;
        /* Add cases for opaque driver here */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LOCATION:
            return( test_opaque_signature_verify_hash( &attributes,
                                                       slot->data.key.data,
                                                       slot->data.key.bytes,
                                                       alg,
                                                       hash,
                                                       hash_length,
                                                       signature,
                                                       signature_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is declared with a lifetime not known to us */
            return status;
    }
#else /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
    return PSA_ERROR_NOT_SUPPORTED;
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void)slot;
    (void)alg;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_length;

    return PSA_ERROR_NOT_SUPPORTED;
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
static psa_status_t get_expected_key_size( const psa_key_attributes_t *attributes,
                                           size_t *expected_size )
{
    if( PSA_KEY_LIFETIME_GET_LOCATION( attributes->core.lifetime ) == PSA_KEY_LOCATION_LOCAL_STORAGE )
    {
        if( PSA_KEY_TYPE_IS_UNSTRUCTURED( attributes->core.type ) )
        {
            *expected_size = PSA_BITS_TO_BYTES( attributes->core.bits );
            return PSA_SUCCESS;
        }

        if( PSA_KEY_TYPE_IS_ECC( attributes->core.type ) )
        {
            if( PSA_KEY_TYPE_IS_KEY_PAIR( attributes->core.type ) )
            {
                *expected_size = PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE( attributes->core.bits );
                return PSA_SUCCESS;
            }
            else
            {
                *expected_size = PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE( attributes->core.bits );
                return PSA_SUCCESS;
            }
        }

        if( PSA_KEY_TYPE_IS_RSA( attributes->core.type ) )
        {
            if( PSA_KEY_TYPE_IS_KEY_PAIR( attributes->core.type ) )
            {
                *expected_size = PSA_KEY_EXPORT_RSA_KEY_PAIR_MAX_SIZE( attributes->core.bits );
                return PSA_SUCCESS;
            }
            else
            {
                *expected_size = PSA_KEY_EXPORT_RSA_PUBLIC_KEY_MAX_SIZE( attributes->core.bits );
                return PSA_SUCCESS;
            }
        }

        return PSA_ERROR_NOT_SUPPORTED;
    }
    else
    {
        /* TBD: opaque driver support, need to calculate size through driver-defined size function */
        return PSA_ERROR_NOT_SUPPORTED;
    }
}
#endif /* PSA_CRYPTO_DRIVER_PRESENT */

psa_status_t psa_driver_wrapper_generate_key( const psa_key_attributes_t *attributes,
                                              psa_key_slot_t *slot )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT)
    /* Try dynamically-registered SE interface first */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if( psa_get_se_driver( slot->attr.lifetime, &drv, &drv_context ) )
    {
        size_t pubkey_length = 0; /* We don't support this feature yet */
        if( drv->key_management == NULL ||
            drv->key_management->p_generate == NULL )
        {
            /* Key is defined as being in SE, but we have no way to generate it */
            return PSA_ERROR_NOT_SUPPORTED;
        }
        return( drv->key_management->p_generate(
            drv_context,
            slot->data.se.slot_number, attributes,
            NULL, 0, &pubkey_length ) );
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    /* Then try accelerator API */
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    size_t export_size = 0;

    status = get_expected_key_size( attributes, &export_size );
    if( status != PSA_SUCCESS )
        return status;

    slot->data.key.data = mbedtls_calloc(1, export_size);
    if( slot->data.key.data == NULL )
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    slot->data.key.bytes = export_size;

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */

            /* Transparent drivers are limited to generating asymmetric keys */
            if( ! PSA_KEY_TYPE_IS_ASYMMETRIC( slot->attr.type ) )
            {
                status = PSA_ERROR_NOT_SUPPORTED;
                break;
            }
#if defined(PSA_CRYPTO_DRIVER_TEST)
            status = test_transparent_generate_key( attributes,
                                                    slot->data.key.data,
                                                    slot->data.key.bytes,
                                                    &slot->data.key.bytes );
            /* Declared with fallback == true */
            if( status != PSA_ERROR_NOT_SUPPORTED )
                break;
#endif /* PSA_CRYPTO_DRIVER_TEST */
            /* Fell through, meaning no accelerator supports this operation */
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
        /* Add cases for opaque driver here */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LOCATION:
            status = test_opaque_generate_key( attributes,
                                               slot->data.key.data,
                                               slot->data.key.bytes,
                                               &slot->data.key.bytes );
            break;
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is declared with a lifetime not known to us */
            status = PSA_ERROR_INVALID_ARGUMENT;
            break;
    }

    if( status != PSA_SUCCESS )
    {
        /* free allocated buffer */
        mbedtls_free( slot->data.key.data );
        slot->data.key.data = NULL;
        slot->data.key.bytes = 0;
    }

    return( status );
#else /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
    return PSA_ERROR_NOT_SUPPORTED;
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void) attributes;
    (void) slot;

    return PSA_ERROR_NOT_SUPPORTED;
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_destroy_key( psa_key_slot_t *slot )
{
    (void) slot;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_export_public_key( psa_key_slot_t *slot )
{
    (void) slot;
    return PSA_ERROR_NOT_SUPPORTED;
}

#include <ctype.h>

psa_status_t psa_driver_wrapper_import_key(
    const psa_key_attributes_t *attributes,
    psa_key_slot_t *slot,
    const uint8_t *key,
    size_t key_length )

{
#if defined(PSA_CRYPTO_DRIVER_PRESENT)
    /* Try accelerator API */
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    uint8_t* output = NULL;
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(
                                      slot->attr.lifetime);
#if defined(PSA_CRYPTO_DRIVER_TEST)
    size_t expected_length;
    size_t keystore_length;
#endif

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(PSA_CRYPTO_DRIVER_TEST)
            mbedtls_fprintf( stdout, " | | | Transp Import-KEY\n" );
#endif /* PSA_CRYPTO_DRIVER_TEST */
            return PSA_ERROR_NOT_SUPPORTED;

#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LOCATION:
            expected_length = key_length + OPAQUE_TEST_DRIVER_KEYHEADER_SIZE;
            output = mbedtls_calloc( 1, expected_length );
            if( output == NULL )
                return PSA_ERROR_INSUFFICIENT_MEMORY;

            status = test_opaque_import_key( attributes,
                                             key,
                                             key_length,
                                             output,
                                             expected_length,
                                             &keystore_length);
            mbedtls_fprintf( stdout, " | | | Opaque Import-KEY %d\n", status );
            for( unsigned i = 0; i < keystore_length; i++ )
                if( isalpha( output[i] ) )
                    mbedtls_fprintf( stdout, "'%c' ", output[i] );
                else
                    mbedtls_fprintf( stdout, "%02X ", output[i] );
            mbedtls_fprintf( stdout, "\n" );
            if( status == PSA_SUCCESS )
            {
                slot->data.key.data = output;
                slot->data.key.bytes = expected_length;
            }
            return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */

        default:
            /* Key is declared with a lifetime not known to us */
            return status;
    }
#else /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
    return PSA_ERROR_NOT_SUPPORTED;
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void)slot;

    return PSA_ERROR_NOT_SUPPORTED;
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

/* End of automatically generated file. */
