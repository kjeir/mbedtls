/*
 * Test driver for key handling functions
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS) && defined(PSA_CRYPTO_DRIVER_TEST)
#include "psa/crypto.h"
#include "mbedtls/ecp.h"
#include "mbedtls/error.h"

#include "drivers/key.h"

#include "test/random.h"

#include <string.h>
#include <ctype.h>
#include "mbedtls/platform.h"

/* If non-null, on success, copy this to the output. */
void *test_driver_keygen_forced_output = NULL;
size_t test_driver_keygen_forced_output_length = 0;

psa_status_t test_transparent_keygen_status = PSA_ERROR_NOT_SUPPORTED;
unsigned long test_transparent_keygen_hit = 0;

psa_status_t test_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length )
{
    ++test_transparent_keygen_hit;

    if( test_transparent_keygen_status != PSA_SUCCESS )
        return( test_transparent_keygen_status );

    if( test_driver_keygen_forced_output != NULL )
    {
        if( test_driver_keygen_forced_output_length > key_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( key, test_driver_keygen_forced_output,
                test_driver_keygen_forced_output_length );
        *key_length = test_driver_keygen_forced_output_length;
        return( PSA_SUCCESS );
    }

    /* Copied from psa_crypto.c */
#if defined(MBEDTLS_ECP_C)
    if ( PSA_KEY_TYPE_IS_ECC( attributes->core.type ) && PSA_KEY_TYPE_IS_KEY_PAIR( attributes->core.type ) )
    {
        psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY( attributes->core.type );
        mbedtls_ecp_group_id grp_id =
            mbedtls_ecc_group_of_psa( curve, PSA_BITS_TO_BYTES( attributes->core.bits ) );
        const mbedtls_ecp_curve_info *curve_info =
            mbedtls_ecp_curve_info_from_grp_id( grp_id );
        mbedtls_ecp_keypair ecp;
        mbedtls_test_rnd_pseudo_info rnd_info;
        memset( &rnd_info, 0x5A, sizeof( mbedtls_test_rnd_pseudo_info ) );

        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        if( attributes->domain_parameters_size != 0 )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( grp_id == MBEDTLS_ECP_DP_NONE || curve_info == NULL )
            return( PSA_ERROR_NOT_SUPPORTED );
        if( curve_info->bit_size != attributes->core.bits )
            return( PSA_ERROR_INVALID_ARGUMENT );
        mbedtls_ecp_keypair_init( &ecp );
        ret = mbedtls_ecp_gen_key( grp_id, &ecp,
                                   &mbedtls_test_rnd_pseudo_rand,
                                   &rnd_info );
        if( ret != 0 )
        {
            mbedtls_ecp_keypair_free( &ecp );
            return( mbedtls_to_psa_error( ret ) );
        }

        /* Make sure to use export representation */
        size_t bytes = PSA_BITS_TO_BYTES( attributes->core.bits );
        if( key_size < bytes )
        {
            mbedtls_ecp_keypair_free( &ecp );
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        }
        psa_status_t status = mbedtls_to_psa_error(
            mbedtls_mpi_write_binary( &ecp.d, key, bytes ) );

        if( status == PSA_SUCCESS )
        {
            *key_length = bytes;
        }

        mbedtls_ecp_keypair_free( &ecp );
        return( status );
    }
    else
#endif /* MBEDTLS_ECP_C */
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_opaque_destroy_key( void )
{
    /* Do something ... */
    return( PSA_SUCCESS );
}


psa_status_t test_opaque_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length )
{
    (void) attributes;
    (void) key;
    (void) key_size;
    (void) key_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

/* Parameter validation macros */
#define OPQTD_VALIDATE_RET( cond ) \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, PSA_ERROR_INVALID_ARGUMENT )
#define OPQTD_VALIDATE( cond ) \
    MBEDTLS_INTERNAL_VALIDATE( cond )

static void rot13( const uint8_t *in,
                   size_t len,
                   uint8_t *out )
{
    char c;
    while( len-- )
    {
        c = (char) *in;
        *out = isalpha( c ) ? tolower(c) < 'n' ? c+13 : c-13 : c;
        in++;
        out++;
    }
}

psa_status_t test_opaque_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *in,
    size_t in_length,
    uint8_t *out,
    size_t out_size,
    size_t *out_length )
{
    OPQTD_VALIDATE_RET( attributes != NULL );
    OPQTD_VALIDATE_RET( in != NULL );
    OPQTD_VALIDATE_RET( out != NULL );
    OPQTD_VALIDATE_RET( out_length != NULL );

    if( ( psa_get_key_type( attributes ) != PSA_KEY_TYPE_AES ) &&
        ( psa_get_key_type( attributes ) !=
          PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_CURVE_SECP_R1 ) ) )
        return( PSA_ERROR_NOT_SUPPORTED );

    mbedtls_fprintf( stdout, " | | | | %d %ld\n", psa_get_key_type( attributes ), psa_get_key_bits( attributes ) );

    if( ( psa_get_key_bits( attributes ) != 128 ) &&      // AES-128
        ( psa_get_key_bits( attributes ) != 192 ) &&      // AES-192
        ( psa_get_key_bits( attributes ) != 256 ) )       // AES-256
        return( PSA_ERROR_NOT_SUPPORTED );

    if( psa_get_key_bits( attributes ) != PSA_BYTES_TO_BITS( in_length ) )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( OPAQUE_TEST_DRIVER_KEYHEADER_SIZE + in_length > out_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    strcpy( (char *) out, OPAQUE_TEST_DRIVER_KEYHEADER );

    /* Obscure key slightly. */
    rot13( in, in_length, out + OPAQUE_TEST_DRIVER_KEYHEADER_SIZE );

    *out_length = in_length + OPAQUE_TEST_DRIVER_KEYHEADER_SIZE;

    return( PSA_SUCCESS );
}

psa_status_t test_opaque_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *in,
    size_t in_length,
    uint8_t *out,
    size_t out_size,
    size_t *out_length )
{
    OPQTD_VALIDATE_RET( attributes != NULL );
    OPQTD_VALIDATE_RET( in != NULL );
    OPQTD_VALIDATE_RET( out != NULL );
    OPQTD_VALIDATE_RET( out_length != NULL );

    (void) attributes;

    if( in_length <= OPAQUE_TEST_DRIVER_KEYHEADER_SIZE )
        return( PSA_ERROR_INVALID_ARGUMENT );

    if( in_length - OPAQUE_TEST_DRIVER_KEYHEADER_SIZE > out_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );

    *out_length = in_length - OPAQUE_TEST_DRIVER_KEYHEADER_SIZE;
    rot13( in + OPAQUE_TEST_DRIVER_KEYHEADER_SIZE, *out_length, out );

    return( PSA_SUCCESS );
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
