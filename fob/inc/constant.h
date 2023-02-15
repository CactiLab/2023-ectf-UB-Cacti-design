#ifndef CONSTANT_H
#define CONSTANT_H

#include <stdint.h>
#include <stddef.h>

#include "mbedtls/entropy.h"
#include "mbedtls/build_info.h"
#include "mbedtls/ctr_drbg.h"

#include "mbedtls/platform.h"

#define OUTPUT_SIZE 32
// #define ENBALE_DRBG
// #define ENABLE_MPU

#define DWT_TRACE_ENABLE 0x40000001
#define ARM_CM_DEMCR (*(uint32_t *)0xE000EDFC)
#define ARM_CM_DWT_CTRL (*(uint32_t *)0xE0001000)	// DWT->CTRL (core_cm33.h, DWT_Type)
#define ARM_CM_DWT_CYCCNT (*(uint32_t *)0xE0001004) // DWT->CYCCNT

// functions for random number generation
void dwt_init(void);
void random_twice_with_ctr_drbg();
void random_init( mbedtls_ctr_drbg_context *drbg, 
                  mbedtls_entropy_context *entropy);
void random_exit( mbedtls_ctr_drbg_context *drbg, 
                  mbedtls_entropy_context *entropy);                  
void random_gnereator(  mbedtls_ctr_drbg_context *drbg, 
                        mbedtls_entropy_context *entropy, 
                        size_t entropy_len,
                        size_t nonce_len,
                        unsigned char *output,
                        size_t output_size);

int ctr_drbg_self_test_entropy(void *data, unsigned char *buf, size_t len);
void mpu_init();

#endif // CONSTANT_H