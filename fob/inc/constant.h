/**
 * @file constant.h
 * @author Xi Tan, Zheyuan Ma
 * @brief eCTF UB Constant Definitions
 * @date 2023
 *
 * @copyright Copyright (c) 2023 UB Cacti Lab
 */

#ifndef CONSTANT_H
#define CONSTANT_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "mbedtls/entropy.h"
#include "mbedtls/build_info.h"
#include "mbedtls/ctr_drbg.h"

#include "mbedtls/platform.h"

#define OUTPUT_SIZE 32
#define ENABLE_MPU
#define AES_KEY_SIZE 32

/*** Macro Definitions ***/
#define FEATURE_EEPROM_PUB_KEY_LOC 0x0
#define PAIRING_EEPROM_PUB_KEY_LOC 0x60
#define UNLOCK_EEPROM_PRIV_KEY_LOC 0xC0
#define PAIRING_EEPROM_PRIV_KEY_LOC 0xC0
#define EEPROM_FEATURE_PUB_SIZE 96
#define EEPROM_PAIRING_PUB_SIZE 96
#define EEPROM_UNLOCK_PRIV_SIZE 320
#define EEPROM_PAIRING_PRIV_SIZE 320

#define DWT_TRACE_ENABLE 0x40000001
#define ARM_CM_DEMCR (*(uint32_t *)0xE000EDFC)
#define ARM_CM_DWT_CTRL (*(uint32_t *)0xE0001000)   // DWT->CTRL (core_cm33.h, DWT_Type)
#define ARM_CM_DWT_CYCCNT (*(uint32_t *)0xE0001004) // DWT->CYCCNT

void mpu_init();
void sys_reset();

void dwt_init(void);
int ctr_drbg_dwt_entropy(void *data, unsigned char *buf, size_t len);
int drng_init(void);
int drng_seed(char *pers);
int drng_free(void);

#endif // CONSTANT_H