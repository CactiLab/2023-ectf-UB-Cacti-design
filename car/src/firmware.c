/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Car Example Design Implementation
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

/**
 * @file firmware.c
 * @author Zheyuan Ma
 * @brief eCTF Car UB Design Implementation
 * @date 2023
 *
 * @copyright Copyright (c) 2023 UB Cacti Lab
 */

#include <stdbool.h>
#include <stdint.h>

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"

#include "secrets.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/memory_buffer_alloc.h"

#include "board_link.h"
#include "feature_list.h"
#include "uart.h"
#include "syscalls.h"
#include "constant.h"

/*** Structure definitions ***/
// Structure of start_car packet FEATURE_DATA
typedef struct
{
    uint8_t car_id;
    uint8_t num_active;
    uint8_t features[NUM_FEATURES];
} FEATURE_DATA;

// Defines a struct for the signed feature data
typedef struct
{
    FEATURE_DATA feature_info;
    uint8_t signature[64];
} SIGNED_FEATURE;

extern mbedtls_ctr_drbg_context ctr_drbg;
uint8_t memory_buf[8192];
uint8_t challenge[32] = {0};
const uint8_t car_id = CAR_ID;

/*** Function definitions ***/
// Core functions - unlockCar and startCar
bool sendChallenge(void);
void receiveAnswerStartCar(void);

/**
 * @brief Main function for the car example
 *
 * Initializes the RF module and waits for a successful unlock attempt.
 * If successful prints out the unlock flag.
 */
int main(void)
{
    // Ensure EEPROM peripheral is enabled
    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    EEPROMInit();

    // Change LED color: red
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0);          // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0);          // g

    // Initialize UART peripheral
    uart_init();

    // Initialize the DWT unit
    dwt_init();

    // Initialize the buffer allocator
    mbedtls_memory_buffer_alloc_init(memory_buf, sizeof(memory_buf));

    // Initialize the random number generator
    drng_init();

#ifdef ENABLE_MPU
    // Init the MPU
    mpu_init();
#endif

    // Initialize board link UART
    setup_board_link();

    while (true)
    {
        // unlockCar();
        if (sendChallenge())
        {
            receiveAnswerStartCar();
        }
    }
}

bool sendChallenge(void)
{
    int ret = 0;

    // Create a message struct variable for receiving data
    MESSAGE_PACKET message;
    uint8_t buffer[256];
    message.buffer = buffer;

    // Receive unlock command
    ret = receive_board_message_by_type(&message, UNLOCK_MAGIC);
    if (ret != 0)
    {
        return false;
    }

    // Generate challenge(32)
    memset(challenge, 0, sizeof(challenge));
    drng_seed("challenge");
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, challenge, sizeof(challenge));
    if (ret == 0)
    {
        MESSAGE_PACKET message;
        message.message_len = sizeof(challenge);
        message.magic = CHALLENGE_MAGIC;
        message.buffer = (uint8_t *)&challenge;
        send_board_message(&message);

        return true;
    }
    return false;
}

/**
 * @brief Function that handles the answer and unlock of car
 */
void receiveAnswerStartCar()
{
    // Create a message struct variable for receiving data
    MESSAGE_PACKET message;
    uint8_t buffer[256];
    message.buffer = buffer + sizeof(challenge);

    // Receive FEATURE_DATA(5) and SIGNATURE(64)
    if (receive_board_message_by_type(&message, ANSWER_MAGIC) != sizeof(FEATURE_DATA) + 64)
    {
        return;
    }

    // The buffer has: CHALLENGE(32), FEATURE_DATA(5), SIGNATURE(64)
    memcpy(buffer, challenge, sizeof(challenge));
    memset(challenge, 0, sizeof(challenge));

    int ret = 0;
    uint8_t eeprom_unlock_pub_key[EEPROM_UNLOCK_PUB_SIZE] = {0};

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // Read public key from EEPROM
    EEPROMRead((uint32_t *)eeprom_unlock_pub_key, UNLOCK_EEPROM_PUB_KEY_LOC,
               EEPROM_UNLOCK_PUB_SIZE);

    // Parse public key
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_key(&pk, eeprom_unlock_pub_key, UNLOCK_PUB_KEY_SIZE);
    if (ret != 0)
    {
        sys_reset();
    }

    // Hash the challenge and feature info
    uint8_t hash[32] = {0};
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), buffer,
                     32 + sizeof(FEATURE_DATA), hash);
    if (ret != 0)
    {
        sys_reset();
    }

    // Verify the signature
    // The buffer has: CHALLENGE(32), FEATURE_DATA(5), SIGNATURE(64)
    uint8_t *signature = buffer + 32 + sizeof(FEATURE_DATA);
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, signature, 64);
    mbedtls_pk_free(&pk);
    if (ret == 0)
    {
        uint8_t eeprom_message[64];
        // Read last 64B of EEPROM
        EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC,
                   UNLOCK_EEPROM_SIZE);

        // Write out full flag if applicable
        uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);

        FEATURE_DATA *feature_info = (FEATURE_DATA *)(buffer + 32);

        // Check if car ID matches
        if (car_id != feature_info->car_id)
        {
            return;
        }

        // Print out features for all active features
        for (int i = 0; i < feature_info->num_active; i++)
        {
            uint8_t eeprom_message[64];
            uint32_t offset = feature_info->features[i] * FEATURE_SIZE;
            if (offset > FEATURE_END)
            {
                offset = FEATURE_END;
            }
            EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - offset, FEATURE_SIZE);
            uart_write(HOST_UART, eeprom_message, FEATURE_SIZE);
        }

        // Change LED color: green
        GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, 0);          // r
        GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, 0);          // b
        GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g
    }
}
