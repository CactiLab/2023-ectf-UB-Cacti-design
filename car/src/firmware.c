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

/*** Function definitions ***/
// Core functions - unlockCar and startCar
bool sendChallenge(void);
void receiveAnswerStartCar(void);

// Helper functions - sending ack messages
void sendAckSuccess(void);
void sendAckFailure(void);

const uint8_t car_id = CAR_ID;

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

    // Receive packet with some error checking
    ret = receive_board_message_by_type(&message, UNLOCK_MAGIC);
    if (ret != 0)
    {
        return false;
    }

    // Generate challenge
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
    message.buffer = buffer;

    // Receive packet with some error checking
    if (receive_board_message_by_type(&message, ANSWER_MAGIC) != 64)
    {
        return;
    }

    uint8_t *signature = buffer;

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
        while (1)
        {
        }
    }

    // Hash the challenge
    uint8_t *hash = buffer + 64;
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), challenge,
                     sizeof(challenge), hash);
    if (ret != 0)
    {
        while (1)
        {
        }
    }

    memset(challenge, 0, sizeof(challenge));

    // Verify the signature
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, signature, 64);
    if (ret == 0)
    {
        uint8_t eeprom_message[64];
        // Read last 64B of EEPROM
        EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC,
                   UNLOCK_EEPROM_SIZE);

        // Write out full flag if applicable
        uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);
        // uart_write(HOST_UART, (uint8_t *)"\n", sizeof("\n"));

        sendAckSuccess();
#ifndef DISABLE_START_VERIFICATION

        // Receive start message
        if (receive_board_message_by_type(&message, START_MAGIC) == sizeof(SIGNED_FEATURE))
        {
            SIGNED_FEATURE *signed_feature = (SIGNED_FEATURE *)buffer;
            FEATURE_DATA *feature_info = &signed_feature->feature_info;

            // Hash the feature info
            hash = buffer + sizeof(SIGNED_FEATURE);
            ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), feature_info,
                             sizeof(FEATURE_DATA), hash);
            if (ret != 0)
            {
                while (1)
                    ;
            }

            // Verify the signature and correct car id
            ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, signed_feature->signature, 64);
            if (ret != 0 || car_id != feature_info->car_id)
            {
                mbedtls_pk_free(&pk);
                return;
            }
#else
        if (receive_board_message_by_type(&message, START_MAGIC) == sizeof(FEATURE_DATA))
        {
            FEATURE_DATA *feature_info = (FEATURE_DATA *)buffer;

            if (car_id != feature_info->car_id)
            {
                mbedtls_pk_free(&pk);
                return;
            }
#endif // DISABLE_START_VERIFICATION

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
    else
    {
        sendAckFailure();
    }

    mbedtls_pk_free(&pk);
    return;
}

/**
 * @brief Function to send successful ACK message
 */
void sendAckSuccess(void)
{
    // Create packet for successful ack and send
    MESSAGE_PACKET message;

    uint8_t buffer[1];
    message.buffer = buffer;
    message.magic = ACK_MAGIC;
    buffer[0] = ACK_SUCCESS;
    message.message_len = 1;

    send_board_message(&message);
}

/**
 * @brief Function to send unsuccessful ACK message
 */
void sendAckFailure(void)
{
    // Create packet for unsuccessful ack and send
    MESSAGE_PACKET message;

    uint8_t buffer[1];
    message.buffer = buffer;
    message.magic = ACK_MAGIC;
    buffer[0] = ACK_FAIL;
    message.message_len = 1;

    send_board_message(&message);
}