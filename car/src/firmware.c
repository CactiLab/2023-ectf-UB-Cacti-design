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
#include <string.h>

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
    uint8_t car_id[8];
    uint8_t num_active;
    uint8_t features[NUM_FEATURES];
} FEATURE_DATA;

// Defines a struct for the signed feature data
typedef struct
{
    FEATURE_DATA feature_info;
    uint8_t signature_size;
    uint8_t signature[256];
} SIGNED_FEATURE;

/*** Macro Definitions ***/
#define UNLOCK_EEPROM_PUB_KEY_LOC 0x0

// Definitions for unlock message location in EEPROM
#define UNLOCK_EEPROM_LOC 0x7C0
#define UNLOCK_EEPROM_SIZE 64

extern mbedtls_ctr_drbg_context ctr_drbg;
unsigned char memory_buf[8192];

/*** Function definitions ***/
// Core functions - unlockCar and startCar
bool sendChallenge(void);
bool receiveAnswer(void);
void unlockCar(void);
void startCar(void);

// Helper functions - sending ack messages
void sendAckSuccess(void);
void sendAckFailure(void);

// Declare password
const uint8_t pass[] = PASSWORD;
const uint8_t car_id[] = CAR_ID;

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
            receiveAnswer();
        }
    }
}

bool sendChallenge(void)
{
    int ret = 0;
    unsigned char challenge[32] = {0};

    // Create a message struct variable for receiving data
    MESSAGE_PACKET message;
    uint8_t buffer[256];
    message.buffer = buffer;

    // Receive packet with some error checking
    receive_board_message_by_type(&message, UNLOCK_MAGIC);

    // Generate challenge
    drng_seed();
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

bool receiveAnswer()
{
    // TODO: Implement
    return false;
}

/**
 * @brief Function that handles unlocking of car
 */
void unlockCar(void)
{
    // Create a message struct variable for receiving data
    MESSAGE_PACKET message;
    uint8_t buffer[256];
    message.buffer = buffer;

    // Receive packet with some error checking
    receive_board_message_by_type(&message, UNLOCK_MAGIC);

    // Pad payload to a string
    message.buffer[message.message_len] = 0;

    // If the data transfer is the password, unlock
    if (!strcmp((char *)(message.buffer), (char *)pass))
    {
        uint8_t eeprom_message[64];
        // Read last 64B of EEPROM
        EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC,
                   UNLOCK_EEPROM_SIZE);

        // Write out full flag if applicable
        uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);

        sendAckSuccess();

        startCar();
    }
    else
    {
        sendAckFailure();
    }
}

/**
 * @brief Function that handles starting of car - feature list
 */
void startCar(void)
{
    // Create a message struct variable for receiving data
    MESSAGE_PACKET message;
    uint8_t buffer[256];
    message.buffer = buffer;

    // Receive start message
    receive_board_message_by_type(&message, START_MAGIC);

    FEATURE_DATA *feature_info = (FEATURE_DATA *)buffer;

    // Verify correct car id
    if (strcmp((char *)car_id, (char *)feature_info->car_id))
    {
        return;
    }

    // Print out features for all active features
    for (int i = 0; i < feature_info->num_active; i++)
    {
        uint8_t eeprom_message[64];

        uint32_t offset = feature_info->features[i] * FEATURE_SIZE;

        EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - offset, FEATURE_SIZE);

        uart_write(HOST_UART, eeprom_message, FEATURE_SIZE);
    }
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