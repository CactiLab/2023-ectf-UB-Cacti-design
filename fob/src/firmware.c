/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Fob Example Design Implementation
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
#include "driverlib/flash.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"

#include "secrets.h"
#include "mbedtls/pk.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/memory_buffer_alloc.h"

#include "board_link.h"
#include "feature_list.h"
#include "uart.h"
#include "syscalls.h"
#include "constant.h"

#define FOB_STATE_PTR 0x3FC00
#define FLASH_DATA_SIZE           \
    (sizeof(FLASH_DATA) % 4 == 0) \
        ? sizeof(FLASH_DATA)      \
        : sizeof(FLASH_DATA) + (4 - (sizeof(FLASH_DATA) % 4))
#define FLASH_PAIRED 0x00
#define FLASH_UNPAIRED 0xFF

/*** Structure definitions ***/
// Defines a struct for the format of an enable message
typedef struct
{
    uint8_t car_id;
    uint8_t feature;
    uint8_t token[8];
} ENABLE_PACKET;

// Defines a struct for the format of a pairing info
typedef struct
{
    uint8_t car_id;
    uint8_t pin_hash[32];
    uint16_t unlock_priv_key_size;
} PAIR_INFO;

// Defines a struct for the format of a pairing packet
typedef struct
{
    PAIR_INFO pair_info;
    uint8_t unlock_priv_key[EEPROM_UNLOCK_PRIV_SIZE];
    u_int8_t padding[11];
} PAIR_PACKET;

// Defines a struct for the format of feature data
typedef struct
{
    uint8_t car_id;
    uint8_t num_active;
    uint8_t features[NUM_FEATURES];
} FEATURE_DATA;

// Defines a struct for storing the state in flash
typedef struct
{
    uint8_t paired;
    PAIR_INFO pair_info;
    FEATURE_DATA feature_info;
} FLASH_DATA;

// Defines a struct for the signed feature data
typedef struct
{
    FEATURE_DATA feature_info;
    uint8_t signature[64];
} SIGNED_FEATURE;

// Defines a struct for the format of the AES info
typedef struct
{
    uint8_t key[AES_KEY_SIZE];
    uint8_t hash[20];
} AES_INFO;

extern mbedtls_ctr_drbg_context ctr_drbg;
uint8_t memory_buf[8192];

/*** Function definitions ***/
// Core functions - all functionality supported by fob
void saveFobState(FLASH_DATA *flash_data);
void pairFob(FLASH_DATA *fob_state_ram);
void sendUnlock(FLASH_DATA *fob_state_ram);
uint8_t recChalSendAnsFeature(FLASH_DATA *fob_state_ram);
void enableFeature(FLASH_DATA *fob_state_ram);

/**
 * @brief Main function for the fob example
 *
 * Listens over UART and SW1 for an unlock command. If unlock command presented,
 * attempts to unlock door. Listens over UART for pair command. If pair
 * command presented, attempts to either pair a new key, or be paired
 * based on firmware build.
 */
int main(void)
{
    FLASH_DATA fob_state_ram;
    FLASH_DATA *fob_state_flash = (FLASH_DATA *)FOB_STATE_PTR;

    memset(&fob_state_ram, 0xFF, sizeof(FLASH_DATA));

// If paired fob, initialize the system information
#if PAIRED == 1
    if (fob_state_flash->paired != FLASH_PAIRED)
    {
        memcpy(fob_state_ram.pair_info.pin_hash, PAIRING_PIN_HASH, 32);
        fob_state_ram.pair_info.car_id = CAR_ID;
        fob_state_ram.feature_info.car_id = CAR_ID;
        fob_state_ram.paired = FLASH_PAIRED;
        fob_state_ram.pair_info.unlock_priv_key_size = UNLOCK_PRIV_KEY_SIZE;

        saveFobState(&fob_state_ram);
    }
#else
    fob_state_ram.paired = FLASH_UNPAIRED;
#endif

    if (fob_state_flash->paired == FLASH_PAIRED)
    {
        memcpy(&fob_state_ram, fob_state_flash, FLASH_DATA_SIZE);
    }

    // This will run on first boot to initialize features
    if (fob_state_ram.feature_info.num_active == 0xFF)
    {
        fob_state_ram.feature_info.num_active = 0;
        saveFobState(&fob_state_ram);
    }

    // Ensure EEPROM peripheral is enabled
    SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
    EEPROMInit();

    // Initialize UART
    uart_init();

    // Initialize the DWT unit
    dwt_init();

    // Initialize the buffer allocator
    mbedtls_memory_buffer_alloc_init(memory_buf, sizeof(memory_buf));

    // Initialize the random number generator
    drng_init();
#ifdef ENABLE_MPU
    // Initizalize MPU
    mpu_init();
#endif

    // Initialize board link UART
    setup_board_link();

    // Setup SW1
    GPIOPinTypeGPIOInput(GPIO_PORTF_BASE, GPIO_PIN_4);
    GPIOPadConfigSet(GPIO_PORTF_BASE, GPIO_PIN_4, GPIO_STRENGTH_4MA,
                     GPIO_PIN_TYPE_STD_WPU);

    // Change LED color: white
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_1, GPIO_PIN_1); // r
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_2, GPIO_PIN_2); // b
    GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3); // g

    // Declare a buffer for reading and writing to UART
    uint8_t uart_buffer[10];
    uint8_t uart_buffer_index = 0;

    uint8_t previous_sw_state = GPIO_PIN_4;
    uint8_t debounce_sw_state = GPIO_PIN_4;
    uint8_t current_sw_state = GPIO_PIN_4;

    // Infinite loop for polling UART
    while (true)
    {

        // Non blocking UART polling
        if (uart_avail(HOST_UART))
        {
            uint8_t uart_char = (uint8_t)uart_readb(HOST_UART);

            if ((uart_char != '\r') && (uart_char != '\n') && (uart_char != '\0') &&
                (uart_char != 0xD) && uart_buffer_index < sizeof(uart_buffer) - 1)
            {
                uart_buffer[uart_buffer_index] = uart_char;
                uart_buffer_index++;
            }
            else
            {
                uart_buffer[uart_buffer_index] = 0x00;
                uart_buffer_index = 0;

                if (!(strcmp((char *)uart_buffer, "enable")))
                {
                    enableFeature(&fob_state_ram);
                }
                else if (!(strcmp((char *)uart_buffer, "pair")))
                {
                    pairFob(&fob_state_ram);
                }
            }
        }

        current_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
        if ((current_sw_state != previous_sw_state) && (current_sw_state == 0))
        {
            // Debounce switch
            for (int i = 0; i < 10000; i++)
                ;
            debounce_sw_state = GPIOPinRead(GPIO_PORTF_BASE, GPIO_PIN_4);
            if (debounce_sw_state == current_sw_state)
            {
                sendUnlock(&fob_state_ram);
                recChalSendAnsFeature(&fob_state_ram);
            }
        }
        previous_sw_state = current_sw_state;
    }
}

/**
 * @brief Function that carries out pairing of the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void pairFob(FLASH_DATA *fob_state_ram)
{
    int ret = 0;
    MESSAGE_PACKET message;
    mbedtls_pk_context pk;
    mbedtls_aes_context aes;
    // Start pairing transaction - fob is already paired
    if (fob_state_ram->paired == FLASH_PAIRED)
    {
        // The pin_buffer has: pin(6), public pairing key(EEPROM_PAIRING_PUB_SIZE)
        uint8_t pin_buffer[6 + EEPROM_PAIRING_PUB_SIZE] = {0};
        uart_write(HOST_UART, (uint8_t *)"P", 1);

        if (uart_read(HOST_UART, pin_buffer, 6) != 6)
        {
            return;
        }

        // Read public pairing key from EEPROM
        EEPROMRead((uint32_t *)((uint8_t *)pin_buffer + 6), PAIRING_EEPROM_PUB_KEY_LOC,
                   EEPROM_PAIRING_PUB_SIZE);

        // Hash the pin buffer
        uint8_t hash[32] = {0};
        ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), pin_buffer,
                         sizeof(pin_buffer), hash);
        if (ret != 0)
        {
            sys_reset();
        }

        // Compare pin_buffer hash with stored hash
        if (memcmp(hash, fob_state_ram->pair_info.pin_hash, 32) == 0)
        {
            int ret = 0;
            PAIR_PACKET pair_packet;
            memcpy(&pair_packet.pair_info, &fob_state_ram->pair_info, sizeof(PAIR_INFO));

            // Load unlock private key to pair_packet
            EEPROMRead((uint32_t *)pair_packet.unlock_priv_key, UNLOCK_EEPROM_PRIV_KEY_LOC,
                       EEPROM_UNLOCK_PRIV_SIZE);

            AES_INFO aes_info;
            drng_seed("aes generate key");
            // Generate random AES key
            ret = mbedtls_ctr_drbg_random(&ctr_drbg, aes_info.key, AES_KEY_SIZE);
            if (ret != 0)
            {
                sys_reset();
            }

            // Generate random AES IV
            uint8_t ciphertext_iv[sizeof(PAIR_PACKET) + 16] = {0};
            ret = mbedtls_ctr_drbg_random(&ctr_drbg, ciphertext_iv + sizeof(PAIR_PACKET), 16);
            if (ret != 0)
            {
                sys_reset();
            }

            // AES-CBC requires input to be a multiple of 16 bytes
            size_t input_len = ((sizeof(PAIR_PACKET) + 15) / 16) * 16;
            uint8_t iv[16] = {0};
            // Copy the iv from the ciphertext_iv buffer as it will be updated
            memcpy(iv, ciphertext_iv + sizeof(PAIR_PACKET), 16);

            // Init AES context with key
            mbedtls_aes_init(&aes);
            ret = mbedtls_aes_setkey_enc(&aes, aes_info.key, 256);
            if (ret != 0)
            {
                sys_reset();
            }
            // Encrypt the pair packet with AES-CBC
            ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, input_len,
                                        iv, (uint8_t *)&pair_packet, ciphertext_iv);
            if (ret != 0)
            {
                sys_reset();
            }
            mbedtls_aes_free(&aes);

            // Make a hash over the ciphertext and iv
            ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), ciphertext_iv,
                             sizeof(ciphertext_iv), aes_info.hash);
            if (ret != 0)
            {
                sys_reset();
            }

            mbedtls_pk_init(&pk);
            // Parse public pairing key
            ret = mbedtls_pk_parse_public_key(&pk, ((uint8_t *)pin_buffer + 6), PAIRING_PUB_KEY_SIZE);
            if (ret != 0)
            {
                sys_reset();
            }

            // Encrypt AES key and hash with public pairing key
            uint8_t aes_info_cipher[64] = {0};
            size_t olen = 0;
            drng_seed("encrypt aes");
            ret = mbedtls_pk_encrypt(&pk, (const uint8_t *)&aes_info, sizeof(AES_INFO),
                                     aes_info_cipher, &olen, sizeof(aes_info_cipher),
                                     mbedtls_ctr_drbg_random, &ctr_drbg);
            if (ret != 0)
            {
                sys_reset();
            }
            mbedtls_pk_free(&pk);

            // Send encrypted AES key and hash to board
            message.message_len = sizeof(aes_info_cipher);
            message.magic = PAIR_MAGIC;
            message.buffer = aes_info_cipher;
            send_board_message(&message);

            // Send AES-encrypted pairing data (ciphertext and iv) to board
            send_pairing_data(ciphertext_iv);
        }
        else
        {
            // Wait 5 seconds before trying again
            for (int i = 0; i < 80000000 * 5; i++)
                ;
        }
    }
    // Start pairing transaction - fob is not paired
    else
    {
        uint8_t buffer[256];
        uint8_t ciphertext_iv[PAIR_DATA_LEN];
        message.buffer = buffer;

        // Receive encrypted AES key and hash
        if (receive_board_message_by_type(&message, PAIR_MAGIC) != 64)
        {
            return;
        }

        // Receive AES-encrypted pairing data (ciphertext and iv)
        receive_pairing_data(ciphertext_iv);

        // Read pairing private key from EEPROM
        uint8_t eeprom_pairing_priv_key[EEPROM_PAIRING_PRIV_SIZE] = {0};
        EEPROMRead((uint32_t *)eeprom_pairing_priv_key, PAIRING_EEPROM_PRIV_KEY_LOC,
                   EEPROM_PAIRING_PRIV_SIZE);

        mbedtls_pk_init(&pk);
        drng_seed("decrypt aes info");
        // Parse pairing private key
        ret = mbedtls_pk_parse_key(&pk, eeprom_pairing_priv_key, PAIRING_PRIV_KEY_SIZE, NULL, 0,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0)
        {
            sys_reset();
        }

        // Decrypt AES key and hash with pairing private key
        AES_INFO aes_info;
        size_t olen = 0;
        ret = mbedtls_pk_decrypt(&pk, message.buffer, message.message_len, (uint8_t *)&aes_info,
                                 &olen, sizeof(AES_INFO), mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0)
        {
            mbedtls_pk_free(&pk);
            return;
        }

        uint8_t hash[20] = {0};
        // Make a hash over the ciphertext and iv
        ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), ciphertext_iv,
                         sizeof(ciphertext_iv), hash);
        if (ret != 0)
        {
            sys_reset();
        }

        // Check if the received data hash matches the decrypted hash
        if (memcmp(hash, aes_info.hash, 20) == 0)
        {
            PAIR_PACKET pair_packet;
            size_t input_len = ((sizeof(PAIR_PACKET) + 15) / 16) * 16;

            // Init AES context with key
            mbedtls_aes_init(&aes);
            ret = mbedtls_aes_setkey_dec(&aes, aes_info.key, 256);
            if (ret != 0)
            {
                return;
            }
            // Decrypt the pair packet with AES-CBC
            ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, input_len,
                                        ciphertext_iv + sizeof(PAIR_PACKET),
                                        ciphertext_iv, (uint8_t *)&pair_packet);
            if (ret != 0)
            {
                return;
            }
            mbedtls_aes_free(&aes);

            // Register the fob as paired
            fob_state_ram->paired = FLASH_PAIRED;
            // Overwrite the pairing private key in EEPROM with the unlock private key
            EEPROMProgram((uint32_t *)pair_packet.unlock_priv_key,
                          UNLOCK_EEPROM_PRIV_KEY_LOC, EEPROM_UNLOCK_PRIV_SIZE);
            // Update the fob state with the new pairing info
            memcpy(&fob_state_ram->pair_info, &pair_packet.pair_info, sizeof(PAIR_INFO));
            fob_state_ram->feature_info.car_id = fob_state_ram->pair_info.car_id;

            uart_write(HOST_UART, (uint8_t *)"Paired", 6);
            saveFobState(fob_state_ram);
        }

        mbedtls_pk_free(&pk);
    }
}

/**
 * @brief Function that handles enabling a new feature on the fob
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void enableFeature(FLASH_DATA *fob_state_ram)
{
    if (fob_state_ram->paired != FLASH_PAIRED)
    {
        return;
    }
    // Create a message struct variable for receiving data
    MESSAGE_PACKET message;
    uint8_t buffer[256];
    message.buffer = buffer;

    message.magic = (uint8_t)uart_readb(HOST_UART);
    if (message.magic != ENABLE_MAGIC)
    {
        return;
    }
    message.message_len = (uint8_t)uart_readb(HOST_UART);
    uart_read(HOST_UART, message.buffer, message.message_len);

    // Message buffer has: ENABLE_PACKET(10), signature(64)
    ENABLE_PACKET *packet = (ENABLE_PACKET *)message.buffer;
    uint8_t *signature = message.buffer + sizeof(ENABLE_PACKET);

    int ret = 0;
    mbedtls_pk_context pk;

    // Read feature public key from EEPROM
    uint8_t eeprom_feature_pub_key[EEPROM_FEATURE_PUB_SIZE] = {0};
    EEPROMRead((uint32_t *)eeprom_feature_pub_key, FEATURE_EEPROM_PUB_KEY_LOC,
               EEPROM_FEATURE_PUB_SIZE);

    // Hash the enable packet
    uint8_t hash[32] = {0};
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), (uint8_t *)packet,
                     sizeof(ENABLE_PACKET), hash);
    if (ret != 0)
    {
        return;
    }

    // Parse feature public key
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_key(&pk, eeprom_feature_pub_key, FEATURE_PUB_KEY_SIZE);
    if (ret != 0)
    {
        goto cleanup;
    }

    // Verify the signature with the feature public key
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, signature, 64);
    if (ret != 0)
    {
        goto cleanup;
    }

    // Check if the car id is correct
    if (fob_state_ram->pair_info.car_id != packet->car_id)
    {
        goto cleanup;
    }

    // Feature list full
    if (fob_state_ram->feature_info.num_active == NUM_FEATURES)
    {
        goto cleanup;
    }

    // Search for feature in list
    for (int i = 0; i < fob_state_ram->feature_info.num_active; i++)
    {
        if (fob_state_ram->feature_info.features[i] == packet->feature)
        {
            goto cleanup;
        }
    }

    // Add feature to list
    fob_state_ram->feature_info.features[fob_state_ram->feature_info.num_active] = packet->feature;
    fob_state_ram->feature_info.num_active++;

    saveFobState(fob_state_ram);
    uart_write(HOST_UART, (uint8_t *)"Enabled", 7);
    goto cleanup;

cleanup:
    mbedtls_pk_free(&pk);
    return;
}

/**
 * @brief Function that sends an unlock message to the car
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
void sendUnlock(FLASH_DATA *fob_state_ram)
{
    if (fob_state_ram->paired == FLASH_PAIRED)
    {
        MESSAGE_PACKET message;
        message.message_len = 0;
        message.magic = UNLOCK_MAGIC;
        message.buffer = NULL;
        send_board_message(&message);
    }
}

/**
 * @brief Function that receives a challenge from the car and sends an answer
 *
 * @param fob_state_ram pointer to the current fob state in ram
 */
uint8_t recChalSendAnsFeature(FLASH_DATA *fob_state_ram)
{
    if (fob_state_ram->paired != FLASH_PAIRED)
    {
        return 0;
    }

    MESSAGE_PACKET message;
    uint8_t buffer[256];
    message.buffer = buffer;
    if (receive_board_message_by_type(&message, CHALLENGE_MAGIC) != 32)
    {
        return 0;
    }

    // The buffer has: CHALLENGE(32), FEATURE_DATA(5)
    memcpy(buffer + 32, &fob_state_ram->feature_info, sizeof(FEATURE_DATA));

    int ret = 0;
    uint8_t eeprom_unlock_priv_key[EEPROM_UNLOCK_PRIV_SIZE] = {0};

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    drng_seed("sign challenge");

    // Read private key from EEPROM
    EEPROMRead((uint32_t *)eeprom_unlock_priv_key, UNLOCK_EEPROM_PRIV_KEY_LOC,
               EEPROM_UNLOCK_PRIV_SIZE);

    ret = mbedtls_pk_parse_key(&pk, eeprom_unlock_priv_key, fob_state_ram->pair_info.unlock_priv_key_size, NULL, 0,
                               mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        sys_reset();
    }

    // Hash the challenge and feature info
    uint8_t hash[32] = {0};
    ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                     buffer, 32 + sizeof(FEATURE_DATA), hash);
    if (ret != 0)
    {
        sys_reset();
    }

    // Sign the hash
    // The buffer has: CHALLENGE(32), FEATURE_DATA(5), SIGNATURE(64)
    uint8_t *signature = buffer + 32 + sizeof(FEATURE_DATA);
    size_t olen = 0;
    ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0, signature, 64,
                          &olen, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0 || olen != 64)
    {
        sys_reset();
    }

    // Send the feature info and signature
    // The message buffer has: FEATURE_DATA(5), SIGNATURE(64)
    message.magic = ANSWER_MAGIC;
    message.message_len = sizeof(FEATURE_DATA) + 64;
    message.buffer = buffer + 32;
    send_board_message(&message);

    mbedtls_pk_free(&pk);
    return 1;
}

/**
 * @brief Function that erases and rewrites the non-volatile data to flash
 *
 * @param info Pointer to the flash data ram
 */
void saveFobState(FLASH_DATA *flash_data)
{
    FlashErase(FOB_STATE_PTR);
    FlashProgram((uint32_t *)flash_data, FOB_STATE_PTR, FLASH_DATA_SIZE);
}
