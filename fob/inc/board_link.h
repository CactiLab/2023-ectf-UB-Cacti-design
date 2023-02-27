/**
 * @file board_link.h
 * @author Frederich Stine
 * @brief Function that defines interface for communication between boards
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#ifndef BOARD_LINK_H
#define BOARD_LINK_H

#include <stdint.h>

#include "inc/hw_memmap.h"

#define ACK_SUCCESS 1
#define ACK_FAIL 0

#define ACK_MAGIC 0x54
#define PAIR_MAGIC 0x55
#define PAIR_DATA_MAGIC 0x56
#define UNLOCK_MAGIC 0x57
#define CHALLENGE_MAGIC 0x58
#define ANSWER_MAGIC 0x59
#define START_MAGIC 0x60
#define ENABLE_MAGIC 0x61
#define BOARD_UART ((uint32_t)UART1_BASE)

#define PAIR_DATA_LEN 384

/**
 * @brief Structure for message between boards
 *
 */
typedef struct
{
  uint8_t magic;
  uint8_t message_len;
  uint8_t *buffer;
} MESSAGE_PACKET;

/**
 * @brief Set the up board link object
 *
 * UART 1 is used to communicate between boards
 */
void setup_board_link(void);

/**
 * @brief Send a message between boards
 *
 * @param message pointer to message to send
 * @return uint32_t the number of bytes sent
 */
uint32_t send_board_message(MESSAGE_PACKET *message);

/**
 * @brief Receive a message between boards
 *
 * @param message pointer to message where data will be received
 * @return uint32_t the number of bytes received
 */
uint32_t receive_board_message(MESSAGE_PACKET *message);

/**
 * @brief Function that retreives messages until the specified message is found
 *
 * @param message pointer to message where data will be received
 * @param type the type of message to receive
 * @return uint32_t the number of bytes received
 */
uint32_t receive_board_message_by_type(MESSAGE_PACKET *message, uint8_t type);

/**
 * @brief Send pairing data between boards
 *
 * @param data pointer to data to send
 * @return uint32_t the number of bytes sent
 */
uint32_t send_pairing_data(uint8_t *data);

/**
 * @brief Receive the pairing data between boards
 *
 * @param message pointer to message where data will be received
 * @return uint32_t the number of bytes received - 0 for error
 */
uint32_t receive_pairing_data(uint8_t *data);


#endif
