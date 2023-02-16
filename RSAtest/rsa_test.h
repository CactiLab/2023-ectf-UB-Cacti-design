//
//  rsa_test.h
//  RSAProject
//
//  Created by guozhicheng on 5/9/16.
//  Modified by Xi Tan on 02/16/2023
//  Copyright © 2023 guozhicheng, Xi Tan. All rights reserved.
//

#ifndef rsa_test_h
#define rsa_test_h

#include <inttypes.h>
#include <stdio.h>
#include "mbedtls/rsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "sha1.h"
#include "rsa.h"

#define KEY_SIZE 512
#define D_SIZE KEY_SIZE/8  //64
#define E_SIZE 8
#define N_SIZE KEY_SIZE/8 //64
#define P_SIZE D_SIZE/2  //32
#define Q_SIZE D_SIZE/2  //32
#define EXPONENT 65537
#define MSG_SIZE 64

int mbedtls_rsa_self_test( int verbose );

void testprint();

void generateRSAKeys();

void initPubKey();

void pubEn() ;

typedef struct
{
    uint32_t key[16];
    uint32_t v0, v1;
} rnd_pseudo_info;

typedef struct __attribute__((packed)){
    uint8_t N[N_SIZE];              /*!<  The public modulus. */
    uint8_t E[E_SIZE];              /*!<  The public exponent. */
    uint8_t D[D_SIZE];              /*!<  The private exponent. */
    uint8_t P[P_SIZE];              /*!<  The first prime factor. */
    uint8_t Q[Q_SIZE];              /*!<  The second prime factor. */
}RSA_KEY_CTX;

#endif /* rsa_test_h */
