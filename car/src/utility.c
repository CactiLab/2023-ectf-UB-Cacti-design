/**
 * @file main.c
 * @author Xi Tan
 * @brief eCTF Fob Example Design Implementation
 * @date 2023.02.08
 *
 * This source file is part of the implentation: take the cpu cycles as seed to generate random number
 *
 * @copyright Copyright (c) 2023 CactiLab
 */

#include "constant.h"

void dwt_init(void)
{
   // See if DWT is available
   if (ARM_CM_DWT_CTRL != 0)
   {                           // See if DWT is available
      ARM_CM_DEMCR |= 1 << 24; // Set bit 24 to enable dwt trace
      ARM_CM_DWT_CYCCNT = 0;
      ARM_CM_DWT_CTRL |= 1 << 0; // Set bit 0
   }
}

void dummy_handler()
{
   while (1)
   {
   }
}

static int ctr_drbg_self_test_entropy(void *data, unsigned char *buf,
                                      size_t len)
{
   const unsigned char *p = data;
   uint32_t tmp[OUTPUT_SIZE / 4] = {0};
   for (size_t i = 0; i < OUTPUT_SIZE / 4; i++)
   {
      tmp[i] = ARM_CM_DWT_CYCCNT + i;
   }
   memcpy(buf, tmp, len);
   return 0;
}

void random_init(mbedtls_ctr_drbg_context *drbg,
                 mbedtls_entropy_context *entropy)
{
   mbedtls_entropy_init(entropy);
   mbedtls_ctr_drbg_init(drbg);
}

void random_exit(mbedtls_ctr_drbg_context *drbg,
                 mbedtls_entropy_context *entropy)
{
   mbedtls_ctr_drbg_free(drbg);
   mbedtls_entropy_free(entropy);
}

void random_gnereator(mbedtls_ctr_drbg_context *drbg,
                      mbedtls_entropy_context *entropy,
                      size_t entropy_len,
                      size_t nonce_len,
                      unsigned char *output,
                      size_t output_size)
{
   size_t ret = 0;
   //  unsigned char output[OUTPUT_SIZE] = {0};

   mbedtls_ctr_drbg_set_entropy_len(drbg, entropy_len); // 32-byte
   mbedtls_ctr_drbg_set_nonce_len(drbg, nonce_len);     // 16-byte
   ret = mbedtls_ctr_drbg_seed(drbg, ctr_drbg_self_test_entropy, entropy, NULL, nonce_len);

   if (ret != 0)
   {
      dummy_handler();
   }
   ret = mbedtls_ctr_drbg_random(drbg, output, output_size);
   if (ret != 0)
   {
      dummy_handler();
   }
}

/***************************************************************************************/
/* test */
// mbedtls_ctr_drbg_reseed_internal(mbedtls_ctr_drbg_context *ctx,
// const unsigned char *additional,
// size_t len,
// size_t nonce_len)
// mbedtls_ctr_drbg_reseed_internal(ctx, custom, len, nonce_len))
//  f_entropy(ctx->p_entropy, seed, ctx->entropy_len)

// ctx = drbg, f_entropy = mbedtls_entropy_func, p_entropy = &entropy, custom = NULL, len = ?
// int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context *ctx,
//                           int (*f_entropy)(void *, unsigned char *, size_t),
//                           void *p_entropy,
//                           const unsigned char *custom,
//                           size_t len)
// ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, (void *) entropy_source_pr, pers_pr, MBEDTLS_CTR_DRBG_KEYSIZE);
/* BEGIN_CASE depends_on:MBEDTLS_ENTROPY_C:MBEDTLS_CTR_DRBG_C */
void random_twice_with_ctr_drbg()
{
   mbedtls_entropy_context entropy;
   mbedtls_ctr_drbg_context drbg;
   int ret = 1;

   unsigned char output1[OUTPUT_SIZE];
   unsigned char output2[OUTPUT_SIZE];

   memset(output1, 0, OUTPUT_SIZE);
   memset(output2, 0, OUTPUT_SIZE);

   /* First round */
   random_init(&drbg, &entropy);

   mbedtls_ctr_drbg_set_entropy_len(&drbg, MBEDTLS_CTR_DRBG_KEYSIZE);   // 32-byte
   mbedtls_ctr_drbg_set_nonce_len(&drbg, MBEDTLS_CTR_DRBG_KEYSIZE / 2); // 16-byte
   ret = mbedtls_ctr_drbg_seed(&drbg, ctr_drbg_self_test_entropy, &entropy, NULL, MBEDTLS_CTR_DRBG_KEYSIZE / 2);

   if (ret != 0)
   {
      dummy_handler();
   }
   ret = mbedtls_ctr_drbg_random(&drbg, output1, sizeof(output1));
   if (ret != 0)
   {
      dummy_handler();
   }
   random_exit(&drbg, &entropy);

   /* Second round */
   random_init(&drbg, &entropy);
   mbedtls_ctr_drbg_set_entropy_len(&drbg, MBEDTLS_CTR_DRBG_KEYSIZE);
   mbedtls_ctr_drbg_set_nonce_len(&drbg, MBEDTLS_CTR_DRBG_KEYSIZE / 2);

   ret = mbedtls_ctr_drbg_seed(&drbg, ctr_drbg_self_test_entropy, &entropy, NULL, MBEDTLS_CTR_DRBG_KEYSIZE / 2);
   if (ret != 0)
   {
      dummy_handler();
   }
   ret = mbedtls_ctr_drbg_random(&drbg, output2, sizeof(output2));
   if (ret != 0)
   {
      dummy_handler();
   }
   random_exit(&drbg, &entropy);

   /* The two rounds must generate different random data. */
   if (memcmp(output1, output2, OUTPUT_SIZE) != 0)
   {
      dummy_handler();
   }

exit:
   random_exit(&drbg, &entropy);
}
/* END_CASE */