#include "mbedtls/entropy.h"
#include "mbedtls/build_info.h"
#include "mbedtls/ctr_drbg.h"

#include "constant.h"

static mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
const char *pers = "fourty-two";

/**
 * @brief  Initialize the DWT
 * @param  None
 * @retval None
 */
void dwt_init(void)
{
    // See if DWT is available
    if (ARM_CM_DWT_CTRL != 0)
    {                            // See if DWT is available
        ARM_CM_DEMCR |= 1 << 24; // Set bit 24 to enable dwt trace
        ARM_CM_DWT_CYCCNT = 0;
        ARM_CM_DWT_CTRL |= 1 << 0; // Set bit 0
    }
}

/**
 * @brief  Entropy function for ctr_drbg
 */
int ctr_drbg_dwt_entropy(void *data, unsigned char *buf,
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

/**
 * @brief  Initialize the DRNG
 * @param  None
 * @retval 0: success
 */
int drng_init()
{
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_set_entropy_len(&ctr_drbg, MBEDTLS_CTR_DRBG_KEYSIZE);   // 32-byte
    mbedtls_ctr_drbg_set_nonce_len(&ctr_drbg, MBEDTLS_CTR_DRBG_KEYSIZE / 2); // 16-byte

    return 0;
}

/**
 * @brief  Seed the DRNG
 * @param  None
 * @retval 0: success
 */
int drng_seed()
{
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, ctr_drbg_dwt_entropy, &entropy,
                              (const unsigned char *)pers, strlen(pers)) != 0)
    {
        while (1)
        {
        }
    }
    return 0;
}

/**
 * @brief  Free the DRNG
 * @param  None
 * @retval 0: success
 */
int drng_free()
{
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return 0;
}