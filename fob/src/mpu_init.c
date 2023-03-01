#include <stdint.h>
#include <stdbool.h>
#include "driverlib/debug.h"
#include "driverlib/mpu.h"
#include "uart.h"
#include "constant.h"

// Flash: Pared firmware (car or fob) (0x00008000 - 0x00023800)/1024 = 110k = 64+32+8+4+2
#define MPU_RGN_SIZE_110K MPU_RGN_SIZE_64K + MPU_RGN_SIZE_32K + MPU_RGN_SIZE_8K + MPU_RGN_SIZE_4K + MPU_RGN_SIZE_2K

// SRAM: (0x20000000-0x20008000)/1024 = 32k

void mpu_handler(void)
{
    ASSERT(MPU_RGN_SIZE_16K);
    uart_writeb(HOST_UART, 0xaa);
}

void mpu_init()
{
    __asm("dmb");

    uint32_t mpu_flag = 0;
    if (MPURegionCountGet() < 8)
    {
        return;
    }
    /* Disable MPU */
    MPUDisable();
    /*
    Configure region 0 to cover FLASH (car or fob) region 0x00008000 - 0x00023800: 110KB
    size: MPU_RGN_SIZE_110K
    executable: yes
    AP: read-only
    */
    mpu_flag = (MPU_RGN_SIZE_110K) | (MPU_RGN_PERM_EXEC) | (MPU_RGN_PERM_PRV_RW_USR_RW) | (MPU_RGN_ENABLE);
    MPURegionSet(0, 0x00008000, mpu_flag);
    MPURegionEnable(0);

    /*
    Configure region 1 to cover Bootloader and pared memory: 0x20000000-0x20008000: 32KB
    size: MPU_RGN_SIZE_32K
    executable: no
    AP: RW
    */
    mpu_flag = (MPU_RGN_SIZE_32K) | (MPU_RGN_PERM_NOEXEC) | (MPU_RGN_PERM_PRV_RW_USR_RW) | (MPU_RGN_ENABLE);
    MPURegionSet(1, 0x20000000, mpu_flag);
    MPURegionEnable(1);

    MPUIntRegister(mpu_handler);
    MPUEnable(MPU_CONFIG_PRIV_DEFAULT);

    __asm("dsb");
    __asm("isb");
}