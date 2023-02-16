/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Aspeed Technology Inc.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#if defined(PLATFORM_FLAVOR_ast2600)
#define GIC_BASE		0x40460000
#define GICC_OFFSET		0x2000
#define GICD_OFFSET		0x1000

#define AHBC_BASE		0x1e600000
#define SCU_BASE		0x1e6e2000
#define UART5_BASE		0x1e784000

#define CONSOLE_UART_BASE	UART5_BASE
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	1846153
#elif defined(PLATFORM_FLAVOR_ast2700)
#define GICD_BASE		0x12200000
#define GICC_BASE		0x40460000
#define GICR_BASE		0x12280000

#define UART4_BASE		0x12c1a000

#define CONSOLE_UART_BASE	UART4_BASE
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	1846153
#else
#error "Unknown platform flavor"
#endif

#endif /*PLATFORM_CONFIG_H*/
