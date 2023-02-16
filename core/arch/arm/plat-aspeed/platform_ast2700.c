// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Aspeed Technology Inc.
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/serial8250_uart.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/panic.h>

register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE, SMALL_PAGE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, GICC_BASE, GIC_CPU_REG_SIZE);

register_ddr(CFG_DRAM_BASE, CFG_DRAM_SIZE);

static struct serial8250_uart_data console_data;
static struct gic_data gic_data;

void main_init_gic(void)
{
	gic_init(&gic_data, GICC_BASE, GICD_BASE);
	itr_init(&gic_data.chip);
}

void main_secondary_init_gic(void)
{
	gic_cpu_init(&gic_data);
}

void itr_core_handler(void)
{
	gic_it_handle(&gic_data);
}

void console_init(void)
{
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}

void plat_primary_init_early(void)
{
	/* TODO */
}
