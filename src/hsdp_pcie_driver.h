/*
 * Xilinx HSDP PCIe Driver
 * Copyright (C) 2021-2022 Xilinx, Inc.
 * Copyright (C) 2022-2023 Advanced Micro Devices, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _HSDP_PCIE_DRIVER_H
#define _HSDP_PCIE_DRIVER_H

#include "hsdp_pcie_user_config.h"

enum pcie_context_type {
	PCIE_CTX_NULL,
	PCIE_CTX_CFG,
	PCIE_CTX_BAR
};

struct pcie_context_t {
	enum pcie_context_type type;
	union {
		void* __iomem bar;
		size_t cfg;
	} offset;
};


int __init xocl_init_hsdp_mgmt(void);
void xocl_fini_hsdp_mgmt(void);
int xocl_set_config_hsdp_mgmt(struct platform_device *pdev, const struct hsdp_pcie_config *config);

int __init xocl_init_hsdp_user(void);
void xocl_fini_hsdp_user(void);
int xocl_set_config_hsdp_user(struct platform_device *pdev, const struct hsdp_pcie_config *config);

int __init xocl_init_hsdp_mgmt_soft(void);
void xocl_fini_hsdp_mgmt_soft(void);
int xocl_set_config_hsdp_mgmt_soft(struct platform_device *pdev, const struct hsdp_pcie_config *config);


#endif /* _HSDP_PCIE_DRIVER_H */
