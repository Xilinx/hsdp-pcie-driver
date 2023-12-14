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

#ifndef _hsdp_pcie_config_H
#define _hsdp_pcie_config_H

enum mgmt_type {
    MT_NULL,
    MT_CPM4,
    MT_CPM5,
    MT_SOFT
};

struct mgmt_bar_space_info {
    unsigned dma_bar_index;
    uint64_t dma_bar_offset;
    enum mgmt_type type;
    unsigned bridge_ctl_bar_index;
    uint64_t bridge_ctl_bar_offset;
    unsigned bridge_bar_index;
    uint64_t bridge_bar_offset;
    uint64_t bridge_bar_size;
    unsigned bridge_ctl_bar_table_entry;
};

struct debug_hub_info {
    uint64_t axi_address;
    unsigned bar_index;
    uint64_t bar_offset;
    uint64_t size;
};

#define MAX_DEBUG_HUBS 16

struct user_bar_space_info {
    const struct debug_hub_info hub_infos[MAX_DEBUG_HUBS];
};

enum platform_device_type {
    DT_HSDP_NULL,
    DT_HSDP_USER,
    DT_HSDP_MGMT
};

struct hsdp_pcie_config {
    const char *name;
    enum platform_device_type device_type;
    union {
        struct mgmt_bar_space_info mgmt;
        struct user_bar_space_info user;
    } u;
};

/* Select CPM4 or CPM5 */
// Versal products with CPM4:
//   - AI Core = VC1502-VC1902
//   - AI Edge = VE1752
//   - Prime   = VM1302-VM1802
#define CPM4
//#define CPM5

/*
 *  Modify the macros and structure below with PCIe customizations for the driver, if desired.
 *    PCIE_VENDOR_ID  - hex value for PCIe device vendor
 *    PCIE_DEVICE_ID  - hex value for PCIe device ID
 */

#define PCIE_DRIVER_NAME "xilinx_hsdp_pcie_driver"

#define PCIE_VENDOR_ID  0x10EE
#define PCIE_DEVICE_ID  0xB03F

static const struct hsdp_pcie_config user_configs[] = {
    /////////////////////////////////////////////////////////
    //  The single debug tree entry below with an empty
    //  name modifier will create a character file called:
    //
    //   /dev/cfg_ioc0
    //
    //  Values set in the mgmt device correlate to Vivado's
    //  configurable example design (CED).
    /////////////////////////////////////////////////////////
#ifdef CPM4
    /* Defaults for CPM4 CED */
    {
        .device_type = DT_HSDP_MGMT,
        .u.mgmt = {
            // CED : PCIe BAR 2 address translates to 0xFE400000 (4 MB aperture)
            //     : HSDP_DMA Base = 0xFE400000 + 0x1F0000 = 0xFE5F0000
            .dma_bar_index         = 0x2,
            .dma_bar_offset        = 0x1F0000,
            // CED : PCIe BAR 4 address translates to 0x600000000 (4 KB aperture)
            .bridge_ctl_bar_index  = 0x4,
            .bridge_ctl_bar_offset = 0x0,
            // CED : AXI BAR 1 from 0x700000000 (4 GB aperture)
            .type                  = MT_CPM4,
            .bridge_bar_index      = 0,
            .bridge_bar_offset     = 0x700000000,
            .bridge_bar_size       = 0x100000000
        },
    },
    {
        .name = "rp1",
        .device_type = DT_HSDP_USER,
        .u.user = {
            .hub_infos = {
                {
                    // CED : PCIe BAR 2 address translates to 0xFE400000, NMU
                    //       remaps up to PL address range
                    .axi_address = 0x20100000000,
                    .bar_index   = 4,
                    .bar_offset  = 0x200000,
                    .size        = 0x200000
                },
                {0}
            }
        },
    },
#elif defined(CPM5)
    /* Defaults for CPM5 CED */
    {
        .device_type = DT_HSDP_MGMT,
        .u.mgmt = {
            .type                       = MT_CPM5,
            // CED : PCIe BAR 2 address translates to 0xFC000000
            //     : HSDP_DMA Base = 0xFC000000 + 0x25F0000 = 0xFE5F0000
            .dma_bar_index              = 0x2,
            .dma_bar_offset             = 0x025F0000,
            // CED : PCIe BAR 2 address translates to 0xFC000000
            //     : CPM5_DMA0_ATTR Base = 0xFC000000 + 0xE10000 = 0xFCE10000
            .bridge_ctl_bar_index       = 0x2,
            .bridge_ctl_bar_offset      = 0x00E10000,
            // CED : CPM5 needs BDF table entry used, which corresponds to CPM
            //       GUI 'AXI BARs' tab
            /* PCIe Region 0 */
            .bridge_ctl_bar_table_entry = 0, //BDF Table Entry 0
            .bridge_bar_offset          = 0xE0000000,
            .bridge_bar_size            = 0x00400000
            /* PCIe Region 1
            .bridge_ctl_bar_table_entry = 128, //BDF Table Entry 128
            .bridge_bar_offset          = 0x700000000,
            .bridge_bar_size            = 0x04000000
            */
            /* PCIe Region 2
            .bridge_ctl_bar_table_entry = 192, //BDF Table Entry 192
            .bridge_bar_offset          = 0x8000000000,
            .bridge_bar_size            = 0x04000000
            */
        },
    },
    {
        .name = "rp1",
        .device_type = DT_HSDP_USER,
        .u.user = {
            .hub_infos = {
                {
                    // CED : PCIe BAR 4 address translates to 0x20100000000
                    .axi_address = 0x20100000000,
                    .bar_index   = 4,
                    .bar_offset  = 0,
                    .size        = 0x200000
                },
                {0}
            }
        },
    },
#else
    {
        .device_type = DT_HSDP_MGMT,
        .u.mgmt = {
            .type                       = MT_SOFT,
            .dma_bar_index              = 0x2,
            .dma_bar_offset             = 0x10000,
            .bridge_bar_offset          = 0x0,
            .bridge_bar_size            = 0x8000000000000000,
            .bridge_ctl_bar_index       = 0x2,
            .bridge_ctl_bar_offset      = 0x0,
            0
        },
    },
#endif
};


#define USER_CONFIG_COUNT (sizeof(user_configs) / sizeof(*user_configs))

#endif /* _hsdp_pcie_config_H */
