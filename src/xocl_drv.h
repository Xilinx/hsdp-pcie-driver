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

#define SUBDEV_SUFFIX
#define XOCL_MAX_DEVICES    16

#define XOCL_HSDP_SIM       "hsdp_sim" SUBDEV_SUFFIX
#define XOCL_HSDP_PUB       "hsdp_user" SUBDEV_SUFFIX
#define XOCL_HSDP_PRI       "hsdp_mgmt" SUBDEV_SUFFIX
#define XOCL_HSDP_SOFT      "hsdp_mgmt_soft" SUBDEV_SUFFIX

#define XOCL_INVALID_MINOR -1

extern struct class *xrt_class;

#define xocl_err(dev, fmt, args...)         \
    dev_err(dev, "%s: "fmt, __func__, ##args)
#define xocl_info(dev, fmt, args...)            \
    dev_info(dev, "%s: "fmt, __func__, ##args)
#define xocl_dbg(dev, fmt, args...)         \
    dev_dbg(dev, "%s: "fmt, __func__, ##args)

#define XOCL_DEV_ID(pdev)           \
    ((pci_domain_nr(pdev->bus) << 16) | \
    PCI_DEVID(pdev->bus->number, pdev->devfn))

struct hsdp_pcie_config;

struct xocl_dev_core {
    struct pci_dev          *pdev;
    int                      dev_minor;
    struct platform_device **pldevs;
    unsigned                npldevs;
    char                     pdev_name[128];
};

typedef void *  xdev_handle_t;


/* helper functions */
xdev_handle_t xocl_get_xdev(struct platform_device *pdev);
int xocl_alloc_dev_minor(xdev_handle_t xdev_hdl);
void xocl_free_dev_minor(xdev_handle_t xdev_hdl);
