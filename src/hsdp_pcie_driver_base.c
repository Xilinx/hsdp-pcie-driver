/*
 * Xilinx HSDP PCIe Driver
 * Copyright (C) 2021 Xilinx Corporation
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

#include <linux/pci.h>
#include <linux/mod_devicetable.h>

#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>

#include <linux/idr.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include "hsdp_pcie_user_config.h"
#include "hsdp_pcie_driver.h"

#include "xocl_drv.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Elessar Taggart <elessar@xilinx.com>");
MODULE_DESCRIPTION("HSDP Debug Register Access over PCIe");

#define MIN(a, b) (a < b ? a : b)

struct xil_hsdp_char {
    struct pci_dev *pci_dev;
    struct hsdp_pcie_config *hsdp_config;
};

struct class *xrt_class;

static DEFINE_IDA(xocl_dev_minor_ida);

xdev_handle_t xocl_get_xdev(struct platform_device *pdev)
{
    struct device *dev;

    dev = pdev->dev.parent;

    return dev ? pci_get_drvdata(to_pci_dev(dev)) : NULL;
}

int xocl_alloc_dev_minor(xdev_handle_t xdev_hdl)
{
    struct xocl_dev_core *core = (struct xocl_dev_core *)xdev_hdl;

    core->dev_minor = ida_simple_get(&xocl_dev_minor_ida,
        0, 0, GFP_KERNEL);

    if (core->dev_minor < 0) {
        xocl_err(&core->pdev->dev, "Failed to alloc dev minor");
        core->dev_minor = XOCL_INVALID_MINOR;
        return -ENOENT;
    }

    return 0;
}

void xocl_free_dev_minor(xdev_handle_t xdev_hdl)
{
    struct xocl_dev_core *core = (struct xocl_dev_core *)xdev_hdl;

    if (core->dev_minor != XOCL_INVALID_MINOR) {
        ida_simple_remove(&xocl_dev_minor_ida, core->dev_minor);
        core->dev_minor = XOCL_INVALID_MINOR;
    }
}

static void xil_hsdp_cleanup(void)
{
    printk(KERN_INFO LOG_PREFIX "Cleaning up resources...\n");

    if (!IS_ERR(xrt_class)) {
        class_unregister(xrt_class);
        class_destroy(xrt_class);
    }
}

int mgmt_probe(struct pci_dev *pdev, const struct hsdp_pcie_config *config)
{
    int status;
    struct xocl_dev_core *core;
    resource_size_t bar_start;
    resource_size_t bar_len;
    resource_size_t map_len;
    struct platform_device *pldev = NULL;
    struct resource *res;
    const int nres = 2;
    unsigned int bar_index = config->u.mgmt.dma_bar_index;

    printk(KERN_INFO LOG_PREFIX "mgmt_probe\n");

    core = pci_get_drvdata(pdev);
    if (!core) {
        xocl_err(&pdev->dev, "driver data is NULL");
        return -EINVAL;
    }

    if ((!pci_resource_flags(pdev, bar_index)) & IORESOURCE_MEM) {
        printk(KERN_ERR LOG_PREFIX "Incorrect BAR configuration\n");
        return -ENODEV;
    }

    bar_start = pci_resource_start(pdev, bar_index);
    bar_len = pci_resource_len(pdev, bar_index);
    map_len = bar_len;

    pldev = platform_device_alloc(XOCL_HSDP_PRI, core->npldevs);
    if (!pldev) {
        xocl_err(&pdev->dev, "failed to alloc device %s", XOCL_HSDP_PRI);
        status = -ENOMEM;
        goto error;
    }

    core->pldevs[core->npldevs++] = pldev;

    /* Set up individual resources */
    res = kzalloc(sizeof (*res)*nres, GFP_KERNEL);
    if (!res) {
        xocl_err(&pldev->dev, "out of memory");
        status = -ENOMEM;
        goto error;
    }
    res[0].start = bar_start;
    res[0].end = bar_start + map_len - 1;
    res[0].flags = IORESOURCE_MEM;

    // AXI Bridge Bar
    bar_index = config->u.mgmt.bridge_ctl_bar_index;
    if ((!pci_resource_flags(pdev, bar_index)) & IORESOURCE_MEM) {
        printk(KERN_ERR LOG_PREFIX "Incorrect BAR configuration\n");
        kfree(res);
        return -ENODEV;
    }

    bar_start = pci_resource_start(pdev, bar_index);
    bar_len = pci_resource_len(pdev, bar_index);
    map_len = bar_len;

    res[1].start = bar_start;
    res[1].end = bar_start + map_len - 1;
    res[1].flags = IORESOURCE_MEM;

    status = platform_device_add_resources(pldev, res, nres);
    kfree(res);
    if (status) {
        xocl_err(&pldev->dev, "failed to add res");
        goto error;
    }

    pldev->dev.parent = &pdev->dev;

    status = xocl_set_config_hsdp_mgmt(pldev, config);
    if (status)
        return status;

    status = platform_device_add(pldev);
    if (status) {
        xocl_err(&pldev->dev, "failed to add device");
        goto error;
    }

    return 0;

error:
    return status;
}

int user_probe(struct pci_dev *pdev, const struct hsdp_pcie_config *config)
{
    int status;
    struct xocl_dev_core *core;
    struct platform_device *pldev = NULL;
    struct resource *res;
    unsigned nres = 0;
    unsigned i;
    const struct debug_hub_info *hub;

    printk(KERN_INFO LOG_PREFIX "user_probe\n");

    core = pci_get_drvdata(pdev);
    if (!core) {
        xocl_err(&pdev->dev, "driver data is NULL");
        return -EINVAL;
    }

    pldev = platform_device_alloc(XOCL_HSDP_PUB, core->npldevs);
    if (!pldev) {
        xocl_err(&pdev->dev, "failed to alloc device %s", XOCL_HSDP_PUB);
        status = -ENOMEM;
        goto error;
    }

    core->pldevs[core->npldevs++] = pldev;

    for (hub = config->u.user.hub_infos; hub->axi_address; ++hub) {
        if ((!pci_resource_flags(pdev, hub->bar_index)) & IORESOURCE_MEM) {
            printk(KERN_ERR LOG_PREFIX "Incorrect BAR configuration\n");
            return -ENODEV;
        }
        ++nres;
    }

    /* Set up individual resources */
    res = kzalloc(sizeof (*res)*nres, GFP_KERNEL);
    if (!res) {
        xocl_err(&pldev->dev, "out of memory");
        status = -ENOMEM;
        goto error;
    }

    for (i = 0; i < nres; ++i) {
        resource_size_t bar_start;
        resource_size_t bar_len;
        resource_size_t map_len;

        hub = config->u.user.hub_infos + i;

        bar_start = pci_resource_start(pdev, hub->bar_index) + hub->bar_offset;
        bar_len = pci_resource_len(pdev, hub->bar_index);
        map_len = MIN(bar_len - hub->bar_offset, hub->size);

        printk(KERN_INFO LOG_PREFIX "User probe bar start 0x%08llx, len 0x%08llx\n",
            (unsigned long long) bar_start, (unsigned long long) map_len);

        res[i].start = bar_start;
        res[i].end = bar_start + map_len - 1;
        res[i].flags = IORESOURCE_MEM;
    }

    status = platform_device_add_resources(pldev, res, nres);
    kfree(res);
    if (status) {
        xocl_err(&pldev->dev, "failed to add res");
        goto error;
    }

    pldev->dev.parent = &pdev->dev;

    status = xocl_set_config_hsdp_user(pldev, config);
    if (status)
        return status;

    status = platform_device_add(pldev);
    if (status) {
        xocl_err(&pldev->dev, "failed to add device");
        goto error;
    }

    return 0;

error:
    return status;
}


int probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    struct xocl_dev_core *core;
    int status = 0;
    int i;

    core = devm_kzalloc(&pdev->dev, sizeof (*core), GFP_KERNEL);
    if (!core) {
        xocl_err(&pdev->dev, "failed to alloc xocl_dev");
        return -ENOMEM;
    }

    /* this is used for all subdevs, bind it to device earlier */
    pci_set_drvdata(pdev, core);

    core->pdev = pdev;
    snprintf(core->pdev_name, sizeof(core->pdev_name)-1, "%02x:%02x.%01x",
        pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));

    status = xocl_alloc_dev_minor(core);
    if (status)
        goto failed_alloc_minor;

    status = pci_enable_device(pdev);
    if (status)
        return status;

    core->pldevs = devm_kzalloc(&pdev->dev, sizeof (*core->pldevs)*USER_CONFIG_COUNT, GFP_KERNEL);
    if (!core->pldevs) {
        xocl_err(&pdev->dev, "out of memory");
        status = -ENOMEM;
        goto failed_alloc_minor;
    }

    /* enable bus master capability */
    pci_set_master(pdev);

    for (i = 0; i < USER_CONFIG_COUNT; ++i) {
        const struct hsdp_pcie_config *config = user_configs + i;
        switch (config->device_type) {
        case DT_HSDP_MGMT:
            status = mgmt_probe(pdev, config);
            if (status) return status;
            break;
        case DT_HSDP_USER:
            status = user_probe(pdev, config);
            if (status) return status;
            break;
        default:
            break;
        }
    }

    return 0;

failed_alloc_minor:
    devm_kfree(&pdev->dev, core);
    pci_set_drvdata(pdev, NULL);
    return status;
}

void remove(struct pci_dev *pdev)
{
    struct xocl_dev_core *core;

    core = pci_get_drvdata(pdev);
    if (!core) {
        xocl_err(&pdev->dev, "driver data is NULL");
        return;
    }

    while (core->npldevs) {
        struct platform_device *pldev = core->pldevs[--core->npldevs];
        device_release_driver(&pldev->dev);
        platform_device_unregister(pldev);
    }

    xocl_free_dev_minor(core);
    pci_set_drvdata(pdev, NULL);
}

static struct pci_device_id xilinx_ids[] = {
    {PCI_DEVICE(PCIE_VENDOR_ID, PCIE_DEVICE_ID)},
    {0, },
};

static struct pci_driver xil_hsdp_pci_driver = {
    .name = PCIE_DRIVER_NAME,
    .id_table = xilinx_ids,
    .probe = probe,
    .remove = remove,
};

static int __init xil_hsdp_init(void)
{
    printk(KERN_INFO LOG_PREFIX "xil_hsdp_init\n");

    // Register the character device class for the actual files
    xrt_class = class_create(THIS_MODULE, "xil_hsdp_class");
    if (IS_ERR(xrt_class)) {
        xil_hsdp_cleanup();
        return PTR_ERR(xrt_class);
    }

    xocl_init_hsdp_mgmt();
    xocl_init_hsdp_user();

    return pci_register_driver(&xil_hsdp_pci_driver);
}


static void __exit xil_hsdp_exit(void)
{
    pci_unregister_driver(&xil_hsdp_pci_driver);

    xocl_fini_hsdp_mgmt();
    xocl_fini_hsdp_user();

    xil_hsdp_cleanup();
}


module_init(xil_hsdp_init);
module_exit(xil_hsdp_exit);
