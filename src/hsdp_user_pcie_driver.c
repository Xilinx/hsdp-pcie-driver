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

#include <linux/pci.h>
#include <linux/mod_devicetable.h>

#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>

#include <linux/uaccess.h>

#include <linux/spinlock.h>
#include <linux/platform_device.h>
#include <linux/list.h>

#include "hsdp_pcie_user_config.h"
#include "xocl_drv.h"

#define MIN(a, b) (a < b ? a : b)

struct hsdp_axi_debug_hub {
    uint64_t axi_address;
    uint64_t phys_address;
    unsigned size;
};

struct hsdp_axi_info {
    struct hsdp_axi_debug_hub *hubs;
    unsigned num_hubs;
};

#define XIL_HSDP_MAGIC 0x415849  // "AXI"
#define XDMA_IOC_AXI_INFO _IOWR(XIL_HSDP_MAGIC, 0, struct hsdp_axi_info)

#define MINOR_PUB_HIGH_BIT  0x00000

#define HSDP_DEV_NAME "axi_user" //SUBDEV_SUFFIX

struct xocl_axi {
    const struct hsdp_pcie_config *config;
    void **__iomem bases;
    uint64_t *phys_addresses;
    unsigned int num_hubs;
    unsigned int instance;
    struct cdev sys_cdev;
    struct device *sys_device;
};

static dev_t axi_dev = 0;

//#define __REG_DEBUG__
#ifdef __REG_DEBUG__
/* SECTION: Function definitions */
static inline void __write_register(const char *fn, u32 value, void *base, unsigned int off)
{
    pr_info("%s: 0x%p, W reg 0x%x, 0x%x.\n", fn, base, off, value);
    iowrite32(value, base + off);
}

static inline u32 __read_register(const char *fn, void *base, unsigned int off)
{
    u32 v = ioread32(base + off);

    pr_info("%s: 0x%p, R reg 0x%x, 0x%x.\n", fn, base, off, v);
    return v;
}
#define write_register(v,base,off) __write_register(__func__, v, base, off)
#define read_register(base,off) __read_register(__func__, base, off)

#else
#define write_register(v,base,off)  iowrite32(v, (base) + (off))
#define read_register(base,off)     ioread32((base) + (off))
#endif /* #ifdef __REG_DEBUG__ */

static long axi_info_ioctl_helper(struct xocl_axi *axi, void __user *arg)
{
    struct hsdp_axi_info info_obj;
    struct hsdp_axi_debug_hub *hubs = NULL;
    int rv = 0;

    rv = copy_from_user((void *)&info_obj, arg, sizeof(struct hsdp_axi_info));
    if (rv) {
        pr_info("copy_from_user hsdp_axi_info failed: %d.\n", rv);
        goto cleanup;
    }

    if (info_obj.num_hubs >= axi->num_hubs && info_obj.hubs) {
        unsigned i;
        size_t hubs_size = sizeof(*hubs)*axi->num_hubs;

        hubs = (struct hsdp_axi_debug_hub*) kmalloc(hubs_size, GFP_KERNEL);

        for(i = 0; i < axi->num_hubs; ++i) {
            hubs[i].axi_address = axi->config->u.user.hub_infos[i].axi_address;
            hubs[i].size = axi->config->u.user.hub_infos[i].size;
            hubs[i].phys_address = axi->phys_addresses[i];
        }

        rv = copy_to_user((void *)info_obj.hubs, hubs, hubs_size);
        if (rv) {
            pr_info("copy_to_user hsdp_axi_debug_hub failed: %d.\n", rv);
            goto cleanup;
        }
    }

    info_obj.num_hubs = axi->num_hubs;

    rv = copy_to_user(arg, (void *)&info_obj, sizeof(struct hsdp_axi_info));
    if (rv) {
        pr_info("copy_to_user hsdp_axi_info failed: %d.\n", rv);
        goto cleanup;
    }

cleanup:
    if (hubs) kfree(hubs);
    return rv;
}

static long axi_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct xocl_axi *axi = filp->private_data;
    long status = 0;

    switch (cmd)
    {
        case XDMA_IOC_AXI_INFO:
            status = axi_info_ioctl_helper(axi, (void __user *)arg);
            break;
        default:
            pr_info("axi_ioctl bad command 0x%X\n", cmd);
            status = -ENOIOCTLCMD;
            break;
    }

    return status;
}

static int char_open(struct inode *inode, struct file *file)
{
    struct xocl_axi *axi = NULL;

    /* pointer to containing structure of the character device inode */
    axi = container_of(inode->i_cdev, struct xocl_axi, sys_cdev);
    /* create a reference to our char device in the opened file */
    file->private_data = axi;

    pr_info("axi char_open %lX\n", (unsigned long) axi);

    return 0;
}

/*
 * Called when the device goes from used to unused.
 */
static int char_close(struct inode *inode, struct file *file)
{
    pr_info("axi char_close %lX\n", (unsigned long) file->private_data);
    return 0;
}

static int axi_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct xocl_axi *axi;
    size_t size = vma->vm_end - vma->vm_start;
    phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
    unsigned i;

    axi = (struct xocl_axi *) file->private_data;

    pr_info("axi mmap %lX\n", (unsigned long) axi);

    for (i = 0; i < axi->num_hubs; ++i) {
        if (offset >= axi->phys_addresses[i] &&
            offset + size <= axi->phys_addresses[i] + axi->config->u.user.hub_infos[i].size) {
            break;
        }
    }

    if (i >= axi->num_hubs)
        return -EINVAL;

    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    /* Remap-pfn-range will mark the range VM_IO */
    if (remap_pfn_range(vma,
                vma->vm_start,
                vma->vm_pgoff,
                size,
                vma->vm_page_prot)) {
        return -EAGAIN;
    }

    return 0;
}

static ssize_t axi_read(struct file *file, char *buf, size_t size, loff_t *addr)
{
    uint32_t tmp_buf[128];
    struct xocl_axi *axi;
    uint64_t offset = 0;
    size_t nread = 0;
    int i;

    axi = (struct xocl_axi *) file->private_data;

    for (i = 0; i < axi->num_hubs; ++i) {
        const struct debug_hub_info *hub = axi->config->u.user.hub_infos + i;
        if (*addr >= hub->axi_address && *addr + size <= hub->axi_address + hub->size) {
            offset = *addr - hub->axi_address;
            break;
        }
    }

    if (i >= axi->num_hubs || !axi->bases[i]) {
        pr_info("\tinvalid arg addr 0x%llX, i %d, num_hubs %u\n", (unsigned long long) *addr, i, (unsigned) axi->num_hubs);
        return -EINVAL;
    }

    //pr_info("axi_read size %lu, addr 0x%08llx\n", (unsigned long) size, (unsigned long long) *addr);

    while (nread < size) {
        int rv;
        int j;
        int chunk_size = MIN(sizeof(tmp_buf), size - nread);

        for (j = 0; j < chunk_size; j += sizeof(uint32_t)) {
            tmp_buf[j>>2] = ioread32(axi->bases[i] + offset + j);
        }

        rv = copy_to_user((void *)(buf + nread), (void *) tmp_buf, chunk_size);
        if (rv) {
            pr_info("copy_to_user from AXI read failed: %d.\n", rv);
            break;
        }
        offset += chunk_size;
        nread += chunk_size;
    }

    return nread;
}

static ssize_t axi_write(struct file *file, const char *buf, size_t size, loff_t *addr)
{
    uint32_t tmp_buf[128];
    struct xocl_axi *axi;
    uint64_t offset = 0;
    size_t nread = 0;
    int i;

    size = MIN(size, sizeof(tmp_buf));

    axi = (struct xocl_axi *) file->private_data;

    //pr_info("axi_write size %lu, addr 0x%08llx\n", (unsigned long) size, (unsigned long long) *addr);

    for (i = 0; i < axi->num_hubs; ++i) {
        const struct debug_hub_info *hub = axi->config->u.user.hub_infos + i;
        if (*addr >= hub->axi_address && *addr + size <= hub->axi_address + hub->size) {
            offset = *addr - hub->axi_address;
            break;
        }
    }

    if (i >= axi->num_hubs || !axi->bases[i]) {
        return -EINVAL;
    }

    while (nread < size) {
        int rv;
        int j;
        int chunk_size = MIN(sizeof(tmp_buf), size - nread);

        rv = copy_from_user((void *) tmp_buf, (void *)(buf + nread), chunk_size);
        if (rv) {
            pr_info("copy_to_user from AXI read failed: %d.\n", rv);
            break;
        }

        for (j = 0; j < chunk_size; j += sizeof(uint32_t)) {
            iowrite32(tmp_buf[j>>2], axi->bases[i] + offset + j);
        }
        offset += chunk_size;
        nread += chunk_size;
    }

    return nread;
}

/*
 * character device file operations 
 */
static const struct file_operations axi_fops = {
    .owner = THIS_MODULE,
    .open = char_open,
    .release = char_close,
    .unlocked_ioctl = axi_ioctl,
    .mmap = axi_mmap,
    .read = axi_read,
    .write = axi_write
};


static int axi_probe(struct platform_device *pdev)
{
    struct xocl_axi *axi;
    struct resource *res;
    struct xocl_dev_core *core;
    const struct debug_hub_info *hub;
    unsigned i = 0;
    unsigned num_hubs = 0;
    int err;

    pr_info("axi_probe %d %s\n", pdev->id, pdev->name);

    core = xocl_get_xdev(pdev);

    axi = platform_get_drvdata(pdev);
    if (!axi) {
        xocl_err(&pdev->dev, "driver data is NULL");
        return -EINVAL;
    }

    for (hub = axi->config->u.user.hub_infos; hub->axi_address; ++hub) ++num_hubs;

    axi->bases = devm_kzalloc(&pdev->dev, sizeof(*axi->bases) * num_hubs, GFP_KERNEL);
    if (!axi->bases)
        return -ENOMEM;

    axi->phys_addresses = devm_kzalloc(&pdev->dev, sizeof(*axi->phys_addresses) * num_hubs, GFP_KERNEL);
    if (!axi->phys_addresses)
        return -ENOMEM;

    for (i = 0; i < num_hubs; ++i) {
        hub = axi->config->u.user.hub_infos + i;
        res = platform_get_resource(pdev, IORESOURCE_MEM, i);

        if (!res) {
            err = -EINVAL;
            goto failed;
        }

        // pr_info("res 0x%08llx, size 0x%08llx",
        //     (unsigned long long) res->start, (unsigned long long) res->end - res->start + 1);

        // // Skip remapping the resources. They are only used when mmapping.
        axi->bases[i] = ioremap(res->start, res->end - res->start + 1);
        //pr_info("mapped %p\n", axi->bases[i]);
        if (!axi->bases[i]) {
            err = -EIO;
            xocl_err(&pdev->dev, "Map iomem failed");
            goto failed;
        }

        axi->phys_addresses[i] = res->start;
        axi->num_hubs++;
    }

    cdev_init(&axi->sys_cdev, &axi_fops);
    axi->sys_cdev.owner = THIS_MODULE;
    axi->instance = XOCL_DEV_ID(core->pdev) |
        platform_get_device_id(pdev)->driver_data;
    axi->sys_cdev.dev = MKDEV(MAJOR(axi_dev), core->dev_minor);
    err = cdev_add(&axi->sys_cdev, axi->sys_cdev.dev, 1);
    if (err) {
        xocl_err(&pdev->dev, "cdev_add failed, %d",err);
        return err;
    }

    if (axi->config->name && axi->config->name[0]) {
        axi->sys_device = device_create(xrt_class, &pdev->dev,
                        axi->sys_cdev.dev,
                        NULL, "%s_%s_%s",
                        platform_get_device_id(pdev)->name,
                        core->pdev_name,
                        axi->config->name);
    } else {
        axi->sys_device = device_create(xrt_class, &pdev->dev,
                        axi->sys_cdev.dev,
                        NULL, "%s_%s",
                        platform_get_device_id(pdev)->name,
                        core->pdev_name);
    }
    if (IS_ERR(axi->sys_device)) {
        err = PTR_ERR(axi->sys_device);
        cdev_del(&axi->sys_cdev);
        goto failed;
    }

    platform_set_drvdata(pdev, axi);
    xocl_info(&pdev->dev, "HSDP device instance %s initialized\n",
        axi->config->name);

    return 0;

failed:
    while (axi->num_hubs) {
        iounmap(axi->bases[--axi->num_hubs]);
    }
    return err;
}

static int axi_remove(struct platform_device *pdev)
{
    struct xocl_axi *axi;

    pr_info("axi_remove %d %s\n", pdev->id, pdev->name);

    axi = platform_get_drvdata(pdev);
    if (!axi) {
        xocl_err(&pdev->dev, "driver data is NULL");
        return -EINVAL;
    }

    while (axi->num_hubs) {
        if (axi->bases[--axi->num_hubs])
            iounmap(axi->bases[axi->num_hubs]);
    }

    device_destroy(xrt_class, axi->sys_cdev.dev);
    cdev_del(&axi->sys_cdev);

    platform_set_drvdata(pdev, NULL);
    kfree(axi);

    return 0;
}

int xocl_set_config_hsdp_user(struct platform_device *pdev, const struct hsdp_pcie_config *config)
{
    struct xocl_axi *axi;

    axi = kzalloc(sizeof(*axi), GFP_KERNEL);
    if (!axi)
        return -ENOMEM;

    axi->config = config;

    platform_set_drvdata(pdev, axi);

    return 0;
}

struct platform_device_id axi_id_table[] = {
    { XOCL_HSDP_SIM, MINOR_PUB_HIGH_BIT },
    { XOCL_HSDP_PUB, MINOR_PUB_HIGH_BIT },
    { },
};

static struct platform_driver axi_driver = {
    .probe      = axi_probe,
    .remove     = axi_remove,
    .driver     = {
        .name = HSDP_DEV_NAME,
    },
    .id_table = axi_id_table,
};

int __init xocl_init_hsdp_user(void)
{
    int err = 0;

    // Register the character packet device major and minor numbers
    err = alloc_chrdev_region(&axi_dev, 0, XOCL_MAX_DEVICES, HSDP_DEV_NAME);
    if (err != 0) goto err_register_chrdev;

    err = platform_driver_register(&axi_driver);
    if (err) {
        goto err_driver_reg;
    }

    pr_info("xocl_init_axi_user %s\n", XOCL_HSDP_PUB);

    return 0;

err_driver_reg:
    unregister_chrdev_region(axi_dev, XOCL_MAX_DEVICES);
err_register_chrdev:
    return err;
}

void xocl_fini_hsdp_user(void) {
    pr_info("xocl_fini_axi_user\n");
    if (axi_dev) {
        unregister_chrdev_region(axi_dev, XOCL_MAX_DEVICES);
        axi_dev = 0;
    }
    platform_driver_unregister(&axi_driver);
}
