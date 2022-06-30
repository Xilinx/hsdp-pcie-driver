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
#include <linux/dma-mapping.h>

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

struct hsdp_packet {
    uint8_t  opcode;  // 'e' egress, 'i' ingress
    uint32_t word_count;
    uint8_t *buf;
};

#define XIL_HSDP_MAGIC 0x485344//50  // "HSDP"
#define XDMA_IOC_HSDP_OP _IOWR(XIL_HSDP_MAGIC, 0, struct hsdp_packet)

#define MINOR_PUB_HIGH_BIT  0x00000
#define MINOR_PRI_HIGH_BIT  0x10000
#define MINOR_NAME_MASK     0xffffffff

#define DMA_BUFFER_SIZE        16 * 1024
#define DPC_PACKET_SIZE        1032
#define DPC_PACKET_BUFFER_SIZE 2 * 1024

#define DMA_EGRESS_OFFSET  0x000
#define DMA_INGRESS_OFFSET 0x100
#define DMA_DESC_SIZE      0x10
#define DMA_DESC_COUNT     0x4
#define DMA_REG_ADDR_LO    0x0
#define DMA_REG_ADDR_HI    0x4
#define DMA_REG_CONTROL    0x8
#define DMA_REG_STATUS     0xC
#define DMA_CONTROL        0x40

#define CPM5_ADDR_LO     0x0
#define CPM5_ADDR_HI     0x4
#define CPM5_ADDR_PASID  0x8
#define CPM5_ADDR_FUNC   0xC
#define CPM5_ADDR_WINDOW 0x10
#define CPM5_ADDR_SMID   0x14

#define HSDP_DEV_NAME "hsdp_mgmt" //SUBDEV_SUFFIX

struct xocl_hsdp {
    const struct hsdp_pcie_config *config;
    void *__iomem base;
    void *__iomem ctl_base;
    unsigned int instance;
    struct cdev sys_cdev;
    struct device *sys_device;
    void *__iomem dma_base;
    void *__iomem dma_buffer;
    dma_addr_t dma_handle;
    uint64_t axi_slave_bridge_base;
    int last_ingress;
    int last_egress;
    int seq;
};

static dev_t hsdp_dev = 0;

//#define __REG_DEBUG__
//#define __DPC_DEBUG__
//#define __RUN_TESTS__


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

#define hsdp_write_egress(value, dma_base, index, reg) write_register(value, dma_base, DMA_EGRESS_OFFSET + (index * DMA_DESC_SIZE) + reg)
#define hsdp_write_ingress(value, dma_base, index, reg) write_register(value, dma_base, DMA_INGRESS_OFFSET + (index * DMA_DESC_SIZE) + reg)
#define hsdp_read_egress(dma_base, index, reg) read_register(dma_base, DMA_EGRESS_OFFSET + (index * DMA_DESC_SIZE) + reg)
#define hsdp_read_ingress(dma_base, index, reg) read_register(dma_base, DMA_INGRESS_OFFSET + (index * DMA_DESC_SIZE) + reg)

#define hsdp_setup_egress(dma_base, index) hsdp_write_egress(0x80000000, dma_base, index, DMA_REG_CONTROL)
#define hsdp_egress_status(dma_base, index) hsdp_read_egress(dma_base, index, DMA_REG_STATUS)
#define hsdp_run_ingress(size, dma_base, index) hsdp_write_ingress(0x80000000 + size - 1, dma_base, index, DMA_REG_CONTROL)
#define hsdp_ingress_status(dma_base, index) hsdp_read_ingress(dma_base, index, DMA_REG_STATUS)

#define ingress_buffer_offset(index) ((index + DMA_DESC_COUNT) * DPC_PACKET_BUFFER_SIZE)
#define egress_buffer_offset(index) (index * DPC_PACKET_BUFFER_SIZE)

#define ingress_buffer(hsdp, index) ((uint8_t *) hsdp->dma_buffer + ingress_buffer_offset(index))
#define egress_buffer(hsdp, index) ((uint8_t *) hsdp->dma_buffer + egress_buffer_offset(index))

#define next_desc_index(index) (index < DMA_DESC_COUNT - 1 ? index + 1 : 0)

static int hsdp_setup_dma(struct xocl_hsdp *hsdp) {
    int i;

    for (i = 0; i < DMA_DESC_COUNT; ++i) {
        hsdp_write_egress(0x40000000, hsdp->dma_base, i, DMA_REG_CONTROL);
        hsdp_write_egress((hsdp->axi_slave_bridge_base & 0xFFFFFFFF) + egress_buffer_offset(i), hsdp->dma_base, i, DMA_REG_ADDR_LO);
        hsdp_write_egress(hsdp->axi_slave_bridge_base >> 32, hsdp->dma_base, i, DMA_REG_ADDR_HI);
    }

    for (i = 0; i < DMA_DESC_COUNT; ++i) {
        hsdp_ingress_status(hsdp->dma_base, i);
        hsdp_write_ingress(0x40000000, hsdp->dma_base, i, DMA_REG_CONTROL);
        hsdp_ingress_status(hsdp->dma_base, i);
        hsdp_write_ingress((hsdp->axi_slave_bridge_base & 0xFFFFFFFF) + ingress_buffer_offset(i), hsdp->dma_base, i, DMA_REG_ADDR_LO);
        hsdp_write_ingress(hsdp->axi_slave_bridge_base >> 32, hsdp->dma_base, i, DMA_REG_ADDR_HI);
        hsdp_ingress_status(hsdp->dma_base, i);
    }

    hsdp_setup_egress(hsdp->dma_base, 0);
    hsdp_setup_egress(hsdp->dma_base, 1);
    hsdp_setup_egress(hsdp->dma_base, 2);
    hsdp_setup_egress(hsdp->dma_base, 3);

    hsdp->last_ingress = DMA_DESC_COUNT;
    hsdp->last_egress = DMA_DESC_COUNT;

    return 0;
}

#ifdef __DPC_DEBUG__
static void dump_dma(struct xocl_hsdp *hsdp) {
    int i;

    pr_info("DMA regs\n");
    for (i = 0; i < DMA_DESC_COUNT; ++i) {
        pr_info("\tegress reg control 0x%08X\n", hsdp_read_egress(hsdp->dma_base, i, DMA_REG_CONTROL));
        pr_info("\tegress reg addr lo 0x%08X\n", hsdp_read_egress(hsdp->dma_base, i, DMA_REG_ADDR_LO));
        pr_info("\tegress reg addr hi 0x%08X\n", hsdp_read_egress(hsdp->dma_base, i, DMA_REG_ADDR_HI));
        pr_info("\tegress reg status  0x%08X\n", hsdp_egress_status(hsdp->dma_base, i));
    }

    for (i = 0; i < DMA_DESC_COUNT; ++i) {
        pr_info("\tingress reg control 0x%08X\n", hsdp_read_ingress(hsdp->dma_base, i, DMA_REG_CONTROL));
        pr_info("\tingress reg addr lo 0x%08X\n", hsdp_read_ingress(hsdp->dma_base, i, DMA_REG_ADDR_LO));
        pr_info("\tingress reg addr hi 0x%08X\n", hsdp_read_ingress(hsdp->dma_base, i, DMA_REG_ADDR_HI));
        pr_info("\tingress reg status  0x%08X\n", hsdp_ingress_status(hsdp->dma_base, i));
    }
}

static void dump_cpm5(struct xocl_hsdp *hsdp, uint64_t offset) {
    pr_info("CPM5 regs (offset 0x%08llX:\n", (unsigned long long) offset);
    pr_info("\taddr lo     0x%08X\n", read_register(hsdp->ctl_base, offset + CPM5_ADDR_LO));
    pr_info("\taddr hi     0x%08X\n", read_register(hsdp->ctl_base, offset + CPM5_ADDR_HI));
    pr_info("\taddr pasid  0x%08X\n", read_register(hsdp->ctl_base, offset + CPM5_ADDR_PASID));
    pr_info("\taddr func   0x%08X\n", read_register(hsdp->ctl_base, offset + CPM5_ADDR_FUNC));
    pr_info("\taddr window 0x%08X\n", read_register(hsdp->ctl_base, offset + CPM5_ADDR_WINDOW));
    pr_info("\taddr smid   0x%08X\n", read_register(hsdp->ctl_base, offset + CPM5_ADDR_SMID));
}
#endif

static int hsdp_run_packet(struct xocl_hsdp *hsdp, struct hsdp_packet *packet, int user) {
    size_t size = packet->word_count;
    u32 status;
    int rv = 0;
    int ii;
    int i;

    // find available ingress
    ii = next_desc_index(hsdp->last_ingress);
    for (i = 0; i < DMA_DESC_COUNT; ++i) {
        status = hsdp_ingress_status(hsdp->dma_base, ii);
        if ((status & 4) == 0) break; // not in progress
        ii = next_desc_index(ii);
    }

    if (i >= DMA_DESC_COUNT) {
        pr_info("No available ingress descriptors");
        return -EBUSY;
    }

    if (user) {
        rv = copy_from_user(hsdp->dma_buffer + ingress_buffer_offset(ii), packet->buf, size * 4);
        if (rv) {
            pr_info("copy_from_user packet failed: %d.\n", rv);
            goto cleanup;
        }
    } else {
        memcpy(hsdp->dma_buffer + ingress_buffer_offset(ii), packet->buf, size * 4);
    }

#ifdef __DPC_DEBUG__
    pr_info("DPC packet (%u):\n", (unsigned) size);
    for (i = 0; i < size; ++i) {
        pr_info("\t0x%08X\n", ((u32 *) (hsdp->dma_buffer + ingress_buffer_offset(ii)))[i]);
    }
#endif

    hsdp_run_ingress(size, hsdp->dma_base, ii);
    hsdp->last_ingress = ii;

cleanup:
    return rv;
}

static int hsdp_get_packet(struct xocl_hsdp *hsdp, struct hsdp_packet *packet, int user) {
    u32 status;
    size_t size;
    int rv = 0;
    int ie;

#ifdef __DPC_DEBUG__
    int i;
#endif

    // check egress done
    ie = next_desc_index(hsdp->last_egress);
    status = hsdp_egress_status(hsdp->dma_base, ie);

    if (status & 2) {  // error
        pr_info("Egress status error 0x%08X", status);
        hsdp_setup_egress(hsdp->dma_base, ie);
        hsdp->last_egress = ie;
    }

    if ((status & 3) == 1) {
        size = ((status >> 8) & 0x1FF) + 1;

#ifdef __DPC_DEBUG__
        pr_info("DPC response packet (%u):\n", (unsigned) size);
        for (i = 0; i < size; ++i) {
            pr_info("\t0x%08X\n", ((u32 *) (hsdp->dma_buffer + egress_buffer_offset(ie)))[i]);
        }
#endif

        if (packet && user) {
            rv = copy_to_user(packet->buf, hsdp->dma_buffer + egress_buffer_offset(ie), size * 4);
            if (rv) {
                pr_info("copy_to_user packet buffer failed: %d.\n", rv);
                goto cleanup;
            }
            packet->word_count = size;
        }

        // resetup the egress desc
        hsdp_setup_egress(hsdp->dma_base, ie);
        hsdp->last_egress = ie;
    } else if (packet) {
        packet->word_count = 0;
    }

cleanup:
    return rv;
}

#ifdef __RUN_TESTS__
static int hsdp_run_fast_packet(struct xocl_hsdp *hsdp, int buf_index, size_t size) {
    u32 status;
    int ii;
    int i;
    u64 address = hsdp->axi_slave_bridge_base + ingress_buffer_offset(buf_index);

    // find available ingress
    ii = next_desc_index(hsdp->last_ingress);
    for (i = 0; i < DMA_DESC_COUNT; ++i) {
        status = hsdp_ingress_status(hsdp->dma_base, ii);
        if ((status & 4) == 0) break; // not in progress
        ii = next_desc_index(ii);
    }

    if (i >= DMA_DESC_COUNT) {
        pr_info("No available ingress descriptors");
        return -EBUSY;
    }

    ingress_buffer(hsdp, buf_index)[1] = hsdp->seq++;

    hsdp_write_ingress(address & 0xFFFFFFFF, hsdp->dma_base, ii, DMA_REG_ADDR_LO);

#ifdef __DPC_DEBUG__
    pr_info("DPC packet (%u):\n", (unsigned) size);
    for (i = 0; i < size; ++i) {
        pr_info("\t0x%08X\n", ((u32 *) ingress_buffer(hsdp, buf_index))[i]);
    }
#endif

    hsdp_run_ingress(size, hsdp->dma_base, ii);
    hsdp->last_ingress = ii;

    return 0;
}

static int hsdp_poll_fast_packet(struct xocl_hsdp *hsdp, uint32_t **buf, size_t *size, int *index) {
    size_t word_count;
    u32 status;
    int ie;
#ifdef __DPC_DEBUG__
    int i;
#endif

    // find a done egress
    ie = next_desc_index(hsdp->last_egress);
    status = hsdp_egress_status(hsdp->dma_base, ie);
    if (status & 2) {  // error
        pr_info("DPC Egress error on desc %d\n", ie);
        hsdp_setup_egress(hsdp->dma_base, ie);
        hsdp->last_egress = ie;
        return 0;
    }

    if (status & 1) {
        word_count = ((status >> 8) & 0xFF) + 1;

#ifdef __DPC_DEBUG__
        pr_info("DPC response packet (%u):\n", (unsigned) word_count);
        for (i = 0; i < word_count; ++i) {
            pr_info("\t0x%08X\n", ((u32 *) (hsdp->dma_buffer + egress_buffer_offset(ie)))[i]);
        }
#endif

        if (buf) {
            *buf = (uint32_t *) egress_buffer(hsdp, ie);
        }

        if (size) {
            *size = word_count;
        }

        if (index) {
            *index = ie;
        } else {
            hsdp_setup_egress(hsdp->dma_base, ie);
        }
        hsdp->last_egress = ie;
    } else if (size) {
        *size = 0;
    }

    return 0;
}

static int hsdp_get_fast_packet(struct xocl_hsdp *hsdp, uint32_t **buf, size_t *size, int *index) {
    int max_polls = 20;

    do {
        hsdp_poll_fast_packet(hsdp, buf, size, index);
        --max_polls;
    } while (max_polls > 0 && *size == 0);

    if (max_polls == 0) {
        pr_info("DPC packet timeout %d\n", hsdp->last_egress);
    }

    return max_polls == 0;
}

static void hsdp_run_enumerate(struct xocl_hsdp *hsdp) {
    u32 packet_buf[] = {
        0x00000001,
        0x99F8B879
    };
    u32 * result_buf;
    size_t word_count;

    hsdp->seq = 0;

    memcpy(ingress_buffer(hsdp, 0), packet_buf, sizeof(packet_buf));

    hsdp_run_fast_packet(hsdp, 0, sizeof(packet_buf) / 4);

    hsdp_get_fast_packet(hsdp, &result_buf, &word_count, NULL);

    hsdp->seq = 1;
}

static void hsdp_run_setconfig(struct xocl_hsdp *hsdp) {
    u32 packet_buf[] = {
        0x00010104,
        0x80000001,
        0x00001280,
        0xD92838C7
    };

    u32 * result_buf;
    size_t word_count;

    memcpy(ingress_buffer(hsdp, 0), packet_buf, sizeof(packet_buf));

    hsdp_run_fast_packet(hsdp, 0, sizeof(packet_buf) / 4);

    hsdp_get_fast_packet(hsdp, &result_buf, &word_count, NULL);
}

static void hsdp_run_getseq(struct xocl_hsdp *hsdp) {
    u32 packet_buf[] = {
        0x00010003,
        0x00000000
    };
    u32 * result_buf;
    size_t word_count;
    int egress_index;

    hsdp->seq = 0;

    memcpy(ingress_buffer(hsdp, 0), packet_buf, sizeof(packet_buf));

    hsdp_run_fast_packet(hsdp, 0, sizeof(packet_buf) / 4);

    hsdp_get_fast_packet(hsdp, &result_buf, &word_count, &egress_index);

    if (word_count) {
        hsdp->seq = (result_buf[0] >> 8) & 0xFF;
        pr_info("DPC seq 0x%02X\n", hsdp->seq);
    }

    hsdp_setup_egress(hsdp->dma_base, egress_index);
}

static void hsdp_run_mwr_test(struct xocl_hsdp *hsdp) {
    u32 packet_buf[] = {
        0x00010120,
        0x0000fffc,
        0x00000000,
        0x22110000,
        0x12153524,
        0xc0895e81,
        0x8484d609,
        0xb1f05663,
        0x06b97b0d,
        0x46df998d,
        0xb2c28465,
        0x89375212,
        0x00f3e301,
        0x06d7cd0d,
        0x3b23f176,
        0x1e8dcd3d,
        0x76d457ed,
        0x462df78c,
        0x7cfde9f9,
        0xe33724c6,
        0xe2f784c5,
        0xd513d2aa,
        0x12110000,
        0x057bee1e
    };
    u32 * result_buf;
    size_t word_count;
    int i = 0, e = 0;
    int total_runs = 1000;

    memcpy(ingress_buffer(hsdp, 0), packet_buf, sizeof(packet_buf));
    memcpy(ingress_buffer(hsdp, 1), packet_buf, sizeof(packet_buf));
    memcpy(ingress_buffer(hsdp, 2), packet_buf, sizeof(packet_buf));
    memcpy(ingress_buffer(hsdp, 3), packet_buf, sizeof(packet_buf));

    pr_info("Start test\n");
    for (e = 0; e < total_runs; ++e) {
        while (i < total_runs && i - e < DMA_DESC_COUNT) {
            hsdp_run_fast_packet(hsdp, i % 4, sizeof(packet_buf) / 4);
            ++i;
        }

        hsdp_get_fast_packet(hsdp, &result_buf, &word_count, NULL);
    }
    pr_info("End test. %d total runs\n", total_runs);
}
#endif

static long hsdp_packet_ioctl_helper(struct xocl_hsdp *hsdp, void __user *arg)
{
    struct hsdp_packet packet_obj;
    char opcode;
    uint32_t word_count;
    int rv;

    //pr_info("hsdp_packet_ioctl_helper\n");

    rv = copy_from_user((void *)&packet_obj, arg, sizeof(struct hsdp_packet));
    if (rv) {
        pr_info("copy_from_user packet_obj failed: %d.\n", rv);
        goto cleanup;
    }

    opcode = packet_obj.opcode;
    word_count = packet_obj.word_count;

    //pr_info("\topcode '%c', word_count 0x%X\n", opcode, word_count);

    if (word_count * 4 > DPC_PACKET_SIZE) {
        pr_info("HSDP Packet IOCTL Invalid word_count\n");
        return -EINVAL;
    }

    switch (opcode) {
    case 'e':
    {
        rv = hsdp_get_packet(hsdp, &packet_obj, 1);
        if (rv) goto cleanup;
        if (packet_obj.word_count) {
            rv = copy_to_user(arg, (void *)&packet_obj, sizeof(struct hsdp_packet));
            if (rv) {
                pr_info("copy_to_user packet_obj failed: %d.\n", rv);
                goto cleanup;
            }
        }
        break;
    }
    case 'i':
    {
        rv = hsdp_run_packet(hsdp, &packet_obj, 1);
        break;
    }
    default:
        pr_info("HSDP Packet IOCTL Invalid opcode\n");
        return -EINVAL;
    }

cleanup:
    return rv;
}

static long hsdp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct xocl_hsdp *hsdp = filp->private_data;
    long status = 0;

    //pr_info("hsdp_ioctl %lX, cmd 0x%X\n", (unsigned long) hsdp, cmd);

    switch (cmd)
    {
        case XDMA_IOC_HSDP_OP:
            status = hsdp_packet_ioctl_helper(hsdp, (void __user *)arg);
            break;
        default:
            pr_info("bad command 0x%X\n", cmd);
            status = -ENOIOCTLCMD;
            break;
    }

    return status;
}

static int char_open(struct inode *inode, struct file *file)
{
    struct xocl_hsdp *hsdp = NULL;

    /* pointer to containing structure of the character device inode */
    hsdp = container_of(inode->i_cdev, struct xocl_hsdp, sys_cdev);
    /* create a reference to our char device in the opened file */
    file->private_data = hsdp;

    pr_info("hsdp char_open %lX\n", (unsigned long) hsdp);

    return 0;
}

/*
 * Called when the device goes from used to unused.
 */
static int char_close(struct inode *inode, struct file *file)
{
    pr_info("hsdp char_close\n");
    return 0;
}

/*
 * character device file operations
 */
static const struct file_operations hsdp_fops = {
        .owner = THIS_MODULE,
        .open = char_open,
        .release = char_close,
        .unlocked_ioctl = hsdp_ioctl,
};

static int hsdp_probe(struct platform_device *pdev)
{
    const struct mgmt_bar_space_info *mgmt;
    struct xocl_hsdp *hsdp;
    struct resource *res;
    struct xocl_dev_core *core;
    uint64_t addr_trans_offset = 0;
    uint64_t mask;
    int err;

    pr_info("hsdp_probe %d %s\n", pdev->id, pdev->name);

    core = xocl_get_xdev(pdev);

    hsdp = platform_get_drvdata(pdev);
    if (!hsdp) {
        xocl_err(&pdev->dev, "driver data is NULL");
        return -EINVAL;
    }

    mgmt = &hsdp->config->u.mgmt;

    if (mgmt->type != MT_CPM4 && mgmt->type != MT_CPM5) {
        err = -EINVAL;
        xocl_err(&pdev->dev, "Invalid mgmt type %d", mgmt->type);
        goto failed;
    }

    // Check that bridge bar size is power of two
    if (!mgmt->bridge_bar_size || ((mgmt->bridge_bar_size & (mgmt->bridge_bar_size - 1)) != 0)) {
        err = -EINVAL;
        xocl_err(&pdev->dev, "Invalid bridge bar size 0x%llx", (unsigned long long) mgmt->bridge_bar_size);
        goto failed;
    }

    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    hsdp->base = ioremap(res->start, res->end - res->start + 1);
    hsdp->dma_base =  hsdp->base + mgmt->dma_bar_offset;
    if (!hsdp->base) {
        err = -EIO;
        xocl_err(&pdev->dev, "Map iomem failed");
        goto failed;
    }

    pr_info("HSDP DMA Base mapped at 0x%p from 0x%llx\n", hsdp->dma_base, (u64)res->start + mgmt->dma_bar_offset);

    res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
    hsdp->ctl_base = ioremap(res->start, res->end - res->start + 1);
    if (!hsdp->ctl_base) {
        err = -EIO;
        xocl_err(&pdev->dev, "Map iomem failed");
        goto failed;
    }

    pr_info("HSDP Ctl Base mapped at 0x%p from 0x%llx\n", hsdp->ctl_base, (u64)res->start);

    err = dma_set_mask_and_coherent(pdev->dev.parent, DMA_BIT_MASK(64));
    if (err) {
        pr_info("DMA could not set mask 0x%llX, err %d\n", DMA_BIT_MASK(64), err);
        err = 0;
    }

    hsdp->dma_buffer = dma_alloc_coherent(pdev->dev.parent, DMA_BUFFER_SIZE, &hsdp->dma_handle, GFP_KERNEL);

    pr_info("DMA Buffer pool mapped at 0x%p, 0x%llX\n",
        hsdp->dma_buffer, (unsigned long long) hsdp->dma_handle);

    mask = mgmt->bridge_bar_size - 1;

    if (mgmt->type == MT_CPM4) {
        addr_trans_offset = 0xEE0 + (mgmt->bridge_bar_index * 8) + mgmt->bridge_ctl_bar_offset;

        write_register((hsdp->dma_handle & ~mask) >> 32, hsdp->ctl_base, addr_trans_offset);
        write_register(hsdp->dma_handle & ~mask, hsdp->ctl_base, addr_trans_offset+4);

        hsdp->axi_slave_bridge_base = mgmt->bridge_bar_offset + (hsdp->dma_handle & mask);
    } else if (mgmt->type == MT_CPM5) {
        int i;
        uint32_t *words = (uint32_t *) hsdp->dma_buffer;
        words[0] = 0xCAFEC0DE;

        for (i = 1; i < 0x1000; i++) {
            words[i] = i;
        }

        addr_trans_offset = mgmt->bridge_ctl_bar_offset + 0x10000 + 0x2420 + (0x20 * mgmt->bridge_ctl_bar_table_entry);

        write_register(hsdp->dma_handle & ~mask, hsdp->ctl_base, addr_trans_offset + CPM5_ADDR_LO);
        write_register((hsdp->dma_handle & ~mask) >> 32, hsdp->ctl_base, addr_trans_offset + CPM5_ADDR_HI);
        write_register(0, hsdp->ctl_base, addr_trans_offset + CPM5_ADDR_PASID);
        write_register(0, hsdp->ctl_base, addr_trans_offset + CPM5_ADDR_FUNC);
        write_register(0xC8004000, hsdp->ctl_base, addr_trans_offset + CPM5_ADDR_WINDOW);
        write_register(0x249, hsdp->ctl_base, addr_trans_offset + CPM5_ADDR_SMID);

#ifdef __DPC_DEBUG__
        dump_cpm5(hsdp, addr_trans_offset);
#endif

        hsdp->axi_slave_bridge_base = mgmt->bridge_bar_offset + (hsdp->dma_handle & mask);
    }
    hsdp_setup_dma(hsdp);

#ifdef __DPC_DEBUG__
    dump_dma(hsdp);
#endif

    cdev_init(&hsdp->sys_cdev, &hsdp_fops);
    hsdp->sys_cdev.owner = THIS_MODULE;
    hsdp->sys_cdev.dev = MKDEV(MAJOR(hsdp_dev), core->dev_minor);
    err = cdev_add(&hsdp->sys_cdev, hsdp->sys_cdev.dev, 1);
    if (err) {
        xocl_err(&pdev->dev, "cdev_add failed, %d",err);
        goto failed;
    }

    hsdp->sys_device = device_create(xrt_class, &pdev->dev,
                    hsdp->sys_cdev.dev,
                    NULL, "%s_%s",
                    platform_get_device_id(pdev)->name,
                    core->pdev_name);
    if (IS_ERR(hsdp->sys_device)) {
        err = PTR_ERR(hsdp->sys_device);
        cdev_del(&hsdp->sys_cdev);
        goto failed;
    }

    xocl_info(&pdev->dev, "HSDP device instance %s_%s initialized\n",
        platform_get_device_id(pdev)->name, core->pdev_name);

#ifdef __REG_DEBUG__
    if (mgmt->type == MT_CPM4) {
        read_register(hsdp->ctl_base, addr_trans_offset);
        read_register(hsdp->ctl_base, addr_trans_offset + 4);
        read_register(hsdp->ctl_base, mgmt->bridge_ctl_bar_offset);
    }
#endif

#ifdef __RUN_TESTS__
    hsdp_run_enumerate(hsdp);
    // hsdp_run_setconfig(hsdp);
    // hsdp_run_getseq(hsdp);
    // hsdp_run_mwr_test(hsdp);
    // hsdp_run_getseq(hsdp);
#endif

    return 0;

failed:
    if (hsdp->dma_buffer)
        dma_free_coherent(pdev->dev.parent, DMA_BUFFER_SIZE, hsdp->dma_buffer, hsdp->dma_handle);
    if (hsdp->ctl_base)
        iounmap(hsdp->ctl_base);
    if (hsdp->base)
        iounmap(hsdp->base);

    return err;
}

static int hsdp_remove(struct platform_device *pdev)
{
    struct xocl_hsdp *hsdp;

    pr_info("hsdp_remove %d %s\n", pdev->id, pdev->name);

    hsdp = platform_get_drvdata(pdev);
    if (!hsdp) {
        xocl_err(&pdev->dev, "driver data is NULL");
        return -EINVAL;
    }

    device_destroy(xrt_class, hsdp->sys_cdev.dev);
    cdev_del(&hsdp->sys_cdev);
    dma_free_coherent(pdev->dev.parent, DMA_BUFFER_SIZE, hsdp->dma_buffer, hsdp->dma_handle);
    if (hsdp->ctl_base)
        iounmap(hsdp->ctl_base);
    if (hsdp->base)
        iounmap(hsdp->base);

    platform_set_drvdata(pdev, NULL);
    kfree(hsdp);

    return 0;
}

int xocl_set_config_hsdp_mgmt(struct platform_device *pdev, const struct hsdp_pcie_config *config)
{
    struct xocl_hsdp *hsdp;

    hsdp = kzalloc(sizeof(*hsdp), GFP_KERNEL);
    if (!hsdp)
        return -ENOMEM;

    hsdp->config = config;

    platform_set_drvdata(pdev, hsdp);

    return 0;
}

struct platform_device_id hsdp_id_table[] = {
    { XOCL_HSDP_PRI, MINOR_PRI_HIGH_BIT },
    { },
};

static struct platform_driver hsdp_driver = {
    .probe      = hsdp_probe,
    .remove     = hsdp_remove,
    .driver     = {
        .name = HSDP_DEV_NAME,
    },
    .id_table = hsdp_id_table,
};

int __init xocl_init_hsdp_mgmt(void)
{
    int err = 0;

    // Register the character packet device major and minor numbers
    err = alloc_chrdev_region(&hsdp_dev, 0, XOCL_MAX_DEVICES, HSDP_DEV_NAME);
    if (err != 0) goto err_register_chrdev;

    err = platform_driver_register(&hsdp_driver);
    if (err) {
        goto err_driver_reg;
    }

    pr_info("xocl_init_hsdp_mgmt %s\n", XOCL_HSDP_PRI);

    return 0;

err_driver_reg:
    unregister_chrdev_region(hsdp_dev, XOCL_MAX_DEVICES);
err_register_chrdev:
    return err;
}

void xocl_fini_hsdp_mgmt(void)
{
    pr_info("xocl_fini_hsdp_mgmt\n");
    if (hsdp_dev) {
        unregister_chrdev_region(hsdp_dev, XOCL_MAX_DEVICES);
        hsdp_dev = 0;
    }
    platform_driver_unregister(&hsdp_driver);
}
