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

//#define __REG_DEBUG__
//#define __DPC_DEBUG__
//#define __RUN_TESTS__

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

#define DPC_PACKET_SIZE        1032
#define DPC_PACKET_BUFFER_SIZE 2 * 1024
#define DMA_DESC_COUNT 4
#define DMA_DESC_SIZE 0x40
#define DMA_DESC_OFFSET        0x440
#define DMA_BUFFER_SIZE        8 * DPC_PACKET_BUFFER_SIZE

#define INGRESS_BUFFER          0
#define EGRESS_BUFFER           INGRESS_BUFFER + DPC_PACKET_BUFFER_SIZE * DMA_DESC_COUNT
#define DMA_DESC_INGRESS        INGRESS_BUFFER + DMA_DESC_OFFSET
#define DMA_DESC_EGRESS         EGRESS_BUFFER + DMA_DESC_OFFSET

#define REG_DESC_NEXT     0x00
#define REG_DESC_NEXT_MSB 0x04
#define REG_DESC_BUFF     0x08
#define REG_DESC_BUFF_MSB 0x0C
#define REG_DESC_CNTL     0x18
#define REG_DESC_STS      0x1C
#define REG_DESC_APP0     0x20

#define REG_DMA_INGRESS_CNTL     0x00
#define REG_DMA_INGRESS_STS      0x04
#define REG_DMA_INGRESS_CUR      0x08
#define REG_DMA_INGRESS_CUR_MSB  0x0C
#define REG_DMA_INGRESS_TAIL     0x10
#define REG_DMA_INGRESS_TAIL_MSB 0x14

#define REG_DMA_INGRESS_CUR64    0x08
#define REG_DMA_INGRESS_TAIL64   0x10

#define REG_DMA_EGRESS_CNTL     0x30
#define REG_DMA_EGRESS_STS      0x34
#define REG_DMA_EGRESS_CUR      0x38
#define REG_DMA_EGRESS_CUR_MSB  0x3C
#define REG_DMA_EGRESS_TAIL     0x40
#define REG_DMA_EGRESS_TAIL_MSB 0x44
#define REG_DMA_EGRESS_CUR64    0x38
#define REG_DMA_EGRESS_TAIL64   0x40

#define AXI_INGRESS_DESC(index) (axi_slave_bridge_base + DMA_DESC_INGRESS + DPC_PACKET_BUFFER_SIZE * (index))
#define AXI_EGRESS_DESC(index) (axi_slave_bridge_base + DMA_DESC_EGRESS + DPC_PACKET_BUFFER_SIZE * (index))
#define AXI_INGRESS_PACKET(index) (axi_slave_bridge_base + INGRESS_BUFFER + DPC_PACKET_BUFFER_SIZE * (index))
#define AXI_EGRESS_PACKET(index) (axi_slave_bridge_base + EGRESS_BUFFER + DPC_PACKET_BUFFER_SIZE * (index))

#define BDF_ADDR_LO     0x2420
#define BDF_ADDR_HI     0x2424
#define BDF_PASID       0x2428
#define BDF_FUNC        0x242C
#define BDF_WINDOW      0x2430
#define BDF_SMID        0x2434
#define BDF_NEXT_OFFSET 0x20

#define HSDP_DEV_NAME "hsdp_mgmt_soft" //SUBDEV_SUFFIX

struct xocl_hsdp {
    const struct hsdp_pcie_config *config;
    void *__iomem base;
    unsigned int instance;
    struct cdev sys_cdev;
    struct device *sys_device;
    void *__iomem csr_base;
    void *__iomem dma_base;
    void *__iomem dma_buffer;
    dma_addr_t dma_handle;
    uint64_t axi_slave_bridge_base;
    int last_ingress;
    int last_egress;
    int seq;
};

static dev_t hsdp_dev = 0;

#ifdef __REG_DEBUG__
/* SECTION: Function definitions */
static inline void __write_register(const char *fn, u32 value, void *base, unsigned int off)
{
    pr_info("%s: 0x%p, W reg 0x%x, 0x%x\n", fn, base, off, value);
    iowrite32(value, base + off);
}

static inline u32 __read_register(const char *fn, void *base, unsigned int off)
{
    u32 v = ioread32(base + off);

    pr_info("%s: 0x%p, R reg 0x%x, 0x%x\n", fn, base, off, v);
    return v;
}
#define write_register(v,base,off) __write_register(__func__, v, base, off)
#define read_register(base,off) __read_register(__func__, base, off)

#else
#define write_register(v,base,off)  iowrite32(v, (base) + (off))
#define read_register(base,off)     ioread32((base) + (off))
#endif /* #ifdef __REG_DEBUG__ */

static inline void write_desc(u32 value, unsigned char * base, unsigned off) {
    *(uint32_t *) (base + off) = value;
}

static inline u32 read_desc(unsigned char * base, unsigned off) {
    return *(uint32_t *) (base + off);
}

#define write_desc_ingress(value, reg, index) write_desc((value), dma_buffer, DMA_DESC_INGRESS + DPC_PACKET_BUFFER_SIZE * index + reg)
#define read_desc_ingress(reg, index) read_desc(dma_buffer, DMA_DESC_INGRESS + DPC_PACKET_BUFFER_SIZE * index + reg)
#define write_desc_egress(value, reg, index) write_desc((value), dma_buffer, DMA_DESC_EGRESS + DPC_PACKET_BUFFER_SIZE * index + reg)
#define read_desc_egress(reg, index) read_desc(dma_buffer, DMA_DESC_EGRESS + DPC_PACKET_BUFFER_SIZE * index + reg)

#define write_dma_reg(value, reg) write_register((value), dma_base, reg)
#define read_dma_reg(reg) read_register(dma_base, reg)

#define hsdp_setup_egress(dma_base, index) hsdp_write_egress(0x80000000, dma_base, index, DMA_REG_CONTROL)
#define hsdp_egress_status(dma_base, index) hsdp_read_egress(dma_base, index, DMA_REG_STATUS)
#define hsdp_run_ingress(size, dma_base, index) hsdp_write_ingress(0x80000000 + size - 1, dma_base, index, DMA_REG_CONTROL)
#define hsdp_ingress_status(dma_base, index) hsdp_read_ingress(dma_base, index, DMA_REG_STATUS)

#define ingress_buffer_offset(index) (INGRESS_BUFFER + index * DPC_PACKET_BUFFER_SIZE)
#define egress_buffer_offset(index) (EGRESS_BUFFER + index * DPC_PACKET_BUFFER_SIZE)

#define ingress_buffer(hsdp, index) ((uint8_t *) hsdp->dma_buffer + ingress_buffer_offset(index))
#define egress_buffer(hsdp, index) ((uint8_t *) hsdp->dma_buffer + egress_buffer_offset(index))

#define next_desc_index(index) (index < DMA_DESC_COUNT - 1 ? index + 1 : 0)

static int hsdp_set_bdf(struct xocl_hsdp *hsdp, uint64_t addr) {
    void *__iomem csr_base = hsdp->csr_base;
    const struct mgmt_bar_space_info *mgmt = &hsdp->config->u.mgmt;
    uint64_t window_mask = mgmt->bridge_bar_size - 1;
    unsigned index = 0;
    const unsigned prot = 0b111;

    uint64_t addr_lo = (addr & ~window_mask) & 0xFFFFFFFF;
    uint64_t addr_hi = (addr - addr_lo) >> 32;
    uint64_t window = 0xC0000000 + (prot << 26) + (mgmt->bridge_bar_size / (1 << 12));

    pr_info("set_bdf mask 0x%08X, hi 0x%08X, lo 0x%08X\n", (unsigned) window_mask, (unsigned) addr_hi, (unsigned) addr_lo);

    write_register(addr_lo,  csr_base, BDF_ADDR_LO + BDF_NEXT_OFFSET * index);
    write_register(addr_hi,  csr_base, BDF_ADDR_HI + BDF_NEXT_OFFSET * index);
    write_register(0,        csr_base, BDF_PASID   + BDF_NEXT_OFFSET * index);
    write_register(0,        csr_base, BDF_FUNC    + BDF_NEXT_OFFSET * index);
    write_register(window,   csr_base, BDF_WINDOW  + BDF_NEXT_OFFSET * index);
    write_register(0,        csr_base, BDF_SMID    + BDF_NEXT_OFFSET * index);

    return 0;
}

static int hsdp_dump_bdf(struct xocl_hsdp *hsdp) {
    void *__iomem csr_base = hsdp->csr_base;
    unsigned index = 0;

    read_register(csr_base, BDF_ADDR_LO + BDF_NEXT_OFFSET * index);
    read_register(csr_base, BDF_ADDR_HI + BDF_NEXT_OFFSET * index);
    read_register(csr_base, BDF_PASID   + BDF_NEXT_OFFSET * index);
    read_register(csr_base, BDF_FUNC    + BDF_NEXT_OFFSET * index);
    read_register(csr_base, BDF_WINDOW  + BDF_NEXT_OFFSET * index);
    read_register(csr_base, BDF_SMID    + BDF_NEXT_OFFSET * index);

    return 0;
}

static int hsdp_setup_dma(struct xocl_hsdp *hsdp) {
    void *__iomem dma_base = hsdp->dma_base;
    void *__iomem dma_buffer = hsdp->dma_buffer;
    uint64_t axi_slave_bridge_base = hsdp->axi_slave_bridge_base;
    uint32_t status;
    int count = 10000;
    int i;

    hsdp->last_ingress = -1;
    hsdp->last_egress = -1;
    
    // reset
    write_dma_reg(0x00010004, REG_DMA_INGRESS_CNTL);
    write_dma_reg(0x00010004, REG_DMA_EGRESS_CNTL);
    while (count-- && (
        (read_dma_reg(REG_DMA_INGRESS_CNTL) & 4) ||
        (read_dma_reg(REG_DMA_EGRESS_CNTL) & 4)
    )) {}

    if (count <= 0) {
        pr_info("Failed to reset DMA");
        return -1;
    }

    // setup ingress
    for (i = 0; i < DMA_DESC_COUNT; ++i) {
        if (i < DMA_DESC_COUNT - 1) {
            write_desc_ingress(AXI_INGRESS_DESC(i + 1) & 0xFFFFFFFF, REG_DESC_NEXT, i);
            write_desc_ingress((AXI_INGRESS_DESC(i + 1) >> 32) & 0xFFFFFFFF, REG_DESC_NEXT_MSB, i);
        } else {
            write_desc_ingress(AXI_INGRESS_DESC(0) & 0xFFFFFFFF, REG_DESC_NEXT, i);
            write_desc_ingress((AXI_INGRESS_DESC(0) >> 32) & 0xFFFFFFFF, REG_DESC_NEXT_MSB, i);
        }
        write_desc_ingress(AXI_INGRESS_PACKET(i) & 0xFFFFFFFF, REG_DESC_BUFF, i);
        write_desc_ingress((AXI_INGRESS_PACKET(i) >> 32) & 0xFFFFFFFF, REG_DESC_BUFF_MSB, i);
        write_desc_ingress(0x80000000, REG_DESC_STS, i);
        write_desc_ingress(0, REG_DESC_CNTL, i);
    }
    write_dma_reg(AXI_INGRESS_DESC(0), REG_DMA_INGRESS_CUR);
    write_dma_reg((AXI_INGRESS_DESC(0) >> 32), REG_DMA_INGRESS_CUR_MSB);

    write_dma_reg(0x00014001, REG_DMA_INGRESS_CNTL);

    // setup egress
    for (i = 0; i < DMA_DESC_COUNT; ++i) {
        if (i < DMA_DESC_COUNT - 1) {
            write_desc_egress(AXI_EGRESS_DESC(i + 1) & 0xFFFFFFFF, REG_DESC_NEXT, i);
            write_desc_egress((AXI_EGRESS_DESC(i + 1) >> 32) & 0xFFFFFFFF, REG_DESC_NEXT_MSB, i);
        } else {
            write_desc_egress(AXI_EGRESS_DESC(0) & 0xFFFFFFFF, REG_DESC_NEXT, i);
            write_desc_egress((AXI_EGRESS_DESC(0) >> 32) & 0xFFFFFFFF, REG_DESC_NEXT_MSB, i);
        }
        write_desc_egress(AXI_EGRESS_PACKET(i) & 0xFFFFFFFF, REG_DESC_BUFF, i);
        write_desc_egress((AXI_EGRESS_PACKET(i) >> 32) & 0xFFFFFFFF, REG_DESC_BUFF_MSB, i);
        write_desc_egress(0x0C000000 | DPC_PACKET_SIZE, REG_DESC_CNTL, i);
        write_desc_egress(0, REG_DESC_STS, i);
        hsdp->last_egress++;
    }
    write_dma_reg(AXI_EGRESS_DESC(0), REG_DMA_EGRESS_CUR);
    write_dma_reg((AXI_EGRESS_DESC(0) >> 32), REG_DMA_EGRESS_CUR_MSB);

    write_dma_reg(0x00010001, REG_DMA_EGRESS_CNTL);

    while ((status = read_dma_reg(REG_DMA_EGRESS_STS)) & 1) {
        pr_info("Egress starting 0x%08X\n", status);
    }

    write_dma_reg(AXI_EGRESS_DESC(DMA_DESC_COUNT - 1), REG_DMA_EGRESS_TAIL);
    write_dma_reg((AXI_EGRESS_DESC(DMA_DESC_COUNT - 1) >> 32), REG_DMA_EGRESS_TAIL_MSB);

    return 0;
}

#ifdef __DPC_DEBUG__
static void dump_dma(struct xocl_hsdp *hsdp) {
    void *__iomem dma_base = hsdp->dma_base;
    pr_info("DMA regs\n");
    
#ifdef __REG_DEBUG__
    read_dma_reg(REG_DMA_INGRESS_CNTL);
    read_dma_reg(REG_DMA_INGRESS_STS);
    read_dma_reg(REG_DMA_INGRESS_CUR);
    read_dma_reg(REG_DMA_INGRESS_CUR_MSB);
    read_dma_reg(REG_DMA_INGRESS_TAIL);
    read_dma_reg(REG_DMA_INGRESS_TAIL_MSB);

    read_dma_reg(REG_DMA_EGRESS_CNTL);
    read_dma_reg(REG_DMA_EGRESS_STS);
    read_dma_reg(REG_DMA_EGRESS_CUR);
    read_dma_reg(REG_DMA_EGRESS_CUR_MSB);
    read_dma_reg(REG_DMA_EGRESS_TAIL);
    read_dma_reg(REG_DMA_EGRESS_TAIL_MSB);
#else
    pr_info("REG_DMA_INGRESS_CNTL     0x%08X\n", read_dma_reg(REG_DMA_INGRESS_CNTL));
    pr_info("REG_DMA_INGRESS_STS      0x%08X\n", read_dma_reg(REG_DMA_INGRESS_STS));
    pr_info("REG_DMA_INGRESS_CUR      0x%08X\n", read_dma_reg(REG_DMA_INGRESS_CUR));
    pr_info("REG_DMA_INGRESS_CUR_MSB  0x%08X\n", read_dma_reg(REG_DMA_INGRESS_CUR_MSB));
    pr_info("REG_DMA_INGRESS_TAIL     0x%08X\n", read_dma_reg(REG_DMA_INGRESS_TAIL));
    pr_info("REG_DMA_INGRESS_TAIL_MSB 0x%08X\n", read_dma_reg(REG_DMA_INGRESS_TAIL_MSB));

    pr_info("REG_DMA_EGRESS_CNTL      0x%08X\n", read_dma_reg(REG_DMA_EGRESS_CNTL));
    pr_info("REG_DMA_EGRESS_STS       0x%08X\n", read_dma_reg(REG_DMA_EGRESS_STS));
    pr_info("REG_DMA_EGRESS_CUR       0x%08X\n", read_dma_reg(REG_DMA_EGRESS_CUR));
    pr_info("REG_DMA_EGRESS_CUR_MSB   0x%08X\n", read_dma_reg(REG_DMA_EGRESS_CUR_MSB));
    pr_info("REG_DMA_EGRESS_TAIL      0x%08X\n", read_dma_reg(REG_DMA_EGRESS_TAIL));
    pr_info("REG_DMA_EGRESS_TAIL_MSB  0x%08X\n", read_dma_reg(REG_DMA_EGRESS_TAIL_MSB));
#endif
}

void hsdp_dump_desc(struct xocl_hsdp *hsdp, size_t index, int egress) {
    void *__iomem dma_buffer = hsdp->dma_buffer;
    uint64_t axi_slave_bridge_base = hsdp->axi_slave_bridge_base;
    size_t k;

    pr_info("%s desc %ld\n", egress ? "egress" : "ingres", (long) index);
    for (k = REG_DESC_NEXT; k <= REG_DESC_STS; k+=4) {
        if (egress)
            pr_info("\t0x%08lX: 0x%08X\n", (unsigned long) AXI_EGRESS_DESC(index) + k, read_desc_egress(k, index));
        else
            pr_info("\t0x%08lX: 0x%08X\n", (unsigned long) AXI_INGRESS_DESC(index) + k, read_desc_ingress(k, index));
    }
 }
#endif

static int hsdp_run_packet(struct xocl_hsdp *hsdp, struct hsdp_packet *packet, int user) {
    void *__iomem dma_base = hsdp->dma_base;
    void *__iomem dma_buffer = hsdp->dma_buffer;
    uint64_t axi_slave_bridge_base = hsdp->axi_slave_bridge_base;
    size_t size = packet->word_count;
    u32 status;
    int rv = 0;
    int ii;
    int i;
    int max_polls = 1000;

    // find available ingress
    ii = next_desc_index(hsdp->last_ingress);
    for (i = 0; i < max_polls; ++i) {
        status = read_desc_ingress(REG_DESC_STS, ii);
        if (status & 0x70000000) { // error
            pr_info("Ingress packet error status 0x%08X\n", status);
            break;
        } else if ((status >> 31) & 1) { // done
            break;
        }
    }

    if (i >= max_polls) {
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

    write_desc_ingress(0x0C000000 | (size * 4), REG_DESC_CNTL, ii);
    write_desc_ingress(0, REG_DESC_STS, ii);
        
    if (read_desc_ingress(REG_DESC_STS, ii) != 0) {
        pr_info("Reg status not reset: 0x%08X\n", read_desc_ingress(REG_DESC_STS, ii));
    }

    write_dma_reg(AXI_INGRESS_DESC(ii), REG_DMA_INGRESS_TAIL);
    write_dma_reg(AXI_INGRESS_DESC(ii) >> 32, REG_DMA_INGRESS_TAIL_MSB);
    hsdp->last_ingress = ii;

cleanup:
    return rv;
}

static int hsdp_get_packet(struct xocl_hsdp *hsdp, struct hsdp_packet *packet, int user) {
    void *__iomem dma_base = hsdp->dma_base;
    void *__iomem dma_buffer = hsdp->dma_buffer;
    uint64_t axi_slave_bridge_base = hsdp->axi_slave_bridge_base;
    u32 status;
    size_t size;
    int rv = 0;
    int ie;

#ifdef __DPC_DEBUG__
    int i;
#endif

    // check egress done
    ie = next_desc_index(hsdp->last_egress);
    status = read_desc_egress(REG_DESC_STS, ie);

    if (status & 0x70000000) { // error
        pr_info("Egress status error 0x%08X", status);
        write_desc_egress(0, REG_DESC_STS, ie);
        write_dma_reg(AXI_EGRESS_DESC(ie), REG_DMA_EGRESS_TAIL);
        write_dma_reg(AXI_EGRESS_DESC(ie) >> 32, REG_DMA_EGRESS_TAIL_MSB);
        hsdp->last_egress = ie;
    } else if ((status >> 31) & 1) { // done
        size = (status & 0x3FFFFFF);

#ifdef __DPC_DEBUG__
        pr_info("DPC response packet (%u):\n", (unsigned) size);
        for (i = 0; i < (size>>2); ++i) {
            pr_info("\t0x%08X\n", ((u32 *) (hsdp->dma_buffer + egress_buffer_offset(ie)))[i]);
        }
        hsdp_dump_desc(hsdp, ie, 1);
#endif

        // resetup the egress desc
        if (packet) {
            if (user) {
                rv = copy_to_user(packet->buf, hsdp->dma_buffer + egress_buffer_offset(ie), size);
                if (rv) {
                    pr_info("copy_to_user packet buffer failed: %d.\n", rv);
                    goto cleanup;
                }
            } else {
                packet->buf = hsdp->dma_buffer + egress_buffer_offset(ie);
            }
            packet->word_count = size >> 2;
        }

        // resetup the egress desc
        write_desc_egress(0, REG_DESC_STS, ie);

        write_dma_reg(AXI_EGRESS_DESC(ie), REG_DMA_EGRESS_TAIL);
        write_dma_reg((AXI_EGRESS_DESC(ie) >> 32), REG_DMA_EGRESS_TAIL_MSB);

        hsdp->last_egress = ie;
    } else if (packet) {
        packet->word_count = 0;
    }

cleanup:
    return rv;
}

#ifdef __RUN_TESTS__
static void hsdp_run_enumerate(struct xocl_hsdp *hsdp) {
    u32 packet_buf[] = {
        0x00000001,
        0x99F8B879
    };
    struct hsdp_packet ipkt = {
        'i',
        sizeof(packet_buf)/sizeof(u32),
        (uint8_t *)&packet_buf
    };
    struct hsdp_packet epkt;
    int count = 10000;

    hsdp->seq = 0;

    hsdp_run_packet(hsdp, &ipkt, 0);

    do {
        hsdp_get_packet(hsdp, &epkt, 0);
    } while (epkt.word_count == 0 && --count > 0);

    hsdp->seq = 1;
}

static void hsdp_run_setconfig(struct xocl_hsdp *hsdp) {
    u32 packet_buf[] = {
        0x00010104,
        0x80000001,
        0x00001280,
        0xD92838C7
    };
    struct hsdp_packet ipkt = {
        'i',
        sizeof(packet_buf)/sizeof(u32),
        (uint8_t *)&packet_buf
    };
    struct hsdp_packet epkt;
    int count = 10000;

    hsdp_run_packet(hsdp, &ipkt, 0);

    do {
        hsdp_get_packet(hsdp, &epkt, 0);
    } while (epkt.word_count == 0 && --count > 0);
}

static void hsdp_run_getseq(struct xocl_hsdp *hsdp) {
    u32 packet_buf[] = {
        0x00010003,
        0x2AEA41B3
    };
    struct hsdp_packet ipkt = {
        'i',
        sizeof(packet_buf)/sizeof(u32),
        (uint8_t *)&packet_buf
    };
    struct hsdp_packet epkt;
    int count = 10000;

    hsdp_run_packet(hsdp, &ipkt, 0);

    do {
        hsdp_get_packet(hsdp, &epkt, 0);
    } while (epkt.word_count == 0 && --count > 0);

    if (epkt.word_count) {
        hsdp->seq = epkt.buf[1];
        pr_info("DPC seq 0x%02X\n", hsdp->seq);
    }
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

static int hsdp_probe(struct platform_device *pdev) {
    const struct mgmt_bar_space_info *mgmt;
    struct xocl_hsdp *hsdp;
    struct resource *res;
    struct xocl_dev_core *core;
    uint64_t mask;
    int skip_tests = 0;
    int err;

    pr_info("hsdp_probe_soft %d %s\n", pdev->id, pdev->name);

    core = xocl_get_xdev(pdev);

    hsdp = platform_get_drvdata(pdev);
    if (!hsdp) {
        xocl_err(&pdev->dev, "driver data is NULL");
        return -EINVAL;
    }

    if (!hsdp->config) {
        err = -EINVAL;
        xocl_err(&pdev->dev, "NULL config");
        goto failed;
    }

    mgmt = &hsdp->config->u.mgmt;
    if (!mgmt) {
        err = -EINVAL;
        xocl_err(&pdev->dev, "NULL mgmt");
        goto failed;
    }

    if (mgmt->type != MT_SOFT) {
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
    if (!res) {
        err = -EINVAL;
        xocl_err(&pdev->dev, "Unable to access res 0");
        goto failed;
    }

    hsdp->base = ioremap(res->start, res->end - res->start + 1);
    if (!hsdp->base) {
        err = -EIO;
        xocl_err(&pdev->dev, "Map iomem failed");
        goto failed;
    }
    hsdp->dma_base =  hsdp->base + mgmt->dma_bar_offset;
    hsdp->csr_base =  hsdp->base + mgmt->bridge_ctl_bar_offset;

    pr_info("HSDP DMA Base mapped at 0x%p from 0x%llx\n", hsdp->dma_base, (u64)res->start + mgmt->dma_bar_offset);

    err = dma_set_mask_and_coherent(pdev->dev.parent, DMA_BIT_MASK(32));
    if (err) {
        pr_info("DMA could not set mask 0x%llX, err %d\n", DMA_BIT_MASK(32), err);
        err = 0;
    }

    hsdp->dma_buffer = dma_alloc_coherent(pdev->dev.parent, DMA_BUFFER_SIZE, &hsdp->dma_handle, GFP_KERNEL);

    pr_info("DMA Buffer pool mapped at 0x%p, 0x%llX\n",
        hsdp->dma_buffer, (unsigned long long) hsdp->dma_handle);

    mask = mgmt->bridge_bar_size - 1;
    hsdp->axi_slave_bridge_base = mgmt->bridge_bar_offset + (hsdp->dma_handle & mask);

    write_register(0xFFFFFFFF, hsdp->csr_base, 0xE10);
    read_register(hsdp->csr_base, 0xE10);

    //hsdp_set_bdf(hsdp, hsdp->dma_handle);
    if (hsdp_setup_dma(hsdp) < 0) {
        skip_tests = 1;
    }

#ifdef __DPC_DEBUG__
    dump_dma(hsdp);
    //hsdp_dump_desc(hsdp, 0, 1);
    //hsdp_dump_desc(hsdp, 1, 1);
    //hsdp_dump_bdf(hsdp);

    // qdma csr registers
    read_register(hsdp->csr_base, 0xE00);
    read_register(hsdp->csr_base, 0xE04);
    read_register(hsdp->csr_base, 0xE08);
    read_register(hsdp->csr_base, 0xE0C);
    read_register(hsdp->csr_base, 0xE10);
    read_register(hsdp->csr_base, 0xE14);
    read_register(hsdp->csr_base, 0xE18);
    read_register(hsdp->csr_base, 0xE1C);
    //read_register(hsdp->csr_base, 0xE20);
    //read_register(hsdp->csr_base, 0xE24);
    //read_register(hsdp->csr_base, 0xE28);
    //read_register(hsdp->csr_base, 0xE2C);
    //read_register(hsdp->csr_base, 0xE30);
    //read_register(hsdp->csr_base, 0xE38);
    //read_register(hsdp->csr_base, 0xE44);
    //read_register(hsdp->csr_base, 0xE88);
    //read_register(hsdp->csr_base, 0xE90);

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

#ifdef __RUN_TESTS__
    if (!skip_tests) {
        hsdp_run_enumerate(hsdp);
        //hsdp_run_setconfig(hsdp);
//        hsdp_run_getseq(hsdp);
//        hsdp_run_getseq(hsdp);
//        hsdp_run_getseq(hsdp);
    //    hsdp_run_getseq(hsdp);
//        dump_dma(hsdp);
    }
#endif

    return 0;

failed:
    if (hsdp->dma_buffer)
        dma_free_coherent(pdev->dev.parent, DMA_BUFFER_SIZE, hsdp->dma_buffer, hsdp->dma_handle);
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
    if (hsdp->base)
        iounmap(hsdp->base);

    platform_set_drvdata(pdev, NULL);
    kfree(hsdp);

    return 0;
}

int xocl_set_config_hsdp_mgmt_soft(struct platform_device *pdev, const struct hsdp_pcie_config *config)
{
    struct xocl_hsdp *hsdp;

    hsdp = kzalloc(sizeof(*hsdp), GFP_KERNEL);
    if (!hsdp)
        return -ENOMEM;

    hsdp->config = config;

    platform_set_drvdata(pdev, hsdp);

    return 0;
}

static struct platform_device_id hsdp_id_table[] = {
    { XOCL_HSDP_SOFT, MINOR_PRI_HIGH_BIT },
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

int __init xocl_init_hsdp_mgmt_soft(void)
{
    int err = 0;

    // Register the character packet device major and minor numbers
    err = alloc_chrdev_region(&hsdp_dev, 0, XOCL_MAX_DEVICES, HSDP_DEV_NAME);
    if (err != 0) goto err_register_chrdev;

    err = platform_driver_register(&hsdp_driver);
    if (err) {
        goto err_driver_reg;
    }

    pr_info("xocl_init_hsdp_mgmt_soft %s\n", XOCL_HSDP_SOFT);

    return 0;

err_driver_reg:
    unregister_chrdev_region(hsdp_dev, XOCL_MAX_DEVICES);
err_register_chrdev:
    return err;
}

void xocl_fini_hsdp_mgmt_soft(void)
{
    pr_info("xocl_fini_hsdp_mgmt_soft\n");
    if (hsdp_dev) {
        unregister_chrdev_region(hsdp_dev, XOCL_MAX_DEVICES);
        hsdp_dev = 0;
    }
    platform_driver_unregister(&hsdp_driver);
}
