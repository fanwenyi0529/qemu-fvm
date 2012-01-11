/*
 * Phytec phyCARD-L
 *
 * Copyright (c) 2011, 2012 Stefan Weil
 *
 * ARM Cortex-A8, OMAP3530, similar to OMAP3430
 *
 */

#include "sysbus.h"
#include "boards.h"
#include "arm-misc.h"
#include "exec-memory.h"        /* get_system_memory */
#include "net.h"

static struct arm_boot_info phycard_binfo;

static void phycard_init(ram_addr_t ram_size,
                        const char *boot_device,
                        const char *kernel_filename, const char *kernel_cmdline,
                        const char *initrd_filename, const char *cpu_model)
{
    CPUState *env;
    MemoryRegion *sysmem = get_system_memory();
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    qemu_irq *cpu_pic;
    qemu_irq pic[64];
    DeviceState *dev;
    int i;

    if (!cpu_model) {
        cpu_model = "cortex-a8";
    }
    env = cpu_init(cpu_model);
    if (!env) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }

    /* RAM at address zero. */
    memory_region_init_ram(ram, "phycard.ram", ram_size);
    vmstate_register_ram_global(ram);
    memory_region_add_subregion(sysmem, 0, ram);

    cpu_pic = arm_pic_init_cpu(env);
    dev = sysbus_create_simple("syborg,interrupt", 0xC0000000,
                               cpu_pic[ARM_PIC_CPU_IRQ]);
    for (i = 0; i < 64; i++) {
        pic[i] = qdev_get_gpio_in(dev, i);
    }

    sysbus_create_simple("syborg,rtc", 0xC0001000, NULL);

    dev = qdev_create(NULL, "syborg,timer");
    qdev_prop_set_uint32(dev, "frequency", 1000000);
    qdev_init_nofail(dev);
    sysbus_mmio_map(sysbus_from_qdev(dev), 0, 0xC0002000);
    sysbus_connect_irq(sysbus_from_qdev(dev), 0, pic[1]);

    sysbus_create_simple("syborg,keyboard", 0xC0003000, pic[2]);
    sysbus_create_simple("syborg,pointer", 0xC0004000, pic[3]);
    sysbus_create_simple("syborg,framebuffer", 0xC0005000, pic[4]);
    sysbus_create_simple("syborg,serial", 0xC0006000, pic[5]);
    sysbus_create_simple("syborg,serial", 0xC0007000, pic[6]);
    sysbus_create_simple("syborg,serial", 0xC0008000, pic[7]);
    sysbus_create_simple("syborg,serial", 0xC0009000, pic[8]);

    if (nd_table[0].vlan || nd_table[0].netdev) {
        DeviceState *dev;
        SysBusDevice *s;

        qemu_check_nic_model(&nd_table[0], "virtio");
        dev = qdev_create(NULL, "syborg,virtio-net");
        qdev_set_nic_properties(dev, &nd_table[0]);
        qdev_init_nofail(dev);
        s = sysbus_from_qdev(dev);
        sysbus_mmio_map(s, 0, 0xc000c000);
        sysbus_connect_irq(s, 0, pic[9]);
    }

    phycard_binfo.ram_size = ram_size;
    phycard_binfo.kernel_filename = kernel_filename;
    phycard_binfo.kernel_cmdline = kernel_cmdline;
    phycard_binfo.initrd_filename = initrd_filename;
    phycard_binfo.board_id = 0;
    arm_load_kernel(env, &phycard_binfo);
}

static QEMUMachine phycard_machine = {
    .name = "phycard-l",
    .desc = "phyCARD-L (ARM Cortex-A8)",
    .init = phycard_init,
};

static void phycard_machine_init(void)
{
    qemu_register_machine(&phycard_machine);
}

machine_init(phycard_machine_init);