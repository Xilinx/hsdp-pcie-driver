MODULENAME = xilinx_hsdp_pcie_driver
DRIVER_LOCATION = /lib/modules/$(shell uname -r)/kernel/drivers/pci/pcie/xilinx/
SOURCE = src

obj-m += $(MODULENAME).o
EXTRA_CFLAGS := -DLOG_PREFIX=\"$(MODULENAME):\ \" -I$(SOURCE)

$(MODULENAME)-objs := $(SOURCE)/hsdp_pcie_driver_base.o $(SOURCE)/hsdp_mgmt_pcie_driver.o $(SOURCE)/hsdp_user_pcie_driver.o $(SOURCE)/hsdp_mgmt_soft_pcie_driver.o

install: module
	mkdir -p $(DRIVER_LOCATION)
	cp -f $(MODULENAME).ko $(DRIVER_LOCATION)

module:
	@echo $($(MODULENAME)-objs)
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

uninstall:
	rm -rf $(DRIVER_LOCATION)

insmod:
	insmod $(DRIVER_LOCATION)/$(MODULENAME).ko
	lsmod | grep xil

rmmod:
	rmmod $(MODULENAME)
