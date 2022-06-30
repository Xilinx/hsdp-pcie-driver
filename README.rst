
HSDP PCIe Driver
================
The HSDP (high speed debug port) PCIe Driver enables configuration and debug commuication through a standard PCIe interface. HSDP uses PCIe as the physical communication channel to send debug protocol messages defined by the Debug Packet Controller (DPC) from a host to device target. Fundamentally, this debug protocol defines how AXI transactions are executed on the target system, for instance the Versal 1902 device. These transactions will typically consist of AXI register read/write operations. The HSDP PCIe driver abstracts the physical PCIe configuration for the DPC interface and establishes methods to perform higher level DPC operations like AXI read/write operations.

There is a Configurable Example Design (CED) hosted on GitHub and fetched through Vivado that can generate a bitstream and be loaded to hardware that can be used with this driver. It is named "Versal CPM Debug-over-PCIe" and can be found by navigating to File->Project->Open Example... 


Building and Installation
=========================

To build this driver:

1. Modify the variables within hsdp_pcie_user_config.h to match your hardware 
   design and IP settings.

   More information and example settings can be found at `Versal_CPM_PCIe_Debug <https://github.com/Xilinx/XilinxCEDStore/tree/master/ced/Xilinx/IPI/Versal_CPM_PCIe_Debug>`_

2. Compile the driver:

      # make install

3. Run depmod to pick up newly installed kernel module:

      # depmod -a xilinx_hsdp_pcie_driver

4. Make sure no older version of the driver are loaded:

      # modprobe -r xilinx_hsdp_pcie_driver

5. Load the module:

      # modprobe xilinx_hsdp_pcie_driver

   NOTE: You can also use insmod on the kernel object file to load the module:

      # make insmod

   but this is not recommended unless necessary for compatibility with older 
   kernels.


Unloading and Uninstalling the Driver
=====================================

1. Unload the kernel module:

      # modprobe -r xilinx_hsdp_pcie_driver

   NOTE: You can also use rmmod to unload the kernel module:

      # make rmmod

   but this is not recommended unless necessary for compatibility with older 
   kernels.

2. From the directory containing the source files, make clean and uninstall:

      # make clean uninstall

   This will remove the compiled driver from the sources directory as well as 
   uninstall it from its location in /lib/modules/[KERNEL_VERSION].

