# GDB may have ./.gdbinit loading disabled by default.  In that case you can
# follow the instructions it prints.  They boil down to adding the following to
# your home directory's ~/.gdbinit file:
#
#   add-auto-load-safe-path /path/to/qemu/.gdbinit

# Load QEMU-specific sub-commands and settings
source scripts/qemu-gdb.py

file ./build/qemu-system-riscv64

b helper_dasics_redirect
b dasics_in_trusted_zone


run -M virt -m 256M -nographic -kernel /home/wanghan/Workspace/ucas-os/riscv-pk/build/bbl \
        -drive file=/home/wanghan/Workspace/ucas-os/ucas-os/img/sd.img,if=none,format=raw,id=x0 \
        -device virtio-blk-device,drive=x0 \
        -bios none

# b cpu-exec.c:971
# if ((RISCVHartArrayState *)0x5555566252d8).harts[0].env.pc == 0x80002048

# c

