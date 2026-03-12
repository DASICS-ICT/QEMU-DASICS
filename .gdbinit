# GDB may have ./.gdbinit loading disabled by default.  In that case you can
# follow the instructions it prints.  They boil down to adding the following to
# your home directory's ~/.gdbinit file:
#
#   add-auto-load-safe-path /path/to/qemu/.gdbinit

# Load QEMU-specific sub-commands and settings
source scripts/qemu-gdb.py

file ./build/qemu-system-riscv64


run -M virt -m 1G \
        -nographic -kernel /home/wanghan/Workspace/riscv-pk-qemu/build/bbl \
        -append "console=ttyS0 rw root=/dev/vda" \
        -bios none

# b cpu-exec.c:971
# if ((RISCVHartArrayState *)0x5555566252d8).harts[0].env.pc == 0x80002048

# c
