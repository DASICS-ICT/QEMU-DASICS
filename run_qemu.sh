#!/bin/sh
sudo /home/ws/qemu/build-dasics/riscv64-softmmu/qemu-system-riscv64 -M virt -m 1G \
	-nographic -kernel riscv-pk/build/bbl \
	-append "console=ttyS0 rw root=/dev/vda" \
	-drive file=img,format=raw,id=hd0 \
	-device virtio-blk-device,drive=hd0 \
	-bios none  -s -S
