cmd_/root/vnic/Supervisor/vnic.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000 -T ./scripts/module-common.lds  --build-id  -o /root/vnic/Supervisor/vnic.ko /root/vnic/Supervisor/vnic.o /root/vnic/Supervisor/vnic.mod.o ;  true