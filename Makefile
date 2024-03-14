DEBIANDIR=debian-base
DEBIANVER=bookworm
LINUXDIR=linux
USERDIR=user
MOUNTDIR=mount
NCORES=8

ifeq ($(STOP),1)
QEMUSTOP = -S
endif

include user/users.mk

all: update-img kernel

$(DEBIANDIR):
	sudo debootstrap $(DEBIANVER) $@ http://deb.debian.org/debian/
	sudo sed -i 's/^root:x:/root::/' $@/etc/passwd
	sudo chroot $@ /bin/sh -c \
		"apt-get update && apt-get install -y build-essential \
		 musl-tools gdb libcapstone-dev libelf-dev libcrypt-dev \
		 debhelper pkg-config"
	sudo ln -s ../asm-generic $@/usr/include/x86_64-linux-musl/
	sudo ln -s ../linux $@/usr/include/x86_64-linux-musl/
	sudo ln -s ../x86_64-linux-gnu/asm $@/usr/include/x86_64-linux-musl/
	for u in $(USERS); do sudo useradd -R $$(realpath $@) $$u; done

update-img: img $(DEBIANDIR) $(USERDIR)
	mkdir -p $(MOUNTDIR)
	sudo mount -o loop img $(MOUNTDIR)
	sudo cp -au $(DEBIANDIR)/. $(MOUNTDIR)/
	sudo cp -ru $(USERDIR)/. $(MOUNTDIR)/root/
	sudo umount $(MOUNTDIR)

img:
	dd if=/dev/zero of=$@ bs=1G count=4
	sudo mkfs.ext4 -F $@

kernel:
	$(MAKE) -C $(LINUXDIR) -j $(NCORES)
	cp -u $(LINUXDIR)/arch/x86/boot/bzImage kernel

run: update-img kernel
	qemu-system-x86_64 -M q35 -smp 4 -m 2G -accel kvm \
	-kernel kernel -append "nokaslr console=ttyS0 root=/dev/sda rw" \
	-drive file=img,media=disk,format=raw,index=0 \
	-nographic -s $(QEMUSTOP)

clean:
	rm -f img kernel

distclean: clean
	$(MAKE) -C linux clean
	rmdir $(MOUNTDIR)
	sudo rm -r $(DEBIANDIR)

.PHONY: all clean distclean run update-img kernel
