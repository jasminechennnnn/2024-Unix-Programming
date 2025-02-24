
obj-m     += maze.o
ccflags-y += -DEXPORT_SYMTAB

all: 
	make -C ../dist/modulebuild M=$(PWD) modules
	mkdir -p ../rootfs/modules
	cp maze.ko  ../rootfs/modules

clean:
	make -C ../dist/modulebuild M=$(PWD) clean