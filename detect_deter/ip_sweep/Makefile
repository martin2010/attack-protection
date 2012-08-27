obj-m:=ip_sweep.o
KERNELBUILD:=/lib/modules/2.6.30.10/build #$(shell uname -r)/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o *.ko *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions
