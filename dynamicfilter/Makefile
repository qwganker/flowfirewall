obj-m += firewall.o
firewall-objs := main.o utils.o rule.o
KERNELBUILD :=/lib/modules/$(shell uname -r)/build  
default:  
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:  
	# rm -rf *.ko *.o  *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions  *~
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean