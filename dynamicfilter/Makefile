# obj-m := k_url_block.o
obj-m := firewall.o  
    KERNELBUILD :=/lib/modules/$(shell uname -r)/build  
default:  
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:  
	rm -rf *.ko *.o  *.mod.c .*.cmd *.markers *.order *.symvers .tmp_versions  *~
