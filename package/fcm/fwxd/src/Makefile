OBJS:=fwx_user.o fwx_netlink.o fwx_ubus.o fwx_config.o fwx_utils.o main.o fwx_app_filter.o fwx_mac_filter.o fwx_common.o fwx_system.o fwx_network.o check_main.o fwx_alert.o fwx_security_ubus.o fwx_hardware.o fwx_device_profile.o fwx_profile_ubus.o
EXEC:=fwxd

all: $(OBJS)
	$(CC) -o $(EXEC) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(EXEC) *.o
