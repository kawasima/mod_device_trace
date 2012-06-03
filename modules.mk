mod_device_trace.la: mod_device_trace.slo hmac.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_device_trace.lo hmac.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_device_trace.la
