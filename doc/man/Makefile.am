dist_man_MANS = instances.conf.5 policy.py.5 zorp.8 zorpctl.8 zorpctl.conf.5

SUFFIXES = .xml

%:: %.xml
	$(ZWA_ROOT)/bin/xml2man.sh $< $@
