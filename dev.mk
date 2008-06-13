define CMDS
    -perl bin/revision.pl
    -perl -Iblib -c bin/openresty
    -sudo killall lighttpd
    sudo /etc/init.d/lighttpd restart
    rm  -f t/cur-timer.dat
    -time prove -Ilib -r t
    bin/perf
endef

all: lib/OpenResty/RestyScript/View.pm

lib/OpenResty/RestyScript/View.pm: grammar/restyscript-view.yp
	yapp -m OpenResty::RestyScript::View -o $@ $<

test: all
	$(CMDS)

debug: all
	$(CMDS)

%.t: all force
	perl -c bin/openresty
	sudo /etc/init.d/lighttpd restart
	-time prove -Ilib $@

force:

