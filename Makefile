all: doc/spec.html

doc/spec.html: doc/spec.pod
	cd doc && podhtm.pl --index --charset UTF-8 --css perl.css -o spec.html spec.pod

test:
	perl -c openapi.pl
	echo > /var/log/lighttpd/error.log
	sudo /etc/init.d/lighttpd restart
	-time prove -Ilib -r t

debug: test
	cat /var/log/lighttpd/error.log | egrep -v '^$$'

