.PHONY: info clean lib client server passwd

SUBDIRS = hkexnet herradurakex hkexpasswd hkexsh hkexshd
LIBS = hkexnet herradurakex

all: lib client server passwd

clean:
	go clean .
	for d in $(SUBDIRS); do\
	  $(MAKE) -C $$d clean;\
	done

lib:
	go install .

client: lib
	$(MAKE) -C hkexsh

ifneq ($(MSYSTEM),)
server: lib
	echo "hkexshd server not supported on Windows (yet)"
else
server: lib
	$(MAKE) -C hkexshd
endif

passwd: lib
	$(MAKE) -C hkexpasswd

