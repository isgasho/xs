.PHONY: info clean common client server passwd subpkgs

SUBPKGS = spinsult hkexnet herradurakex
TOOLS = hkexpasswd hkexsh hkexshd
SUBDIRS = $(LIBS) $(TOOLS)

all: common client server passwd

clean:
	go clean .
	for d in $(SUBDIRS); do\
	  $(MAKE) -C $$d clean;\
	done

subpkgs:
	for d in $(SUBPKGS); do\
	  $(MAKE) -C $$d all;\
	done

tools:
	for d in $(TOOLS); do\
	  $(MAKE) -C $$d all;\
	done

common:
	go install .

client: common
	$(MAKE) -C hkexsh

ifneq ($(MSYSTEM),)
server: common
	echo "hkexshd server not (yet) supported on Windows"
else
server: common
	$(MAKE) -C hkexshd
endif

passwd: common
	$(MAKE) -C hkexpasswd

