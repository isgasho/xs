.PHONY: info clean common client server passwd subpkgs

SUBPKGS = logger spinsult hkexnet herradurakex
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

ifeq ($(MSYSTEM),)
ifneq ($(GOOS),windows)
server: common
	$(MAKE) -C hkexshd
else
	echo "Cross-build of hkexshd server for Windows not yet supported"
endif
else
server: common
	echo "hkexshd server not (yet) supported on Windows"
endif

passwd: common
	$(MAKE) -C hkexpasswd

