.PHONY: vis clean common client server passwd subpkgs install uninstall

SUBPKGS = logger spinsult hkexnet herradurakex
TOOLS = hkexpasswd hkexsh hkexshd
SUBDIRS = $(LIBS) $(TOOLS)

INSTPREFIX = /usr/local

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

vis:
	@which go-code-visualizer >/dev/null 2>&1; \
	stat=$$?; if [ $$stat -ne "0" ]; then \
	  /bin/echo "go-code-visualizer not found. Run go get github.com/CodeHipster/go-code-visualizer to install."; \
	else \
	  go-code-visualizer . && dot -Tpng dot-visual.gv -o viz_hkexsh_dot.png; \
	fi

install:
	cp hkexsh/hkexsh $(INSTPREFIX)/bin
ifeq ($(MSYSTEM),)
ifneq ($(GOOS),windows)
	cp hkexshd/hkexshd hkexpasswd/hkexpasswd $(INSTPREFIX)/sbin
else
	mv $(INSTPREFIX)/bin/hkexsh $(INSTPREFIX)/bin/_hkexsh
	cp hkexsh/mintty_wrapper.sh $(INSTPREFIX)/bin/hkexsh
	echo "Cross-build of hkexshd server for Windows not yet supported"
endif
else
	echo "Cross-build of hkexshd server for Windows not yet supported"
endif
	cd $(INSTPREFIX)/bin && ln -s hkexsh hkexcp && cd -


uninstall:
	rm -f $(INSTPREFIX)/bin/hkexsh $(INSTPREFIX)/bin/hkexcp $(INSTPREFIX)/bin/_hkexsh
ifeq ($(MSYSTEM),)
ifneq ($(GOOS),windows)
	rm -f $(INSTPREFIX)/sbin/hkexshd $(INSTPREFIX)/sbin/hkexpasswd
else
endif
else
endif
