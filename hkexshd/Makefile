.PHONY: clean all vis lint

EXTPKGS = binary,bytes,crypto,encoding,errors,flag,fmt,internal,io,log,net,os,path,runtime,time,strings,sync,syscall
EXE = $(notdir $(shell pwd))

all:
	go build .

clean:
	$(RM) $(EXE) $(EXE).exe

vis:
	go-callvis -skipbrowser -output hkexshd-vis -ignore $(EXTPKGS) -group pkg,type .
	../fixup-gv.sh hkexshd.go && cat hkexshd-vis.gv | dot -Tpng -ohkexshd-vis.gv.png

lint:
	-gometalinter --deadline=60s | sort

