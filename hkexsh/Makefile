.PHONY: clean all vis lint

EXTPKGS = bytes,errors,flag,fmt,internal,io,log,net,os,path,runtime,time,strings,sync,syscall,binary,encoding
EXE = $(notdir $(shell pwd))

all:
	go build .

clean:
	$(RM) $(EXE) $(EXE).exe

vis:
	go-callvis -skipbrowser -output hkexsh-vis -ignore $(EXTPKGS) -group pkg,type .
	../fixup-gv.sh hkexsh.go && cat hkexsh-vis.gv | dot -Tpng -ohkexsh-vis.gv.png

lint:
	-gometalinter --deadline=60s | sort
