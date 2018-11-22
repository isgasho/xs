.PHONY: clean all vis

EXTPKGS = bytes,errors,flag,fmt,internal,io,log,net,os,path,runtime,time,strings,sync,syscall,binary,encoding
EXE = $(notdir $(shell pwd))

all:
	go build .

clean:
	$(RM) $(EXE) $(EXE).exe

vis:
	go-callvis -skipbrowser -svg -output hkexsh-vis -ignore $(EXTPKGS) -group pkg,type .


