.PHONY: clean all vis lint

EXTPKGS = binary,bytes,crypto,encoding,errors,flag,fmt,internal,io,log,net,os,path,runtime,time,strings,sync,syscall
EXE = $(notdir $(shell pwd))

all:
	go build .

clean:
	$(RM) $(EXE) $(EXE).exe

vis:
	go-callvis -skipbrowser -png -svg -output hkexshd-vis -ignore $(EXTPKGS) -group pkg,type .

lint:
	-gometalinter --deadline=60s | sort

