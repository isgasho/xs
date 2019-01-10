.PHONY: clean all vis lint

EXTPKGS = bytes,errors,flag,fmt,internal,io,log,net,os,path,runtime,time,strings,sync,syscall,binary,encoding
EXE = $(notdir $(shell pwd))

all:
	go build .

clean:
	$(RM) $(EXE) $(EXE).exe

vis:
	go-callvis -file hkexsh-vis -format jpg -ignore $(EXTPKGS) -group pkg,type .
	../fixup-gv.sh hkexsh.go && cat hkexsh-vis.gv | dot -Tjpg -ohkexsh-vis-fixedup.png

lint:
	-gometalinter --deadline=60s | sort
