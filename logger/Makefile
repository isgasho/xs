.PHONY: clean all lint

EXE = $(notdir $(shell pwd))

all:
	go build .

clean:
	$(RM) $(EXE) $(EXE).exe

lint:
	gometalinter --deadline 60s | sort
