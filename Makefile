.PHONY: clean lib client server passwd

all: lib client server passwd

clean:
	rm -f\
 hkexsh/hkexsh hkexsh/hkexsh.exe\
 hkexshd/hkexshd hkexshd/hkexshd.exe\
 hkexpasswd/hkexpasswd hkexpasswd/hkexpasswd.exe


lib:
	go install .

client: lib
	cd hkexsh; go build .; cd -

server: lib
	cd hkexshd; go build .; cd -

passwd: lib
	cd hkexpasswd; go build .; cd -

