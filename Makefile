# Makefile for libosdp

all:
	(cd src-lib; make all; cd ..)
	(cd src-485; make all; cd ..)
	(cd src-tls; make all; cd ..)
	(cd src-ui; make all; cd ..)

clean:
	(cd src-lib; make clean; cd ..)
	(cd src-485; make clean; cd ..)
	(cd src-tls; make clean; cd ..)
	(cd src-ui; make clean; cd ..)
	rm -rf release-libosdp.tgz opt stderr

build:	all
	(cd src-lib; make build; cd ..)
	(cd src-485; make build; cd ..)
	(cd src-tls; make build; cd ..)
	(cd src-ui; make build; cd ..)
	cp doc/config-samples/open-osdp-params-CP.json \
	  opt/open-osdp/run/CP/open-osdp-params.json
	cp doc/config-samples/open-osdp-params-PD.json \
	  opt/open-osdp/run/PD/open-osdp-params.json
	cp doc/config-samples/open-osdp-params-MON.json \
	  opt/open-osdp/run/MON/open-osdp-params.json
	(cd test; make build-test; cd ..)

release:	build
	tar czvf release-libosdp.tgz opt/*

