.PHONY: all
all: apply.sh

apply.sh: a.py ipv4.list
	python3 $< > $@

.PHONY: apply
apply: apply.sh
	-sudo sh $<

revert.sh: a.py ipv4.list
	python3 $< -d > $@

.PHONY: revert
revert: revert.sh
	-sudo sh $<

.PHONY: reboot
reboot: apply.sh revert.sh
	-sudo sh revert.sh
	-sudo sh apply.sh

###

.PHONY: merge
merge: ipv4.list ipv4.list.new
	@sort $^ | uniq > $<.t
	@wc -l $<
	@wc -l $<.t
	@mv $<.t $<

.PHONY: scan
scan: ipv4.list.new

.PHONY: ipv4.list.new
ipv4.list.new: res0 res1 res2 res3 res4 res5 res6 res7
	wc -l $@
	cat res* | grep -F "Address: " | sort | uniq | sed "s/Address: //g" >> $@
	$(RM) res*
	sort $@ | uniq >> $@.tmp
	mv $@.tmp $@
	wc -l $@

res%:
	i=0; \
	while [ "$$i" != 50 ]; do \
		i=$$((i+1)); \
		echo $@ $$i; \
		nslookup -timeout=1 www.youtube.com 8.8.4.4 | grep -PA 1 'Name:\twww.youtube.com' >> $@; \
	done; \
	true
# nslookup -timeout=1 www.youtube.com 8.8.4.4 | grep -PA 1 'Name:\twww.youtube.com' >> $@;
# nslookup -timeout=1 -type=AAAA google.com 8.8.4.4 | grep -PA 1 'Name:\tgoogle.com' >> $@

.PHONY: clean
clean:
	$(RM) res* *.sh ipv4.list.*

.PHONY: tests
tests:
	nslookup youtube.com 8.8.8.8
	nslookup youtube.com 2606:4700:4700::1111

.PHONY: fail
fail:
	nslookup youtube.com 114.114.114.114
