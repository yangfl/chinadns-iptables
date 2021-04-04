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
scan: res0 res1 res2 res3 res4 res5 res6 res7

ipv4.list.new:
	cat res* | grep -F "Address: " | sort | uniq | sed "s/Address: //g" >> $@

res%:
	i=0; \
	while [ "$$i" != 50 ]; do \
		i=$$((i+1)); \
		echo $@ $$i; \
		a=$$(nslookup -timeout=3 www.youtube.com 8.8.8.8); \
		echo "$$a" | grep -qP 'Name:\twww.youtube.com' && echo "$$a" >> $@; \
	done; true

.PHONY: clean
clean:
	$(RM) res* res *.sh ipv4.list.*

.PHONY: tests
tests:
	nslookup youtube.com 8.8.8.8
	nslookup youtube.com 2606:4700:4700::1111

.PHONY: fail
fail:
	nslookup youtube.com 114.114.114.114
