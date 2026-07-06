.PHONY: all
all: apply.sh

apply.sh: a.py ip.txt
	python3 $< > $@

.PHONY: apply
apply: apply.sh
	-sudo sh $<

revert.sh: a.py ip.txt
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
merge: ip.txt ip.new.txt
	@sort $^ | uniq | grep -v '^2001::' | grep -v '^2a03:2880:f1' > $<.tmp
	@wc -l $<
	@wc -l $<.tmp
	@mv $<.tmp $<
	$(RM) ip.new.txt

.PHONY: scan
scan: ip.new.txt

.PHONY: ip.new.txt
ip.new.txt: scan.0.txt scan.1.txt scan.2.txt scan.3.txt scan.4.txt scan.5.txt scan.6.txt scan.7.txt
	cat scan.*.txt | grep -Po '\t[^\t]+$$' | cut -f2 >> $@
	$(RM) scan.*.txt
	sort $@ | uniq > $@.tmp
	mv $@.tmp $@
	wc -l $@

#DOMAIN := twitter.com
DOMAIN := rr5.sn-o097znse.googlevideo.com
SERVER := 8.8.4.4

scan.%.txt:
	i=0; \
	while [ "$$i" != 128 ]; do \
		i=$$((i+1)); \
		echo $@ $$i; \
		res=$$(dig +timeout=1 +tries=1 @$(SERVER) $(DOMAIN) A); \
		if echo "$$res" | grep -qF "ADDITIONAL: 0"; then \
			echo "$$res" | grep '^$(DOMAIN)\.' >> $@; \
		fi; \
		res=$$(dig +timeout=1 +tries=1 @$(SERVER) $(DOMAIN) AAAA); \
		if echo "$$res" | grep -qF "ADDITIONAL: 0"; then \
			echo "$$res" | grep '^$(DOMAIN)\.' >> $@; \
		fi; \
	done; \
	true
# nslookup -timeout=1 www.youtube.com 8.8.4.4 | grep -PA 1 'Name:\twww.youtube.com' >> $@;
# nslookup -timeout=1 -type=AAAA google.com 8.8.4.4 | grep -PA 1 'Name:\tgoogle.com' >> $@

.PHONY: clean
clean:
	$(RM) res* *.sh ip.txt.*

.PHONY: tests
tests:
	nslookup youtube.com 8.8.8.8
	nslookup youtube.com 2606:4700:4700::1111

.PHONY: fail
fail:
	nslookup youtube.com 114.114.114.114
