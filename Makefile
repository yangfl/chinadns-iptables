all: a.sh

a.sh: a.py
	python3 a.py > a.sh

apply: a.sh
	sudo sh a.sh

tests:
	nslookup youtube.com 8.8.8.8
	nslookup youtube.com 2606:4700:4700::1111

fail:
	nslookup youtube.com 114.114.114.114
