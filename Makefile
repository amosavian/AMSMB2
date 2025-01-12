test:
	swift test

linuxtest:
	docker build -f Dockerfile -t linuxtest .
	docker run --rm -v .:/home/nonroot/src/app linuxtest

cleanlinuxtest:
	docker build -f Dockerfile -t linuxtest .
	docker run --rm linuxtest
