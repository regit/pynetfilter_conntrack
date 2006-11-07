.PHONY: test_README

PYTHON=python
REST2HTML=rst2html   # Debian package: python-docutils

test: test_doc test_README test_setup
test_doc:
	$(PYTHON) test_doc.py
test_README: README
	$(REST2HTML) README > /dev/null || exit $$?
test_setup:
	$(PYTHON) setup.py test

install: test
	sudo $(PYTHON) setup.py install

cheeseshop: test clean
	sudo $(PYTHON) register sdist bdist_egg upload

clean:
	find -name "*.pyc" -print0|xargs -0 rm -f
	rm -rf pynetfilter_conntrack.egg-info dist build

