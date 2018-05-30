ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src
EXTRA_DIST = autogen.sh
REPO_TAG=$(shell git describe --tags --match "v*" 2>/dev/null | cut -b 2-)
REPO_TAGFMT=$(shell echo ${REPO_TAG} | sed 's/-g/-/')
REPO_VER=$(shell echo ${REPO_TAGFMT} | cut -d '-' -f 1)
REPO_REL=$(shell echo ${REPO_TAGFMT} | cut -d '-' -f 2,3 | sed 's/-/_/')
REPO_COMMITS=$(shell git log --oneline | wc -l)

rpmdir=$(abs_builddir)/rpms

rpm: dist
	rm -rf $(rpmdir)
	mkdir -p $(rpmdir)/SOURCES
	mkdir -p $(rpmdir)/SRPMS
	mkdir -p $(rpmdir)/RPMS
	mkdir -p $(rpmdir)/BUILD
	mkdir -p $(rpmdir)/BUILDROOT
	cp $(distdir).tar.gz $(rpmdir)/SOURCES
	REPO_VER=$(REPO_VER) && REPO_REL=$(REPO_REL) && \
	rpmbuild -ba \
           -D "_topdir $(rpmdir)" \
		   -D "_version $${REPO_VER:=0.0}" \
		   -D "_release $${REPO_REL:=$(REPO_COMMITS)}" \
           $(top_srcdir)/pid1.spec

install_rpm:
	[ ! -z $(rpm_install_dir) ] || echo must run make rpm_install_dir=...
	mkdir -p $(rpm_install_dir)
	rsync -r $(rpmdir)/RPMS $(rpm_install_dir)
	rsync -r $(rpmdir)/SRPMS $(rpm_install_dir)
	
