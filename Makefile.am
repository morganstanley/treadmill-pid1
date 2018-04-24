ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src
EXTRA_DIST = autogen.sh

rpmdir=$(abs_builddir)/rpms

rpm: dist
	rm -rf $(rpmdir)
	mkdir -p $(rpmdir)/SOURCES
	mkdir -p $(rpmdir)/SRPMS
	mkdir -p $(rpmdir)/RPMS
	mkdir -p $(rpmdir)/BUILD
	mkdir -p $(rpmdir)/BUILDROOT
	cp $(distdir).tar.gz $(rpmdir)/SOURCES
	rpmbuild -ba -D "_topdir $(rpmdir)" $(top_srcdir)/pid1.spec

install_rpm:
	[ ! -z $(rpm_install_dir) ] || echo must run make rpm_install_dir=...
	mkdir -p $(rpm_install_dir)
	rsync -r $(rpmdir)/RPMS $(rpm_install_dir)
	rsync -r $(rpmdir)/SRPMS $(rpm_install_dir)
	
