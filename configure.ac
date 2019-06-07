AC_INIT(treadmill-pid1, m4_esyscmd_s([git describe --tags HEAD --long --match "v*" 2>/dev/null > /dev/null; if [ $? == 0 ]; then git describe --tags HEAD --long --match "v*" 2>/dev/null | cut -b 2- | cut -d '-' -f 1; else echo 0.0; fi]), andreikeis@noreply.users.github.com)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/pid1.c)
AM_INIT_AUTOMAKE([tar-pax])
AC_PROG_CC
AC_PROG_CC_STDC
AC_OUTPUT(Makefile src/Makefile)

