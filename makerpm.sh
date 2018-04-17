#!/bin/sh

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

while getopts "d:" OPT; do
    case "${OPT}" in
        d)
            RPMDIR=${OPTARG}
            ;;
    esac
done
shift $((OPTIND-1))

if [ "$RPMDIR" == "" ]; then
    RPMDIR=~/rpms/
fi

mkdir -p $RPMDIR/SPEC
m4 -D VERSION=1.0 -D TOPDIR=$RPMDIR $DIR/pid1.spec > $RPMDIR/SPEC/pid1.spec

for SDIR in SOURCES BUILD RPMS SRPMS; do
    mkdir -vp $RPMDIR/$SDIR
done

./autogen.sh

BUILDDIR=$(mktemp -d)
cd $BUILDDIR
$DIR/configure && make && make dist
cp pid1-*.tar.gz $RPMDIR/SOURCES
cd $DIR
rm -rf $BUILDDIR

rpmbuild --buildroot=$RPMDIR/BUILDROOT -ba $RPMDIR/SPEC/pid1.spec
