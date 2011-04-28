#!/bin/sh
#
# $Id: autogen.sh,v 1.5 2004/08/18 11:25:39 bazsi Exp $
#
# Run this script to generate Makefile skeletons and configure
# scripts.
#

libtoolize -f --copy
aclocal $*
autoheader
automake --add-missing --force-missing --copy --foreign
autoconf
