#!/bin/sh

TIDYRC=`dirname $0`/perltidyrc

find . \( -name .*.pm -o -name *.pl \) -print |\
xargs perltidy --profile=${TIDYRC} --backup-and-modify-in-place

find . \( -name '*.pl.bak' -o -name '*.pm.bak' \) -type f -print |\
xargs rm
