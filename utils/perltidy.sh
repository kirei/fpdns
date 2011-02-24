#!/bin/sh

TIDYRC=`dirname $0`/perltidyrc

find . \( -name \*.pm -o -name \*.pl -o -name fpdns \) -print |\
xargs perltidy --profile=${TIDYRC} --backup-and-modify-in-place

find . -name '*.bak'  -type f -print | xargs rm