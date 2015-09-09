#!/bin/sh
DATE=`date "+%Y%m%d%H%M"`
COMMIT=`git rev-parse HEAD`
SHORTCOMMIT=`git rev-parse --short=8 HEAD`

cp plexus.spec.tmpl plexus.spec

sed -i -e "s;@@DATE@@;${DATE};" plexus.spec
sed -i -e "s;@@COMMIT@@;${COMMIT};" plexus.spec
sed -i -e "s;@@SHORTCOMMIT@@;${SHORTCOMMIT};" plexus.spec
