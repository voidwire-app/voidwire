#!/bin/sh
# android-qa host peer: stands in for /usr/bin/xdg-open on the CI runner only
# (the desktop opener execs that fixed path). Records the URL, opens nothing.
echo "$(date +%H:%M:%S.%N) OPENED argc=$# $1" >> /tmp/vw-peer/opened.log
