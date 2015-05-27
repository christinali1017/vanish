#!/bin/sh
set -e
filename=kademlia-`whoami`-`date "+%Y.%m.%d-%H.%M.%S"`.tar.gz
tar -cvf ${filename} src 

