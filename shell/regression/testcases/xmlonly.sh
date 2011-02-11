#!/bin/sh
#
# extract the xml cib
#
sed -n '/^<?xml/,/^<\/cib>/p'
