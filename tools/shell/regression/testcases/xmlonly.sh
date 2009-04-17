#
# extract the xml cib
#
sed -n /^<?xml/,/^<\/cib>/p
