find -name "*.pyc" -print0|xargs -0 rm -f
rm -rf pynetfilter_conntrack.egg-info dist build
