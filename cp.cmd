## Template for copying files from local to remote site, destdir DEST:
tar -cz -f - testdir/sub1/bar.txt | \
  tar -xzv -C DEST --xform="s#.*/\(.*\)#\1#"

# Note the --xform= option will strip leading path components from the file
# on extraction (ie., throw away dirtree info when copying into remote DEST)
#
# Probably need to have a '-r' option ala 'scp -r' to control --xform=
# (in the absence of --xform=.. above, files and dirs will all be extracted
# to remote DEST preserving tree structure.)

