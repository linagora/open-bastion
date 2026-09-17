#!/usr/bin/awk -f
# build_alt_map.awk
# Usage: awk -f build_alt_map.awk deps_graph

BEGIN {
    print "{"
    first = 1
}

# Match a node declaration like "	alt1 [" and remember its id
/^[[:space:]]*(alt|virt)[0-9]+[[:space:]]*\[/ {
    match($0, /(alt|virt)[0-9]+/)
    current = substr($0, RSTART, RLENGTH)
    next
}

# Match the label line belonging to the current alt node,
# e.g.: label = "<debconf> \{debconf\} | <other> ..."
current != "" && /label[[:space:]]*=/ {
    if (match($0, /<[^>]+>/)) {
        name = substr($0, RSTART + 1, RLENGTH - 2)

        if (!first) {
            print ","
        }
        printf "  \"%s\": \"%s\"", current, name
        first = 0
    }
    current = ""
}

END {
    print ""
    print "}"
}
