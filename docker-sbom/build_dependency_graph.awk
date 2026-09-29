#!/usr/bin/awk -f
# Builds the dependency graph of one package from the dpkg inventory of the
# image it is installed in, as the JSON array generate-sbom.sh consumes.
#
# Usage: awk -v root=PACKAGE -f build_dependency_graph.awk INVENTORY
#
# INVENTORY holds one tab-separated record per package, in the field order the
# query in generate-sbom.sh declares:
#
#     Package   db:Status-Status   Pre-Depends   Depends   Provides
#
# Refs are installed packages only, and only those reachable from PACKAGE: a
# dependency entry is resolved to the installed package satisfying it, by name
# or through the Provides of a virtual package.

BEGIN { FS = "\t" }

# dpkg-query does not escape what it prints: a tab or a newline inside a field
# would shift or split the record, and the fields read below would no longer be
# the ones asked for.
NF != 5 && $0 != "" {
    print "warning: ignoring malformed record: " $0 > "/dev/stderr"
    next
}

# dpkg-query -W also reports packages that are in the dpkg database without being
# installed (config-files leftovers, for instance); they are not graph nodes.
$1 != "" && $2 == "installed" {
    installed[$1] = 1
    predeps[$1] = $3
    deps[$1] = $4
    if ($5 != "") {
        n = split($5, provided, ",")
        for (i = 1; i <= n; i++) {
            name = provided[i]
            sub(/\(.*/, "", name)          # "mail-transport-agent (= 3.9.0-4)"
            gsub(/^[ \t]+/, "", name)
            gsub(/[ \t]+$/, "", name)
            if (name != "") providers[name] = providers[name] " " $1
        }
    }
}

# A dependency entry carries a version constraint, possibly a build profile and
# an architecture qualifier; only the package name is of interest here.
function package_name(entry) {
    sub(/\(.*/, "", entry)
    sub(/<.*/, "", entry)
    sub(/:.*/, "", entry)
    gsub(/^[ \t]+/, "", entry)
    gsub(/[ \t]+$/, "", entry)
    return entry
}

# The installed package satisfying a dependency name: the package itself, or a
# provider of a virtual package. Providers are named in a fixed order so that
# the same inventory always yields the same graph.
function candidate(name,    n, names, i, best, one) {
    if (name in installed) return name
    if (!(name in providers)) return ""
    n = split(providers[name], names, " ")
    for (i = 1; i <= n; i++) {
        one = names[i]
        if (one != "" && (best == "" || one < best)) best = one
    }
    return best
}

# Resolves a dependency list into the installed packages it requires, adding
# them to targets. Alternatives are equivalent for dpkg, so the first one an
# installed package satisfies is the one kept. Version constraints are not
# compared: the image is built by installing the package, so dpkg already holds
# a version satisfying each of them.
function collect(pkg, list, targets,    n, entries, i, m, alts, j, name, target, found, named) {
    n = split(list, entries, ",")
    for (i = 1; i <= n; i++) {
        m = split(entries[i], alts, "|")
        found = 0
        named = 0
        for (j = 1; j <= m; j++) {
            name = package_name(alts[j])
            if (name == "") continue
            named = 1
            target = candidate(name)
            if (target != "") {
                targets[target] = 1
                found = 1
                break
            }
        }
        if (named && !found) {
            print "warning: " pkg ": no installed package satisfies: " entries[i] > "/dev/stderr"
        }
    }
}

# Fills order with the keys of targets, sorted, and returns how many there
# are: the emitted graph, and therefore the SBOM, must not depend on awk's
# array traversal order.
function sorted_keys(targets, order,    n, i, j, held) {
    n = 0
    for (key in targets) order[++n] = key
    for (i = 2; i <= n; i++) {
        held = order[i]
        for (j = i - 1; j >= 1 && order[j] > held; j--) order[j + 1] = order[j]
        order[j + 1] = held
    }
    return n
}

function json_names(order, n,    i, list) {
    list = ""
    for (i = 1; i <= n; i++) list = list (i > 1 ? "," : "") "\"" order[i] "\""
    return list
}

END {
    if (!(root in installed)) {
        print "error: " root " is not installed in the image" > "/dev/stderr"
        exit 1
    }

    print "["
    queue[1] = root
    visited[root] = 1
    head = 1
    tail = 1
    first = 1
    # Breadth-first walk: dpkg dependency graphs contain cycles, which the
    # visited set terminates, and only the packages reachable from root belong
    # in the SBOM.
    while (head <= tail) {
        pkg = queue[head++]
        split("", targets)
        collect(pkg, predeps[pkg], targets)
        collect(pkg, deps[pkg], targets)
        n = sorted_keys(targets, order)
        if (!first) print ","
        first = 0
        printf "  {\"ref\": \"%s\", \"dependsOn\": [%s]}", pkg, json_names(order, n)
        for (i = 1; i <= n; i++) {
            if (!(order[i] in visited)) {
                visited[order[i]] = 1
                queue[++tail] = order[i]
            }
        }
    }
    print ""
    print "]"
}
