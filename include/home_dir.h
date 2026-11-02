#ifndef OB_HOME_DIR_H
#define OB_HOME_DIR_H

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * Name of the staging directory built beside the account's home. The caller
 * fills it with mkdtemp() and moves it into place once complete, so that the
 * home never appears under its final name root-owned or half-populated.
 *
 * The parent directory must already exist and be writable: mkdtemp() creates
 * the last path component only. Any trailing slash on `home` is ignored, so
 * that "/home/alice/" stages in "/home" rather than inside the home itself.
 *
 * Returns 0 when `out` holds the template, -1 for an empty, relative or
 * overlong path, or a home with no usable parent (a single leading slash).
 */
static inline int home_dir_temp_template(const char *home, char *out, size_t out_size)
{
    char parent[PATH_MAX];
    char *slash;
    size_t len;
    int n;

    if (!home || !*home || !out || out_size == 0) {
        return -1;
    }

    /*
     * Stage only absolute homes: a relative one would resolve against the
     * caller's working directory, not beside the account's home.
     */
    if (home[0] != '/') {
        return -1;
    }
    if (snprintf(parent, sizeof(parent), "%s", home) >= (int)sizeof(parent)) {
        return -1;
    }

    /* Drop a trailing slash so the home itself is not taken for its parent. */
    len = strlen(parent);
    while (len > 1 && parent[len - 1] == '/') {
        parent[--len] = '\0';
    }

    slash = strrchr(parent, '/');
    if (!slash || slash == parent) {
        return -1;
    }
    *slash = '\0';

    /*
     * Collapse slashes left by a base ending in '/', as in "/home//alice",
     * so the template stays a clean sibling path.
     */
    len = strlen(parent);
    while (len > 1 && parent[len - 1] == '/') {
        parent[--len] = '\0';
    }
    /* A home directly below the root has no parent to stage in. */
    if (parent[1] == '\0') {
        return -1;
    }

    n = snprintf(out, out_size, "%s/.ob-home.XXXXXX", parent);
    if (n < 0 || (size_t)n >= out_size) {
        return -1;
    }
    return 0;
}

/*
 * Move a staged home to its final path. rename() is atomic within a
 * filesystem, and refuses to replace a non-empty directory (ENOTEMPTY), so a
 * directory that appeared at the home path meanwhile is reported rather than
 * adopted. An empty directory there is replaced; it holds nothing to lose.
 */
static inline int home_dir_commit(const char *tmp, const char *home)
{
    return rename(tmp, home);
}

#endif /* OB_HOME_DIR_H */
