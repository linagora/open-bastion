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
 * Returns 0 when `out` holds the template, -1 for a home with no usable
 * parent (relative path, or a single leading slash).
 */
static inline int home_dir_temp_template(const char *home, char *out, size_t out_size)
{
    char parent[PATH_MAX];
    char *slash;
    int n;

    if (!home || !*home || !out || out_size == 0) {
        return -1;
    }
    if (snprintf(parent, sizeof(parent), "%s", home) >= (int)sizeof(parent)) {
        return -1;
    }

    slash = strrchr(parent, '/');
    if (!slash || slash == parent) {
        return -1;
    }
    *slash = '\0';

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
