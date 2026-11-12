/*
 * test_username_validator.c - ob_valid_username(), the one user-name grammar
 *
 * The named cases come from tests/username_corpus.txt, which
 * test_ob_username_grammar.sh also runs through the regular expression of the
 * shell scripts: both sides must give the same verdict on every line.
 */

#include <locale.h>
#include <stdio.h>
#include <string.h>

#include "str_utils.h"

static int tests_run = 0;
static int tests_failed = 0;

static void check(int cond, const char *what, const char *name)
{
    tests_run++;
    if (!cond) {
        tests_failed++;
        printf("  FAIL: %s: \"%s\"\n", what, name);
    }
}

static void run_corpus(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        tests_failed++;
        return;
    }
    char line[256];
    int cases = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
        char *name = strchr(line, ' ');
        if (!name) {
            printf("  malformed corpus line: %s\n", line);
            tests_failed++;
            continue;
        }
        *name++ = '\0';
        if (strcmp(line, "valid") == 0) {
            check(ob_valid_username(name), "should be accepted", name);
        } else if (strcmp(line, "invalid") == 0) {
            check(!ob_valid_username(name), "should be refused", name);
        } else {
            printf("  unknown verdict: %s\n", line);
            tests_failed++;
        }
        cases++;
    }
    fclose(f);
    printf("  %d corpus cases\n", cases);
    check(cases > 0, "the corpus is not empty", path);
}

int main(int argc, char **argv)
{
    const char *corpus = argc > 1 ? argv[1] : OB_USERNAME_CORPUS;

    printf("Username grammar ^[a-z_][a-z0-9_.-]{0,31}$\n");
    run_corpus(corpus);

    /* Cases a line-based corpus cannot carry. */
    check(!ob_valid_username(NULL), "NULL refused", "(null)");
    check(!ob_valid_username(""), "empty refused", "");
    check(!ob_valid_username("alice\nroot:0:0"), "newline refused",
          "alice\\nroot:0:0");
    check(!ob_valid_username("alice\rroot"), "carriage return refused",
          "alice\\rroot");
    check(!ob_valid_username("alice\tbob"), "tab refused", "alice\\tbob");

    char huge[4096];
    memset(huge, 'a', sizeof(huge) - 1);
    huge[sizeof(huge) - 1] = '\0';
    check(!ob_valid_username(huge), "4095 characters refused", "a...a");

    /* In a single-byte locale islower() accepts accented letters; the grammar
     * must not depend on the locale of the process that loads the module. */
    if (setlocale(LC_CTYPE, "fr_FR.ISO-8859-1") ||
        setlocale(LC_CTYPE, "en_US.ISO-8859-1")) {
        check(!ob_valid_username("j\xe9r\xf4me"), "Latin-1 letters refused",
              "j\\xe9r\\xf4me");
    }
    check(!ob_valid_username("j\xe9r\xf4me"), "high bytes refused",
          "j\\xe9r\\xf4me");

    printf("%d/%d checks passed\n", tests_run - tests_failed, tests_run);
    return tests_failed == 0 ? 0 : 1;
}
