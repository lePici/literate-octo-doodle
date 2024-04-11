#define _GNU_SOURCE

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "sysrepo.h"
#include "rr_sysrepo.h"

#define RRSREX_ERR "ERROR rr_sysrepo_example: "
#define RRSREX_INFO "INFO rr_sysrepo_example: "
#define RRSREX_MAX_ARGS_COUNT 4

#define CHECK_RC(RC) \
    if (RC) { \
        goto cleanup; \
    }

#define CHECK_ARG(RC, STR) \
    if (RC == -1) { \
        fprintf(stderr, RRSREX_ERR "unknown argument \"%s\".\n", STR); \
        goto cleanup; \
    }

#define CHECK_ARG_IS_SET(ARG) \
    if (!ARG) { \
        rc = -1; \
        fprintf(stderr, RRSREX_ERR "wrong number of parameters.\n"); \
        goto cleanup; \
    }

void
print_help(void)
{
    printf("Usage:\n");
    printf("  rr_sysrepo_example <command> [arguments]\n");
    printf("  rr_sysrepo_example <command> [arguments] <command> [arguments] ...\n");
    printf("Example:\n");
    printf("  ./rr_sysrepo_example get-config running,/*\n");
    printf("  ./rr_sysrepo_example edit-config running,replace,set,data.xml get-config running,/*\n");
    printf("\nCommand and its arguments separated by a comma:\n");
    printf("  get-config DATASTORE,XPATH\n");
    printf("  get-config DATASTORE,FILE\n");
    printf("\t Retrieve all or part of a specified configuration.\n");
    printf("\t DATASTORE: candidate | running | startup\n");
    printf("\t XPATH: xpath expression\n");
    printf("\t FILE: contains a filter in 'subtree' format written in XML.\n");
    printf("  edit-config DATASTORE,DEFOP,TESTOP,FILE\n");
    printf("\t Loads all or part of a specified configuration to the specified target configuration.\n");
    printf("\t DATASTORE: candidate | running \n");
    printf("\t DEFOP: merge | replace | none \n");
    printf("\t TESTOP: set | test \n");
    printf("\t FILE: content for the edit command in XML format.\n");
    printf("  copy-config DST_DATASTORE,SRC_DATASTORE\n");
    printf("  copy-config DST_DATASTORE,FILE\n");
    printf("\t Create or replace a datastore.\n");
    printf("\t DST_DATASTORE: candidate | running | startup \n");
    printf("\t SRC_DATASTORE: candidate | running | startup \n");
    printf("\t FILE: content for the copy command operation in XML format\n");
    printf("  delete-config\n");
    printf("\t Delete the startup datastore.\n");
    printf("  lock DATASTORE\n");
    printf("\t Lock the datastore.\n");
    printf("\t DATASTORE: candidate | running | startup \n");
    printf("  unlock DATASTORE\n");
    printf("\t Unlock the datastore.\n");
    printf("\t DATASTORE: candidate | running | startup \n");
    printf("  get XPATH\n");
    printf("  get FILE\n");
    printf("\t Get the running datastore subset and/or state data that matched by filter.\n");
    printf("\t XPATH: xpath expression\n");
    printf("\t FILE: contains a filter in 'subtree' format written in XML.\n");
    printf("discard-changes\n");
    printf("\t Revert the candidate configuration to the current running configuration.\n");
    printf("validate DATASTORE\n");
    printf("\t Perform the validation a datastore.\n");
    printf("\t DATASTORE: candidate | running | startup \n");
    fflush(stdout);
}

void
process_arguments(char *tup, char *args[])
{
    char *token;
    uint32_t i;

    if (!tup) {
        return;
    }

    token = strtok(tup, ",");
    args[0] = token;
    for (i = 1; i < RRSREX_MAX_ARGS_COUNT; i++) {
        token = strtok(NULL, ",");
        if (token) {
            args[i] = token;
        } else {
            return;
        }
    }
}

int
parse_defop(char *str, rrsr_ec_default_operation_t *defop)
{
    if (!strncmp("merge", str, 5)) {
        *defop = RRSR_EC_MERGE;
    } else if (!strncmp("replace", str, 7)) {
        *defop = RRSR_EC_REPLACE;
    } else if (!strncmp("none", str, 4)) {
        *defop = RRSR_EC_NONE;
    } else {
        return -1;
    }

    return 0;
}

int
parse_testop(char *str, rrsr_ec_test_option_t *testop)
{
    if (!strncmp("set", str, 3)) {
        *testop = RRSR_EC_TEST_THEN_SET;
    } else if (!strncmp("test", str, 4)) {
        *testop = RRSR_EC_TEST_ONLY;
    } else {
        return -1;
    }

    return 0;
}

int
parse_datastore(char *str, sr_datastore_t *ds)
{
    if (!strncmp("startup", str, 7)) {
        *ds = SR_DS_STARTUP;
    } else if (!strncmp("running", str, 7)) {
        *ds = SR_DS_RUNNING;
    } else if (!strncmp("candidate", str, 9)) {
        *ds = SR_DS_CANDIDATE;
    } else if (!strncmp("operational", str, 11)) {
        *ds = SR_DS_OPERATIONAL;
    } else if (!strncmp("factory", str, 7)) {
        *ds = SR_DS_FACTORY_DEFAULT;
    } else {
        return -1;
    }

    return 0;
}

int
parse_data_from_file(const char *filepath, const struct ly_ctx *ctx, struct lyd_node **data)
{
    int rc;
    struct ly_in *in;
    int parse_flags;

    rc = ly_in_new_filepath(filepath, 0, &in);
    if (rc) {
        fprintf(stderr, RRSREX_ERR "Open file failed.\n");
        return -1;
    }
    parse_flags = LYD_PARSE_NO_STATE | LYD_PARSE_ONLY;
    rc = lyd_parse_data(ctx, NULL, in, LYD_XML, parse_flags, 0, data);
    if (rc) {
        fprintf(stderr, RRSREX_ERR "parse or validation failed.\n");
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    int rc = SR_ERR_OK, i;
    const struct ly_ctx *ctx;
    char *command, *argument;
    struct lyd_node *config = NULL, *data = NULL;
    struct ly_out *out = NULL;
    sr_datastore_t src_datastore, dst_datastore;
    rrsr_ec_default_operation_t defop;
    rrsr_ec_test_option_t testop;

    /* turn logging on */
    sr_log_stderr(SR_LL_WRN);
    ly_log_level(LY_LLWRN);

    rc = ly_out_new_file(stdout, &out);
    CHECK_RC(rc);

    /* connect to sysrepo */
    rc = sr_connect(0, &connection);
    CHECK_RC(rc);

    /* start session */
    rc = sr_session_start(connection, SR_DS_RUNNING, &session);
    CHECK_RC(rc);

    /* create data tree nodes */
    ctx = sr_session_acquire_context(session);

    for (i = 1; i < argc; ++i) {
        char *args[RRSREX_MAX_ARGS_COUNT] = {0};

        if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i]) || !strcmp("help", argv[i])) {
            print_help();
            break;
        }

        command = argv[i];
        argument = (i + 1) < argc ? argv[i + 1] : NULL; 

        if (!strcmp("get-config", command)) {
            process_arguments(argument, args);
            CHECK_ARG_IS_SET(args[1]);

            /* get data from datastore */
            rc = parse_datastore(args[0], &src_datastore);
            CHECK_ARG(rc, args[0]);
            if (access(args[1], F_OK) != 0) {
                /* arg0 = DATASTORE, arg1 = XPATH */
                /* arg1 is not file, so it must be xpath */
                rc = rrsr_get_config(session, src_datastore, args[1], &data);
                CHECK_RC(rc);
            } else {
                /* arg0 = DATASTORE, arg1 = FILE */
                /* arg1 is file and inside is filter in the 'subtree' format */
                rc = parse_data_from_file(args[1], ctx, &config);
                CHECK_RC(rc);
                rc = rrsr_get_config2(session, src_datastore, config, &data);
                CHECK_RC(rc);
            }

            /* print data from datastore */
            lyd_print_all(out, data, LYD_XML, 0);
            ly_print_flush(out);
            i++;
        } else if (!strcmp("edit-config", command)) {
            /* arg0 = DATASTORE, arg1 = DEFOP, arg2 = TESTOP, arg3 = FILE */
            process_arguments(argument, args);
            CHECK_ARG_IS_SET(args[3]);

            /* prepare arguments */
            rc = parse_datastore(args[0], &dst_datastore);
            CHECK_ARG(rc, args[0]);
            rc = parse_defop(args[1], &defop);
            CHECK_ARG(rc, args[1]);
            rc = parse_testop(args[2], &testop);
            CHECK_ARG(rc, args[2]);

            /* parse xml in the file and store it to 'config' */
            rc = parse_data_from_file(args[3], ctx, &config);
            CHECK_RC(rc);

            /* execute */
            rc = rrsr_edit_config(session, dst_datastore, defop, testop, config);
            CHECK_RC(rc);
            i++;
        } else if (!strcmp("copy-config", command)) {
            process_arguments(argument, args);
            CHECK_ARG_IS_SET(args[1]);

            rc = parse_datastore(args[0], &dst_datastore);
            CHECK_ARG(rc, args[0]);
            rc = parse_datastore(args[1], &src_datastore);
            if (rc >= 0) {
                /* arg0 = DATASTORE, arg1 = DATASTORE */
                /* arg1 is a source datastore */
                rc = rrsr_copy_config(session, dst_datastore, src_datastore);
                CHECK_RC(rc);
            } else {
                /* arg0 = DATASTORE, arg1 = FILE */
                /* arg1 is a file and inside is data to copy */
                rc = parse_data_from_file(args[1], ctx, &config);
                CHECK_RC(rc);
                rc = rrsr_copy_config2(session, dst_datastore, config);
                config = NULL;
                CHECK_RC(rc);
            }
            i++;
        } else if (!strcmp("delete-config", command)) {
            rc = rrsr_delete_config_startup(session);
            CHECK_RC(rc);
        } else if (!strcmp("lock", command)) {
            process_arguments(argument, args);
            CHECK_ARG_IS_SET(args[0]);
            rc = parse_datastore(args[0], &dst_datastore);
            CHECK_ARG(rc, args[0]);
            rc = rrsr_lock(session, dst_datastore);
            if (rc) {
                printf(RRSREX_ERR "unable to lock datastore because it is already locked.\n");
            } else {
                printf(RRSREX_INFO "datastore is locked.\n");
            }
            CHECK_RC(rc);
            i++;
        } else if (!strcmp("unlock", command)) {
            process_arguments(argument, args);
            CHECK_ARG_IS_SET(args[0]);
            rc = parse_datastore(args[0], &dst_datastore);
            CHECK_ARG(rc, args[0]);
            rc = rrsr_unlock(session, dst_datastore);
            CHECK_RC(rc);
            printf(RRSREX_INFO "datastore is unlocked.\n");
            i++;
        } else if (!strcmp("get", command)) {
            process_arguments(argument, args);
            CHECK_ARG_IS_SET(args[0]);

            /* get data from datastore */
            if (access(args[0], F_OK) != 0) {
                /* arg0 = XPATH */
                /* arg0 is not file, so it must be xpath */
                rc = rrsr_get(session, args[0], &data);
                CHECK_RC(rc);
            } else {
                /* arg0 = FILE */
                /* arg0 is file and inside is filter in the 'subtree' format */
                rc = parse_data_from_file(args[0], ctx, &config);
                CHECK_RC(rc);
                rc = rrsr_get2(session, config, &data);
                CHECK_RC(rc);
            }

            /* print data */
            lyd_print_all(out, data, LYD_XML, 0);
            ly_print_flush(out);
            i++;
        } else if (!strcmp("discard-changes", command)) {
            rc = rrsr_discard_changes(session);
            CHECK_RC(rc);
        } else if (!strcmp("validate", command)) {
            process_arguments(argument, args);
            CHECK_ARG_IS_SET(args[0]);
            rc = parse_datastore(args[0], &src_datastore);
            CHECK_ARG(rc, args[0]);
            rc = rrsr_validate(session, src_datastore);
            if (rc) {
                printf(RRSREX_INFO "datastore is not valid\n");
            } else {
                printf(RRSREX_INFO "datastore is valid.\n");
            }
            CHECK_RC(rc);
            i++;
        } else {
            printf("Unknown command: %s\n", command);
            break;
        }
    }

cleanup:
    lyd_free_all(config);
    lyd_free_all(data);
    ly_out_free(out, NULL, 0);
    sr_disconnect(connection);
    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
