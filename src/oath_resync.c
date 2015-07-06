#include <lber.h>
#include <slapi-plugin.h>
#include <stdio.h>

#include "oath.h"

#define OATH_RESYNC_EXOP_REQUEST_OID  "1.3.6.1.4.1.38409.2.11.1"
#define OATH_RESYNC_EXOP_RESPONSE_OID "1.3.6.1.4.1.38409.2.11.2"

static int argc;
static char **argv;

static Slapi_PluginDesc oath_exop_plugin_desc = {
    "oath-exop-plugin",
    "CargoSoft",
    "0.1",
    "Support resynchronization for OATH compliant OTP tokens"
};

static Slapi_ComponentId *oath_exop_plugin_id;

static OATHConfig oath_exop_config = {
    .hotp_length = 6,
    .hotp_trunc_offset = -1,
    .hotp_checksum = 0,
    .hotp_inner_window = 10,
    .hotp_outer_window = 300,
    .token_base = NULL
};

static char *oath_exop_oid_list[] = {
    OATH_RESYNC_EXOP_REQUEST_OID,
    NULL
};

int oath_exop(Slapi_PBlock *pb) {

    int rc = SLAPI_PLUGIN_EXTENDED_NOT_HANDLED;
    struct berval *reqdata = NULL, *respdata = NULL;
    BerElement *reqber = NULL, *respber = NULL;
    char *dn = NULL, *otp1 = NULL, *otp2 = NULL;
    char *reqoid = NULL, *respoid = OATH_RESYNC_EXOP_RESPONSE_OID;
    Slapi_PBlock *upb = NULL, *tpb = NULL;
    Slapi_Entry **entries, *entry;
    int nentries = 0;
    int hotp_len = oath_exop_config.hotp_length;
    int w;
    Token token;

    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "--> oath_exop");

    slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_OID, &reqoid);

    if (!reqoid) {
        slapi_log_error(SLAPI_LOG_FATAL, "oath", "oath_exop: Cannot retrieve request OID");
        goto free_ber;
    }

    if (strcmp(reqoid, OATH_RESYNC_EXOP_REQUEST_OID)) {
        slapi_log_error(SLAPI_LOG_FATAL, "oath", "oath_exop: Invalid request OID");
        goto free_ber;
    }

    slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_VALUE, &reqdata);

    if (!reqdata || !reqdata->bv_val) {
        slapi_log_error(SLAPI_LOG_FATAL, "oath", "oath_exop: No request data received\n");
        goto free_ber;
    }

    if (!(reqber = ber_init(reqdata))) {
        slapi_log_error(SLAPI_LOG_FATAL, "oath", "oath_exop: Failed to decode request data\n");
        goto free_ber;
    }

    if (ber_scanf(reqber, "{aaa}", &dn, &otp1, &otp2) == LBER_ERROR) {
        slapi_log_error(SLAPI_LOG_FATAL, "oath", "oath_exop: Failed to parse request data\n");
        rc = LDAP_PROTOCOL_ERROR;
        goto free_ber;
    }

    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop: Received request:\nDN = %s\nOTP1 = %s\nOTP2 = %s\n", dn, otp1, otp2);

    // GO!
    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop: Token base = %s\n", oath_exop_config.token_base);

    upb = slapi_pblock_new();
    slapi_search_internal_set_pb(upb, dn, LDAP_SCOPE_SUB, "(objectClass=*)", NULL, 0, NULL, NULL, oath_exop_plugin_id, 0);
    slapi_search_internal_pb(upb);
    slapi_pblock_get(upb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    slapi_pblock_get(upb, SLAPI_NENTRIES, &nentries);
    slapi_pblock_get(upb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);

    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop: found %d entries\n", nentries);

    if (rc == LDAP_SUCCESS && nentries > 0 && entries != NULL && (entry = *entries) != NULL) {

        char filter[1024], *attrs[] = {"tokenSerial", "tokenSeed", "tokenCounter", "tokenPIN", NULL};
        Slapi_Entry **tokens;
        int ntokens = 0;

        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop: Resynchronizing DN: %s\n", dn);

        // search for tokens

        snprintf(filter, 1024, "(&(objectClass=oathToken)(tokenOwner=%s))", dn);

        tpb = slapi_pblock_new();
        slapi_search_internal_set_pb(tpb, oath_exop_config.token_base, LDAP_SCOPE_SUBTREE, filter, attrs, 0, NULL, NULL, oath_exop_plugin_id, 0);
        slapi_search_internal_pb(tpb);
        slapi_pblock_get(tpb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
        slapi_pblock_get(tpb, SLAPI_NENTRIES, &ntokens);
        slapi_pblock_get(tpb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &tokens);

        if (rc == LDAP_SUCCESS && ntokens > 0 && tokens != NULL) {

            int t;
            unsigned char hotp[hotp_len + 1];

            for (t = 0; t < ntokens; t++) {

                oath_token_from_entry(&token, tokens[t]);

                slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop: Found token: %s\n", token.serial);

                if (strlen(otp1) != hotp_len || strlen(otp2) != hotp_len)
                    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop: OTP length did not match\n");

                else for (w = 0; w < oath_exop_config.hotp_outer_window; w++) {

                        if (!oath_hotp(hotp, hotp_len, token.seed->bv_val, token.seed->bv_len, token.counter + w, oath_exop_config.hotp_trunc_offset, oath_exop_config.hotp_checksum))
                            goto hotp_error;

                        if (strncmp(hotp, otp1, hotp_len))
                            continue;

                        if (!oath_hotp(hotp, hotp_len, token.seed->bv_val, token.seed->bv_len, token.counter + w + 1, oath_exop_config.hotp_trunc_offset, oath_exop_config.hotp_checksum))
                            goto hotp_error;

                        if (strncmp(hotp, otp2, hotp_len))
                            continue;

                        // success

                        if (oath_update_token(tokens[t], token.counter + w + 2) != 0) {
                            slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop: Failed to update token entry\n");
                            rc = LDAP_OPERATIONS_ERROR;
                        };

                        goto send_response;

                        // HOTP error
hotp_error:
                        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop: HOTP error for token %s\n", token.serial);
                        break;

                    }

                slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop: Token %s did not match\n", token.serial);
                oath_token_free(&token);

            }

            // No token matched
            rc = SLAPI_PLUGIN_EXTENDED_NOT_HANDLED;
            goto free_ber;

        } else { // no tokens associated

            slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop: DN %s has got no token(s) associated, rc = %d\n", dn, rc);
            rc = SLAPI_PLUGIN_EXTENDED_NOT_HANDLED;
            // XXX: should send LDAP_NO_SUCH_OBJECT
            goto free_ber;

        }

    } else {

        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop: %s not found\n", dn);
        rc = SLAPI_PLUGIN_EXTENDED_NOT_HANDLED;
        // XXX: should send LDAP_NO_SUCH_OBJECT
        goto free_ber;

    }

    // Send response

send_response:

    if ((respber = ber_alloc()) == NULL) {
        rc = LDAP_NO_MEMORY;
        goto free_ber;
    }

    if (ber_printf(respber, "{si}", token.serial, token.counter + w + 2) == LBER_ERROR) {
        slapi_log_error(SLAPI_LOG_FATAL, "oath", "oath_exop: Unable to encode response\n");
        ber_free(respber, 1);
        rc = LDAP_ENCODING_ERROR;
        goto free_ber;
    }

    oath_token_free(&token);

    ber_flatten(respber, &respdata);
    ber_free(respber, 1);

    slapi_pblock_set(pb, SLAPI_EXT_OP_RET_OID, respoid);
    slapi_pblock_set(pb, SLAPI_EXT_OP_RET_VALUE, respdata);

    slapi_send_ldap_result(pb, rc, NULL, NULL, 0, NULL);
    rc = SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
    ber_bvfree(respdata);

free_ber:
    ber_memfree(dn);
    ber_memfree(otp1);
    ber_memfree(otp2);
    if (reqber) ber_free(reqber, 1);

    if (tpb) {
        slapi_free_search_results_internal(tpb);
        slapi_pblock_destroy(tpb);
    }

    if (upb) {
        slapi_free_search_results_internal(upb);
        slapi_pblock_destroy(upb);
    }

    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "<-- oath_exop (rc = %d)\n", rc);

    return rc;

}

int oath_exop_start(Slapi_PBlock *pb) {

    int rc = oath_config(&oath_exop_config, argv[0], oath_exop_plugin_id);

    if (rc)
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop_start: Failed to load configuration (%s), using defaults\n", ldap_err2string(rc));
    else
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop_start: Successfully loaded configuration\n");

    return 0;

}

int oath_exop_close(Slapi_PBlock *pb) {

    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop_close: Freeing configuration\n");

    oath_config_free(&oath_exop_config);

    return 0;

}

int oath_exop_init(Slapi_PBlock *pb) {

    int rc;

    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &oath_exop_plugin_id);

    if (slapi_pblock_get(pb, SLAPI_PLUGIN_ARGC, (void *) &argc) != 0 ||
            slapi_pblock_get(pb, SLAPI_PLUGIN_ARGV, (void *) &argv)) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop_init: Failed to obtain plugin args, not registering plugin\n");
        return -1;
    }

    if (argc < 1) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop_init: No configuration given, not registering plugin\n");
        return -1;
    }

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03) != 0 ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *) &oath_exop_plugin_desc) != 0 ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, (void *) oath_exop_oid_list) != 0 ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *) oath_exop) != 0 ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN, (void *) oath_exop_start) != 0 ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN, (void *) oath_exop_close) != 0) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop_init: Error registering plugin\n");
        return -1;
    }

    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_exop_init: Plugin successfully registered\n");

    return 0;

}
