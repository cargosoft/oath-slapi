#include <slapi-plugin.h>
#include <stdio.h>

#include "oath.h"

static int argc;
static char **argv;

static Slapi_PluginDesc oath_preop_plugin_desc = {
    "oath-preop-plugin",
    "CargoSoft",
    "0.1",
    "Support simple authentication with OATH compliant OTP tokens"
};

static Slapi_ComponentId *oath_preop_plugin_id;

static OATHConfig oath_preop_config = {
    .hotp_length = 6,
    .hotp_trunc_offset = -1,
    .hotp_checksum = 0,
    .hotp_inner_window = 10,
    .hotp_outer_window = 100,
    .token_base = NULL
};

int oath_preop_bind(Slapi_PBlock *pb) {

    char *dn;
    const char *creds;
    int creds_len, hotp_len = oath_preop_config.hotp_length, pin_len, method, rc = LDAP_SUCCESS, handled = 1;
    struct berval *credentials;
    Slapi_Value *sv_creds = NULL;
    Slapi_PBlock *upb, *tpb; // PBlocks for user and token searches
    Token token;

    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind\n");

    if (slapi_pblock_get(pb, SLAPI_BIND_METHOD, (void *) &method) != 0 ||
            slapi_pblock_get(pb, SLAPI_BIND_TARGET, (void *) &dn) != 0 ||
            slapi_pblock_get(pb, SLAPI_BIND_CREDENTIALS, (void *) &credentials) != 0) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: Could not get parameters for bind operation\n");
        slapi_send_ldap_result(pb, LDAP_OPERATIONS_ERROR, NULL, NULL, 0, NULL);
        return 1;
    }

    switch (method) {

        case LDAP_AUTH_SIMPLE:

            rc = LDAP_SUCCESS;
            sv_creds = slapi_value_new_berval(credentials);
            creds = slapi_value_get_string(sv_creds);
            creds_len = creds ? strlen(creds) : 0;

            Slapi_Entry **entries, *entry;
            int nentries = 0;

            upb = slapi_pblock_new();
            slapi_search_internal_set_pb(upb, dn, LDAP_SCOPE_SUB, "(objectClass=*)", NULL, 0, NULL, NULL, oath_preop_plugin_id, 0);
            slapi_search_internal_pb(upb);
            slapi_pblock_get(upb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
            slapi_pblock_get(upb, SLAPI_NENTRIES, &nentries);
            slapi_pblock_get(upb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);

            if (rc == LDAP_SUCCESS && nentries > 0 && entries != NULL && (entry = *entries) != NULL) {

                char filter[1024], *attrs[] = {"tokenSerial", "tokenSeed", "tokenCounter", "tokenPIN", NULL};
                Slapi_Entry **tokens;
                int ntokens = 0;

                slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: Authenticating DN: %s\n", dn);

                // search for tokens

                snprintf(filter, 1024, "(&(objectClass=oathToken)(tokenOwner=%s))", dn);

                tpb = slapi_pblock_new();
                slapi_search_internal_set_pb(tpb, oath_preop_config.token_base, LDAP_SCOPE_SUBTREE, filter, attrs, 0, NULL, NULL, oath_preop_plugin_id, 0);
                slapi_search_internal_pb(tpb);
                slapi_pblock_get(tpb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
                slapi_pblock_get(tpb, SLAPI_NENTRIES, &ntokens);
                slapi_pblock_get(tpb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &tokens);

                if (rc == LDAP_SUCCESS && ntokens > 0 && tokens != NULL) {

                    int t, w;
                    unsigned char hotp[hotp_len + 1];

                    for (t = 0; t < ntokens; t++) {

                        oath_token_from_entry(&token, tokens[t]);

                        pin_len = token.pin ? strlen(token.pin) : 0;

                        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: Found token: %s\n", token.serial);

                        if (pin_len + hotp_len != creds_len)
                            slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: Credentials length did not match\n");

                        else if (token.pin && strncmp(creds, token.pin, pin_len))
                            slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: PIN did not match\n");

                        else for (w = 0; w < oath_preop_config.hotp_inner_window; w++) {

                            if (oath_hotp(hotp, hotp_len, token.seed->bv_val, token.seed->bv_len, token.counter + w, oath_preop_config.hotp_trunc_offset, oath_preop_config.hotp_checksum)) {

                                // slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: hotp(%d) =  %s\n", token.counter + w, hotp);

                                if (!strncmp(hotp, creds + pin_len, hotp_len)) {

                                    // success
                                    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: hotp(%d) =  %s\n", token.counter + w, hotp);

                                    if (oath_update_token(tokens[t], token.counter + w + 1) != 0) {
                                        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: Failed to update token entry\n");
                                        rc = LDAP_OPERATIONS_ERROR;
                                    };

                                    // OpenLDAP does not support setting SLAPI_CONN_DN and SLAPI_CONN_AUTHMETHOD

/*
                                    if (slapi_pblock_set(pb, SLAPI_CONN_DN, slapi_ch_strdup(dn)) != 0 ||
                                            slapi_pblock_set(pb, SLAPI_CONN_AUTHMETHOD, SLAPD_AUTH_SIMPLE) != 0) {
                                        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: Failed to set DN and auth method for connection\n", dn);
                                        rc = LDAP_OPERATIONS_ERROR;
                                    }
*/

                                    goto free_tpb;

                                }

                            } else {
                                // HOTP error
                                slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: HOTP error for token %s\n", token.serial);
                                break;
                            }

                        }

                        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: Token %s did not match\n", token.serial);
                        oath_token_free(&token);

                    }

                    // No token matched

                    handled = 0;
                    goto free_tpb;

                } else { // no tokens associated

                    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: DN %s has got no token(s) associated, rc = %d\n", dn, rc);
                    handled = 0;
                    goto free_upb;

                }


            } else {

                // entry not found; don't fail because this can be root (directory manager) DN

                slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_bind: DN %s not found\n", dn);

                if (rc == LDAP_SUCCESS)
                    rc = LDAP_OPERATIONS_ERROR;
                else
                    handled = 0;

                goto free_upb;

            }

            break;

        case LDAP_AUTH_NONE:
        case LDAP_AUTH_SASL:
        default:
            slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_bind_preop: Authentication type not supported: %d", method);
            return 0;

    }

free_tpb:
    oath_token_free(&token);
    slapi_free_search_results_internal(tpb);
    slapi_pblock_destroy(tpb);

free_upb:
    slapi_free_search_results_internal(upb);
    slapi_pblock_destroy(upb);

    slapi_value_free(&sv_creds);

    if (handled) {
        slapi_send_ldap_result(pb, rc, NULL, NULL, 0, NULL);
        return 1;
    } else
        return 0;

}

int oath_preop_start(Slapi_PBlock *pb) {

    int rc = oath_config(&oath_preop_config, argv[0], oath_preop_plugin_id);

    if (rc)
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_start: Failed to load configuration (%s), using defaults\n", ldap_err2string(rc));
    else
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_start: Successfully loaded configuration\n");

    return 0;

}

int oath_preop_close(Slapi_PBlock *pb) {

    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_close: Freeing configuration\n");

    oath_config_free(&oath_preop_config);

    return 0;

}

int oath_preop_init(Slapi_PBlock *pb) {

    int rc;

    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &oath_preop_plugin_id);

    if (slapi_pblock_get(pb, SLAPI_PLUGIN_ARGC, (void *) &argc) != 0 ||
            slapi_pblock_get(pb, SLAPI_PLUGIN_ARGV, (void *) &argv)) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_init: Failed to obtain plugin args, not registering plugin\n");
        return -1;
    }

    if (argc < 1) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_init: No configuration given, not registering plugin\n");
        return -1;
    }

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03) != 0 ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *) &oath_preop_plugin_desc) != 0 ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_BIND_FN, (void *) oath_preop_bind) != 0 ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN, (void *) oath_preop_start) != 0 ||
            slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN, (void *) oath_preop_close) != 0) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath",
                "oath_preop_init: Error registering plugin\n");
        return -1;
    }

    slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_preop_init: Plugin successfully registered\n");

    return 0;

}

Token *oath_token_from_entry(Token *token, Slapi_Entry *e) {

    if (e != NULL && token != NULL) {

        Slapi_Attr *seed;

        token->serial = slapi_entry_attr_get_charptr(e, "tokenSerial");
        token->pin = slapi_entry_attr_get_charptr(e, "tokenPIN");
        token->counter = slapi_entry_attr_get_long(e, "tokenCounter");

        slapi_entry_attr_find(e, "tokenSeed", &seed);

        if (seed != NULL) {
            struct berval *bval;
            Slapi_Value *sval;
            slapi_attr_first_value(seed, &sval);
            bval = slapi_value_get_berval(sval);
            token->seed = ber_bvdup(bval);
        }

    }

    return token;

}

void oath_token_free(Token *token) {

    if (token->pin) {
        slapi_ch_free_string(&token->pin);
        token->pin = NULL;
    }

    if (token->serial) {
        slapi_ch_free_string(&token->serial);
        token->serial = NULL;
    }

    if (token->seed) {
        ber_bvfree(token->seed);
        token->seed = NULL;
    }

}

int oath_update_token(Slapi_Entry *e, long i) {

    char *dn, value[22], *values[2] = {value, NULL};
    int rc = LDAP_SUCCESS;
    Slapi_PBlock *pb;

    snprintf(value, 22, "%d", i);

    LDAPMod mod = {
        .mod_op = LDAP_MOD_REPLACE,
        .mod_type = "tokenCounter",
        .mod_values = values
    };

    LDAPMod *mods[] = {&mod, NULL};

    dn = slapi_entry_get_dn(e);
    pb = slapi_pblock_new();
    slapi_modify_internal_set_pb(pb, dn, mods, NULL, NULL, oath_preop_plugin_id, 0);

    if (slapi_modify_internal_pb(pb) != 0) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "oath", "oath_update_token: Failed to update token\n");
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    }

    slapi_pblock_destroy(pb);

    return rc;

}
