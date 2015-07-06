#include <slapi-plugin.h>

#include "oath.h"

int oath_config(OATHConfig *config, char *dn, Slapi_ComponentId *plugin_id) {

    int rc, nentries;
    Slapi_Entry **entries, *entry;
    Slapi_PBlock *pb = slapi_pblock_new();

    slapi_search_internal_set_pb(pb, dn, LDAP_SCOPE_SUBTREE, "(objectClass=oathConfig)", NULL, 0, NULL, NULL, plugin_id, 0);
    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);
    slapi_pblock_get(pb, SLAPI_NENTRIES, &nentries);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);

    if (rc == LDAP_SUCCESS && nentries > 0 && entries != NULL && (entry = *entries) != NULL)
        oath_config_from_entry(config, entry);

    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);

    return rc;

}

OATHConfig *oath_config_from_entry(OATHConfig *config, Slapi_Entry *e) {

    if (e != NULL && config != NULL) {

        Slapi_Attr *attr;

        if (slapi_entry_attr_find(e, "hotpLength", &attr) == 0)
            config->hotp_length = slapi_entry_attr_get_int(e, "hotpLength");

        if (slapi_entry_attr_find(e, "hotpTruncOffset", &attr) == 0)
            config->hotp_trunc_offset = slapi_entry_attr_get_int(e, "hotpTruncOffset");

        if (slapi_entry_attr_find(e, "hotpChecksum", &attr) == 0)
            config->hotp_checksum = slapi_entry_attr_get_int(e, "hotpChecksum");

        if (slapi_entry_attr_find(e, "hotpInnerWindow", &attr) == 0)
            config->hotp_inner_window = slapi_entry_attr_get_int(e, "hotpInnerWindow");

        if (slapi_entry_attr_find(e, "hotpOuterWindow", &attr) == 0)
            config->hotp_outer_window = slapi_entry_attr_get_int(e, "hotpOuterWindow");

        config->token_base = slapi_entry_attr_get_charptr(e, "oathTokens");

    }

    return config;

}

void oath_config_free(OATHConfig *config) {

    if (config->token_base)
        slapi_ch_free_string(&config->token_base);

}
