package com.xwiki.authentication.saml;

import org.xwiki.configuration.ConfigurationSource;

public class XwikiAuthConfig {
    private static final String DEFAULT_AUTH_FIELD = "saml_user";
    private static final String DEFAULT_FIELDS_MAPPING = "email=email,first_name=firstName,last_name=lastName";
    private static final String DEFAULT_XWIKI_USERNAME_RULE = "first_name,last_name";
    private static final String DEFAULT_XWIKI_USERNAME_RULE_CAPITALIZE = "true";

    private final static String PROPERTY_PREFIX = "xwiki.authentication.saml2.";
    private static final String DEFAULT_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    public static final String DEFAULT_GROUP_FOR_NEW_USERS = "XWiki.SamlUsers";

    public final String entityId;
    public final String assertionConsumerServiceUrl;
    public final String nameIdFormat;
    public final String idpEntityId;
    public final String idpSingleSignOnUrl;
    public final String x509Certificate;
    public final String defaultGroupForNewUsers;
    public final String[] fieldMapping;
    public final String authFieldName;
    public final String[] userNameRule;
    public final boolean shouldCapitalizeUserNames;
    public final boolean allowLoginFallback;

    public XwikiAuthConfig(
            String spEntityId,
            String assertionConsumerServiceUrl,
            String nameIdFormat,
            String idpEntityId,
            String idpSingleSignOnUrl,
            String x509Certificate,
            String defaultGroupForNewUsers,
            String[] fieldMapping,
            String authFieldName,
            String[] userNameRule,
            boolean shouldCapitalizeUserNames,
            boolean allowLoginFallback
            ) {
        this.entityId = spEntityId;
        this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
        this.nameIdFormat = nameIdFormat;
        this.idpEntityId = idpEntityId;
        this.idpSingleSignOnUrl = idpSingleSignOnUrl;
        this.x509Certificate = x509Certificate;
        this.defaultGroupForNewUsers = defaultGroupForNewUsers;
        this.fieldMapping = fieldMapping;
        this.authFieldName = authFieldName;
        this.userNameRule = userNameRule; 
        this.shouldCapitalizeUserNames = shouldCapitalizeUserNames;
        this.allowLoginFallback = allowLoginFallback;
    }

    public static XwikiAuthConfig from(ConfigurationSource cfg) {
        return new XwikiAuthConfig(
            property(cfg, "sp.entityid"),
            property(cfg, "sp.assertion_consumer_service.url"),
            property(cfg, "sp.nameidformat", DEFAULT_NAMEID_FORMAT),
            property(cfg, "idp.entityid"),
            property(cfg, "idp.single_sign_on_service.url"),
            property(cfg, "idp.x509cert"),
            property(cfg, "default_group_for_new_users", DEFAULT_GROUP_FOR_NEW_USERS),
            property(cfg, "fields_mapping", DEFAULT_FIELDS_MAPPING).split(","),
            property(cfg, "auth_field", DEFAULT_AUTH_FIELD),
            property(cfg, "xwiki_user_rule", DEFAULT_XWIKI_USERNAME_RULE).split(","),
            property(cfg, "xwiki_user_rule_capitalize", DEFAULT_XWIKI_USERNAME_RULE_CAPITALIZE).equalsIgnoreCase("true"),
            property(cfg, "allow_login_fallback", "true").equalsIgnoreCase("true")
        );
    }

    private static <T> T property(ConfigurationSource cfg, String propertyName) {
        return cfg.getProperty(PROPERTY_PREFIX + propertyName);
    }
    private static <T> T property(ConfigurationSource cfg, String propertyName, T defaultValue) {
        return cfg.getProperty(PROPERTY_PREFIX + propertyName, defaultValue);
    }
}
