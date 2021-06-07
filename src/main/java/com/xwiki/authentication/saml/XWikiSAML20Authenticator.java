/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.xwiki.authentication.saml;

import com.onelogin.saml2.Auth;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseProperty;
import com.xpn.xwiki.objects.StringProperty;
import com.xpn.xwiki.objects.classes.StringClass;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.Utils;
import com.xpn.xwiki.web.XWikiRequest;
import com.xpn.xwiki.web.XWikiResponse;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.model.EntityType;
import org.xwiki.model.ModelConfiguration;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.rendering.syntax.Syntax;

import java.io.IOException;
import java.util.*;

import static java.util.Arrays.asList;
import static org.apache.commons.compress.utils.Sets.newHashSet;
import static org.apache.commons.lang3.ObjectUtils.defaultIfNull;

/**
 * Authentication using a SAML 2.0 server. The following parameters are needed for customizing its behavior in xwiki.cfg:
 * <dl>
 * <dt>xwiki.authentication.saml2.idp.single_sign_on_service.url</dt>
 * <dd>The url to the IdP authentication URL</dd>
 * <dd>required; example: {@code  https://accounts.google.com/o/saml2/idp?idpid=}</dd>
 * <dt>xwiki.authentication.saml2.sp.entityid</dt>
 * <dd>An identifier for the application that will be also configured on the IdP. Can be any unique string</dd>
 * <dd>required</dd>
 * <dt>xwiki.authentication.saml2.idp.x509cert</dt>
 * <dd>The IdP certificate. For multiple lines, add \ at the line break</dd>
 * <dd>required</dd>
 * <dt>xwiki.authentication.saml2.sp.assertion_consumer_service.url</dt>
 * <dd>The ACS link (link to the login submit page)</dd>
 * <dd>required; https://<you wiki domain>/bin/loginsubmit/XWiki/XWikiLogin</dd>
 * <dt>xwiki.authentication.saml2.idp.entityid</dt>
 * <dd>service provider issuer or entityid url</dd>
 * <dd>required; example: {@code https://accounts.google.com/o/saml2?idpid}</dd>
 * <dt>xwiki.authentication.saml2.sp.nameidformat</dt>
 * <dd>the {@code nameidformat} used as a login key</dd>
 * <dd>optional; example: {@code urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress}</dd>
 * <dt>xwiki.authentication.saml2.fields_mapping</dt>
 * <dd>mapping between {@code XWikiUsers} fields and SAML fields</dd>
 * <dd>optional; default value: {@code email=email,first_name=firstName,last_name=lastName}</dd>
 * <dt>xwiki.authentication.saml2.auth_field</dt>
 * <dd>the name of the attribute used to cache the authentication result in the current session</dd>
 * <dd>optional; default value: {@code saml_user}</dd>
 * <dt>xwiki.authentication.saml2.xwiki_user_rule</dt>
 * <dd>list of fields to use for generating an XWiki username</dd>
 * <dd>optional; default value: {@code first_name,last_name}</dd>
 * <dt>xwiki.authentication.saml2.xwiki_user_rule_capitalize</dt>
 * <dd>capitalize each field value when generating the username</dd>
 * <dd>optional; default value: {@code true}; any other value is treated as {@code false}</dd>
 * <dd>xwiki.authentication.saml2.defaultGroupForNewUsers</dd>
 * <dd>The group where new users will be added</dd>
 * <dt>optional; default value {@code XWiki.SamlUsers}</dt>
 * </dl>
 *
 * @version $Id$
 */
public class XWikiSAML20Authenticator extends XWikiAuthServiceImpl
{
    private static final Logger LOG = LoggerFactory.getLogger(XWikiSAML20Authenticator.class);

    private static final String REQUEST_ID_SESSION_KEY = "saml20_id";
    private static final String ORIGINAL_URL_SESSION_KEY = "saml20_url";
    private static final String SAML_ID_XPROPERTY_NAME = "nameid";

    private static final EntityReference PROFILE_PARENT = new EntityReference("XWikiUsers", EntityType.DOCUMENT,
        new EntityReference(XWiki.SYSTEM_SPACE, EntityType.SPACE));

    private static final EntityReference SAML_XCLASS = new EntityReference("SAMLAuthClass", EntityType.DOCUMENT,
        new EntityReference(XWiki.SYSTEM_SPACE, EntityType.SPACE));

    private static final EntityReference USER_XCLASS = PROFILE_PARENT;

    @SuppressWarnings("deprecation")
    private final DocumentReferenceResolver<String> currentMixedDocumentReferenceResolver =
        Utils.getComponent(DocumentReferenceResolver.TYPE_STRING, "currentmixed");

    @SuppressWarnings("deprecation")
    private final EntityReferenceSerializer<String> compactStringEntityReferenceSerializer =
        Utils.getComponent(EntityReferenceSerializer.TYPE_STRING, "compactwiki");

    @SuppressWarnings("deprecation")
    private final ModelConfiguration defaultReference = Utils.getComponent(ModelConfiguration.class);

    @SuppressWarnings("deprecation")
    private final ConfigurationSource configurationSource = Utils.getComponent(ConfigurationSource.class, "xwikicfg");

    private final XwikiAuthConfig authConfig;

    private Map<String, String> userPropertiesMapping;

    private final Saml2Settings samlSettings;

    private final XWikiGroupUtils xWikiGroupUtils;

    public XWikiSAML20Authenticator() {
        xWikiGroupUtils = new XWikiGroupUtils(currentMixedDocumentReferenceResolver);
        authConfig = XwikiAuthConfig.from(configurationSource);

        samlSettings = buildSamlSettings();
    }

    @Override
    public void showLogin(XWikiContext context) throws XWikiException
    {
        final XWikiRequest request = context.getRequest();

        final String randId = RandomStringUtils.randomAlphanumeric(42);
        request.getSession().setAttribute(REQUEST_ID_SESSION_KEY, randId);
        LOG.debug("Random ID: [{}]", randId);

        // Remember the requested URL, so we can return to it afterwards
        final String sourceUrl = getSourceUrl(context, request);

        request.getSession().setAttribute(ORIGINAL_URL_SESSION_KEY, sourceUrl);
    }

    private String getSourceUrl(XWikiContext context, XWikiRequest request) throws XWikiException {
        final String sourceUrl = request.getParameter("xredirect");
        if (sourceUrl != null)
            return request.getContextPath() + "/" + sourceUrl;

        if (context.getAction().startsWith("login"))
            return context.getWiki().getURL(new DocumentReference(context.getWikiId(),
                this.defaultReference.getDefaultReferenceValue(EntityType.SPACE),
                this.defaultReference.getDefaultReferenceValue(EntityType.DOCUMENT)), "view", context);

        return XWiki.getRequestURL(request).toString();
    }

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        final XWikiRequest request = context.getRequest();
        final XWikiResponse response = context.getResponse();

        final String samlUserName = getSAMLAuthenticatedUserFromSession(context);
        if (samlUserName != null) {
            LOG.debug("Found authenticated user [{}]", samlUserName);
            return new XWikiUser(getUserReferenceForName(samlUserName), context.isMainWiki());
        }
        final String samlResponse = request.getParameter("SAMLResponse");
        final boolean hasSamlResponse = samlResponse != null;
        if (!hasSamlResponse) {
            final String action = context.getAction();
            if (asList("login", "skin", "ssx").contains(action))
                return super.checkAuth(context);

            if (context.getRequest().getCookie("username") != null
                    || action.equals("logout")
                    || action.equals("loginsubmit")) {
                LOG.debug("Fallback to standard authentication");
                return super.checkAuth(context);
            }
        }

        try {
            if (LOG.isDebugEnabled())
                LOG.debug("SAML 2.0 Authentication redirection started");

            final Auth auth = new Auth(this.samlSettings, request, response);

            if (!hasSamlResponse) {
                auth.login(XWiki.getRequestURL(request).toString());
                return null;
            }

            auth.processResponse();
            if (auth.isAuthenticated()) {
                final DocumentReference userReference = findOrCreateUser(context, auth);
                if (userReference != null) {
                    String nameId = auth.getNameId();
                    LOG.debug("Found authentication of user [{}]", nameId);
                    return new XWikiUser(userReference, context.isMainWiki());
                }
            }
            LOG.error("Saml authentication failed {}", auth.getLastErrorReason(), auth.getLastValidationException());
        } catch (com.onelogin.saml2.exception.Error e) {
            LOG.error("Saml authentication failed", e);
        } catch (Exception e) {
            throw new XWikiException(e.getMessage(), e);
        }

        return null;
    }

    @Override
    public XWikiUser checkAuth(String username, String password, String rememberMe, XWikiContext context)
        throws XWikiException
    {
        // We can't validate a password, so we either forward to the default authenticator or return the cached auth
        final String auth = getSAMLAuthenticatedUserFromSession(context);

        if (StringUtils.isEmpty(auth))
            // No SAML authentication, try standard authentication
            return super.checkAuth(context);
        else
            return checkAuth(context);
    }

    private DocumentReference findOrCreateUser(XWikiContext context, Auth auth) throws XWikiException, IOException {
        final XWikiRequest request = context.getRequest();
        final Map<String, String> attributes = new HashMap<>();

        try {
            LOG.debug("Reading authentication response");
            auth.getAttributesName().forEach(attributeName ->
                    attributes.put(attributeName, String.join(",", auth.getAttributes().get(attributeName))));

        } catch (Exception e1) {
            LOG.error("Failed reading authentication response", e1);
            throw e1;
        }

        // let's map the data
        final Map<String, String> userData = getExtendedInformation(attributes);
        final String nameID = auth.getNameId();
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML ID is [{}]", nameID);
            LOG.debug("SAML attributes are [{}]", attributes);
            LOG.debug("SAML user data are [{}]", userData);
        }
        final DocumentReference userReference = getLocalUsername(nameID, userData, context);
        if (userReference == null)
            return null;

        final XWikiDocument userDoc = context.getWiki().getDocument(userReference, context);

        // we found a user or generated a unique user name
        // check if we need to create/update a user page
        final String database = context.getWikiId();
        try {
            // Switch to main wiki to force users to be global users
            context.setWikiId(context.getMainXWiki());

            final XWiki xwiki = context.getWiki();
            // test if user already exists
            if (xwiki.exists(userReference, context))
                syncUserFields(context, userData, userReference);
            else
            if (!createUser(context, userData, nameID, userReference)) {
                LOG.error("Failed to create user [{}]", userReference);
                return null;
            }
        } finally {
            context.setWikiId(database);
        }
        syncUserGroups(context, attributes, userReference, userDoc);

        // Mark in the current session that we have authenticated the user
        LOG.debug("Setting authentication in session for user [{}]", userReference);
        context.getRequest().getSession().setAttribute(authConfig.authFieldName,
            this.compactStringEntityReferenceSerializer.serialize(userReference));

        // Successfully logged in, redirect to the originally requested URL
        final String sourceUrl = (String) request.getSession().getAttribute(ORIGINAL_URL_SESSION_KEY);
        LOG.debug("Redirecting after valid authentication to [{}]", sourceUrl);
        context.getResponse().sendRedirect(sourceUrl);
        context.setFinished(true);
        return userReference;
    }

    private void syncUserGroups(XWikiContext context, Map<String, String> attributes, DocumentReference userReference, XWikiDocument userDoc) throws XWikiException {
        final Set<String> groupsFromSaml = newHashSet((defaultIfNull(attributes.get("XWikiGroups"), "")).split(","));
        groupsFromSaml.add(authConfig.defaultGroupForNewUsers);

        final BaseObject userObj = userDoc.getXObject(USER_XCLASS);
        if (userObj == null)
            return;

        final Optional<StringProperty> samlManagedGroupsProp = Optional.ofNullable((StringProperty) userObj.get("SamlManagedGroups"));

        final Set<String> previousManagedGroups = newHashSet(samlManagedGroupsProp.map(StringProperty::getValue).orElse("").split(","));
        previousManagedGroups.removeAll(groupsFromSaml);

        groupsFromSaml.forEach(group -> xWikiGroupUtils.addUserToXWikiGroup(userReference.getName(), group, context));
        previousManagedGroups.forEach(group -> xWikiGroupUtils.removeUserFromXWikiGroup(userReference.getName(), group, context));

        userObj.put("SamlManagedGroups", new StringClass().fromString(String.join(",", groupsFromSaml)));
        context.getWiki().saveDocument(userDoc, context);
    }

    private void syncUserFields(XWikiContext context, Map<String, String> userData, DocumentReference userReference) throws XWikiException {
        final XWikiDocument userDoc = context.getWiki().getDocument(userReference, context);
        final BaseObject userObj = userDoc.getXObject(USER_XCLASS);
        boolean updated = false;

        for (Map.Entry<String, String> entry : userData.entrySet()) {
            String field = entry.getKey();
            String value = entry.getValue();
            BaseProperty<?> prop = (BaseProperty<?>) userObj.get(field);
            String currentValue = (prop == null || prop.getValue() == null) ? null : prop.getValue().toString();
            if (value != null && !value.equals(currentValue)) {
                userObj.set(field, value, context);
                updated = true;
            }
        }

        if (updated) {
            context.getWiki().saveDocument(userDoc, context);
            LOG.debug("User [{}] has been successfully updated", userReference);
        }
    }

    private boolean createUser(XWikiContext context, Map<String, String> userData, String nameID, DocumentReference userReference) throws XWikiException {
        LOG.info("Will create new user [{}]", userReference);

        // create user
        userData.put("active", "1");

        String content = "{{include document=\"XWiki.XWikiUserSheet\"/}}";
        Syntax syntax = Syntax.XWIKI_2_1;

        int result = context.getWiki().createUser(userReference.getName(), userData, PROFILE_PARENT,
            content, syntax, "edit", context);
        if (result < 0) {
            LOG.error("Failed to create user [{}] with code [{}]", userReference, result);
            return false;
        }

        final XWikiDocument userDoc = context.getWiki().getDocument(userReference, context);
        final BaseObject samlIdObject = userDoc.newXObject(SAML_XCLASS, context);
        final BaseProperty samlIdProp = new StringClass().fromString(nameID);
        samlIdProp.setOwnerDocument(samlIdObject.getOwnerDocument());
        samlIdObject.safeput(SAML_ID_XPROPERTY_NAME, samlIdProp);
        context.getWiki().saveDocument(userDoc, context);

        LOG.info("User [{}] has been successfully created", userReference);
        return true;
    }

    private DocumentReference getLocalUsername(String nameID, Map<String, String> userData, XWikiContext context)
        throws XWikiException
    {
        final String sql = "select distinct obj.name from BaseObject as obj, StringProperty as nameidprop "
            + "where obj.className=?1 and obj.id=nameidprop.id.id and nameidprop.id.name=?2 and nameidprop.value=?3";
        final List<String> list = context.getWiki().getStore().search(sql, 1, 0,
            asList(this.compactStringEntityReferenceSerializer.serialize(SAML_XCLASS),
                SAML_ID_XPROPERTY_NAME, nameID), context);
        final String validUserName;

        if (list.size() == 0) {
            // User does not exist. Let's generate a unique page name
            LOG.debug("Did not find XWiki User. Generating it.");
            String userName = generateXWikiUsername(userData);
            if (userName.equals(""))
                throw new XWikiException(
                        "Could not generate a username for user " + nameID,
                        new IllegalStateException("Could not generate a username for user "));

            validUserName = context.getWiki().getUniquePageName("XWiki", userName, context);
            LOG.debug("Generated XWiki User Name [{}]", validUserName);
        } else {
            validUserName = list.get(0);
            LOG.debug("Found XWiki User [{}]", validUserName);
        }

        if (validUserName != null)
            return getUserReferenceForName(validUserName);
        return null;
    }

    private DocumentReference getUserReferenceForName(String validUserName) {
        return this.currentMixedDocumentReferenceResolver.resolve(validUserName, PROFILE_PARENT);
    }

    private String getSAMLAuthenticatedUserFromSession(XWikiContext context)
    {
        return (String) context.getRequest().getSession(true).getAttribute(authConfig.authFieldName);
    }

    private Map<String, String> getExtendedInformation(Map<String, String> data)
    {
        final Map<String, String> extInfos = new HashMap<>();
        for (Map.Entry<String, String> entry : getFieldMapping().entrySet()) {
            String dataValue = data.get(entry.getKey());

            if (dataValue != null)
                extInfos.put(entry.getValue(), dataValue);
        }
        return extInfos;
    }

    private String generateXWikiUsername(Map<String, String> userData)
    {
        final StringBuilder userName = new StringBuilder();

        for (String field : this.authConfig.userNameRule) {
            String value = userData.get(field);
            if (StringUtils.isNotBlank(value)) {
                if (this.authConfig.shouldCapitalizeUserNames) {
                    userName.append(StringUtils.trim(StringUtils.capitalize(value)));
                } else {
                    userName.append(StringUtils.trim(value));
                }
            }
        }
        return userName.toString();
    }

    /**
     * @return the mapping between HTTP header fields names and XWiki user profile fields names.
     */
    private Map<String, String> getFieldMapping()
    {
        if (this.userPropertiesMapping == null) {
            this.userPropertiesMapping = new HashMap<>();

            for (String f : authConfig.fieldMapping) {
                String[] field = f.split("=");
                if (2 == field.length) {
                    String xwikiPropertyName = field[0].trim();
                    String samlAttributeName = field[1].trim();

                    this.userPropertiesMapping.put(samlAttributeName, xwikiPropertyName);
                } else {
                    LOG.error("Error parsing SAML fields_mapping attribute in xwiki.cfg: [{}]", f);
                }
            }
        }

        return this.userPropertiesMapping;
    }

    private Saml2Settings buildSamlSettings() {
        final Properties settings = new Properties();
        settings.put("onelogin.saml2.strict", true);
        settings.put("onelogin.saml2.sp.entityid", authConfig.entityId);
        settings.put("onelogin.saml2.sp.assertion_consumer_service.url", authConfig.assertionConsumerServiceUrl);
        settings.put("onelogin.saml2.sp.nameidformat", authConfig.nameIdFormat);
        settings.put("onelogin.saml2.idp.entityid", authConfig.idpEntityId);
        settings.put("onelogin.saml2.idp.single_sign_on_service.url", authConfig.idpSingleSignOnUrl);
        settings.put("onelogin.saml2.idp.x509cert", authConfig.x509Certificate);
        Saml2Settings s = new SettingsBuilder().fromProperties(settings).build();
        return s;
    }
}