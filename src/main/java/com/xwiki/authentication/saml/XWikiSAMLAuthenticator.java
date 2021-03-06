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

import org.xwiki.environment.Environment;
import org.xwiki.model.EntityType;
import org.xwiki.model.ModelConfiguration;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.rendering.syntax.Syntax;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.BaseProperty;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.Utils;
import com.xpn.xwiki.web.XWikiRequest;
import com.xpn.xwiki.web.XWikiResponse;

/**
 * Authentication using a SAML server. The following parameters are needed for customizing its behavior in xwiki.cfg:
 * <dl>
 * <dt>xwiki.authentication.saml.cert</dt>
 * <dd>path to certificate file, relative to the webapp directory</dd>
 * <dd>required; example: {@code /WEB-INF/cert.txt}</dd>
 * <dt>xwiki.authentication.saml.authurl</dt>
 * <dd>identity provider URL</dd>
 * <dd>required; example: {@code https://www.ip-url.fr/}</dd>
 * <dt>xwiki.authentication.saml.issuer</dt>
 * <dd>service provider URL</dd>
 * <dd>required; example: {@code www.sp-url.com}</dd>
 * <dt>xwiki.authentication.saml.namequalifier</dt>
 * <dd>the {@code SPNameQualifier} value</dd>
 * <dd>required; example: {@code www.sp-url.com}</dd>
 * <dt>xwiki.authentication.saml.fields_mapping</dt>
 * <dd>mapping between {@code XWikiUsers} fields and SAML fields</dd>
 * <dd>optional; default value: {@code email=mail,first_name=givenName,last_name=sn}</dd>
 * <dt>xwiki.authentication.saml.id_field</dt>
 * <dd>the name of the SAML field containing the SAML user identifier</dd>
 * <dd>optional; default value: {@code userPrincipalName}</dd>
 * <dt>xwiki.authentication.saml.auth_field</dt>
 * <dd>the name of the attribute used to cache the authentication result in the current session</dd>
 * <dd>optional; default value: {@code saml_user}</dd>
 * <dt>xwiki.authentication.saml.xwiki_user_rule</dt>
 * <dd>list of fields to use for generating an XWiki username</dd>
 * <dd>optional; default value: {@code first_name,last_name}</dd>
 * <dt>xwiki.authentication.saml.xwiki_user_rule_capitalize</dt>
 * <dd>capitalize each field value when generating the username</dd>
 * <dd>optional; default value: {@code 1}; any other value is treated as {@code false}</dd>
 * </dl>
 *
 * @version $Id$
 */
public class XWikiSAMLAuthenticator extends XWikiAuthServiceImpl
{
    /** Logging helper object. */
    private static final Logger LOG = LoggerFactory.getLogger(XWikiSAMLAuthenticator.class);

    /** The default name of the attribute used to cache the authentication result in the current session. */
    private static final String DEFAULT_AUTH_FIELD = "saml_user";

    /** The default name of the SAML field containing the SAML user identifier. */
    private static final String DEFAULT_ID_FIELD = "userPrincipalName";

    /** The default mapping between {@code XWikiUsers} fields and SAML fields. */
    private static final String DEFAULT_FIELDS_MAPPING = "email=mail,first_name=givenName,last_name=sn";

    /** The default list of fields to use for generating an XWiki username. */
    private static final String DEFAULT_XWIKI_USERNAME_RULE = "first_name,last_name";

    /** By default, capitalize each field when generating the username. */
    private static final String DEFAULT_XWIKI_USERNAME_RULE_CAPITALIZE = "1";

    private static final String REQUEST_ID_SESSION_KEY = "saml_id";

    private static final String ORIGINAL_URL_SESSION_KEY = "saml_url";

    private static final String SAML_ID_XPROPERTY_NAME = "nameid";

    private static final String CONFIG_KEY_IDP_CERTIFICATE = "xwiki.authentication.saml.cert";

    private static final String CONFIG_KEY_IDP_URL = "xwiki.authentication.saml.authurl";

    /** The document set as the parent of new XWiki user profiles. */
    private static final EntityReference PROFILE_PARENT = new EntityReference("XWikiUsers", EntityType.DOCUMENT,
        new EntityReference(XWiki.SYSTEM_SPACE, EntityType.SPACE));

    /** Custom XClass used for storing the original ID of the remote user. */
    private static final EntityReference SAML_XCLASS = new EntityReference("SAMLAuthClass", EntityType.DOCUMENT,
        new EntityReference(XWiki.SYSTEM_SPACE, EntityType.SPACE));

    /** The XClass used for storing XWiki user profiles. */
    private static final EntityReference USER_XCLASS = PROFILE_PARENT;

    /** Provides access to the environment, used for reading the configured IdP certificate. */
    @SuppressWarnings("deprecation")
    private Environment environment = Utils.getComponent(Environment.class);

    /** Configuration for the default space and document. */
    @SuppressWarnings("deprecation")
    private ModelConfiguration defaultReference = Utils.getComponent(ModelConfiguration.class);

    /** Resolves partial serialized references into full document references. */
    @SuppressWarnings("deprecation")
    private DocumentReferenceResolver<String> currentMixedDocumentReferenceResolver =
        Utils.getComponent(DocumentReferenceResolver.TYPE_STRING, "currentmixed");

    /** Serializes references so that they don't contain the current wiki. */
    @SuppressWarnings("deprecation")
    private EntityReferenceSerializer<String> compactStringEntityReferenceSerializer =
        Utils.getComponent(EntityReferenceSerializer.TYPE_STRING, "compactwiki");

    /** The configured mapping between XWikiUsers fields and SAML fields. */
    private Map<String, String> userPropertiesMapping;

    private MarshallerFactory marshallers;

    private ParserPool parsers;

    private UnmarshallerFactory unmarshallers;

    private XMLObjectBuilderFactory builders;

    private SAMLSignatureProfileValidator sigProfileValidator;

    private SignatureValidator sigValidator;

    /**
     * Default constructor, initializes the instance members.
     *
     * @throws Exception if the initialization fails for any reason, such as missing or bad configuration, missing
     *             support for cryptography, or server IO errors
     */
    public XWikiSAMLAuthenticator() throws Exception
    {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            LOG.error("Failed to bootstrap saml module: {}", e.getMessage());
            throw new XWikiException(XWikiException.MODULE_XWIKI_USER,
                XWikiException.ERROR_XWIKI_INIT_FAILED,
                "Failed to bootstrap saml module");
        }

        this.marshallers = Configuration.getMarshallerFactory();
        this.parsers = Configuration.getParserPool();
        this.unmarshallers = Configuration.getUnmarshallerFactory();
        this.builders = Configuration.getBuilderFactory();
        this.sigProfileValidator = new SAMLSignatureProfileValidator();

        // Reading certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        String cert = getSAMLCertificate(Utils.getContext());
        if (StringUtils.isBlank(cert)) {
            LOG.error("Missing configuration key [{}] in xwiki.cfg, SAML authentication is unavailable",
                CONFIG_KEY_IDP_CERTIFICATE);
            throw new XWikiException(XWikiException.MODULE_XWIKI_USER,
                XWikiException.ERROR_XWIKI_INIT_FAILED,
                "SAML module isn't properly configured, missing certificate file configuration");
        }
        LOG.debug("Configured certificate for the identity provider: [{}]", cert);
        InputStream sis = this.environment.getResourceAsStream(cert);
        try {
            if (sis == null) {
                LOG.error("Missing or unreadable SAML IdP certificate [{}]", cert);
                throw new XWikiException(XWikiException.MODULE_XWIKI_USER,
                    XWikiException.ERROR_XWIKI_INIT_FAILED,
                    "SAML module isn't properly configured, missing certificate file");
            }
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(sis);
            BasicX509Credential credential = new BasicX509Credential();
            credential.setEntityCertificate(certificate);
            this.sigValidator = new SignatureValidator(credential);
        } finally {
            sis.close();
        }
    }

    @Override
    public void showLogin(XWikiContext context) throws XWikiException
    {
        XWikiRequest request = context.getRequest();
        XWikiResponse response = context.getResponse();

        // Generate random request ID
        String randId = RandomStringUtils.randomAlphanumeric(42);
        request.getSession().setAttribute(REQUEST_ID_SESSION_KEY, randId);
        LOG.debug("Random ID: [{}]", randId);

        // Remember the requested URL, so we can return to it afterwards
        String sourceurl = request.getParameter("xredirect");
        if (sourceurl == null) {
            if (context.getAction().startsWith("login")) {
                sourceurl = context.getWiki().getURL(new DocumentReference(context.getDatabase(),
                    this.defaultReference.getDefaultReferenceValue(EntityType.SPACE),
                    this.defaultReference.getDefaultReferenceValue(EntityType.DOCUMENT)), "view", context);
            } else {
                sourceurl = XWiki.getRequestURL(request).toString();
            }
        }
        request.getSession().setAttribute(ORIGINAL_URL_SESSION_KEY, sourceurl);

        AuthnRequest authRequest = setupAuthenticationRequest(randId, context);

        if (LOG.isDebugEnabled()) {
            LOG.debug("New AuthnRequestImpl: [{}]", authRequest.toString());
            LOG.debug("Assertion Consumer Service URL: [{}]", authRequest.getAssertionConsumerServiceURL());
        }

        // Now we must build our representation to put into the html form to be submitted to the IdP
        Marshaller marshaller = this.marshallers.getMarshaller(authRequest);
        if (marshaller == null) {
            LOG.error("Failed to get marshaller for [{}]", authRequest);
            throw new XWikiException(XWikiException.MODULE_XWIKI_USER,
                XWikiException.ERROR_XWIKI_USER_INIT,
                "Failed to get marshaller for " + authRequest);
        } else {
            Element authDOM;
            String samlRequest = "";
            try {
                authDOM = marshaller.marshall(authRequest);
                StringWriter rspWrt = new StringWriter();
                XMLHelper.writeNode(authDOM, rspWrt);
                String messageXML = rspWrt.toString();
                Deflater deflater = new Deflater(Deflater.DEFLATED, true);
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
                deflaterOutputStream.write(messageXML.getBytes());
                deflaterOutputStream.close();
                samlRequest = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
                samlRequest = URLEncoder.encode(samlRequest, XWiki.DEFAULT_ENCODING);
                LOG.debug("Converted AuthRequest: [{}]", messageXML);
            } catch (Exception e) {
                LOG.error("Failed to marshall request for [{}]", authRequest);
                throw new XWikiException(XWikiException.MODULE_XWIKI_USER,
                    XWikiException.ERROR_XWIKI_USER_INIT, "Failed to marshall request for " + authRequest);
            }

            String actionURL = getSAMLAuthenticatorURL(context);
            String url = actionURL + "?SAMLRequest=" + samlRequest;
            LOG.info("Saml request sent to [{}]", url);
            try {
                response.sendRedirect(url);
                context.setFinished(true);
            } catch (IOException e) {
                // Should not happen
            }
        }
    }

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        // Check in the session if the user is already authenticated
        String samlUserName = getSAMLAuthenticatedUserFromSession(context);
        if (samlUserName == null) {
            // Check if we have a SAML Response to verify
            if (checkSAMLResponse(context)) {
                // Successfully authenticated, a redirect to the originally requested URL is already sent
                return null;
            }

            // Check standard authentication
            if (context.getRequest().getCookie("username") != null || context.getAction().equals("logout")
                || context.getAction().startsWith("login")) {
                LOG.debug("Fallback to standard authentication");
                return super.checkAuth(context);
            }

            return null;
        } else {
            LOG.debug("Found authentication of user [{}]", samlUserName);
            if (context.isMainWiki()) {
                return new XWikiUser(samlUserName);
            } else {
                return new XWikiUser(context.getMainXWiki() + ":" + samlUserName);
            }
        }
    }

    @Override
    public XWikiUser checkAuth(String username, String password, String rememberme, XWikiContext context)
        throws XWikiException
    {
        // We can't validate a password, so we either forward to the default authenticator or return the cached auth
        String auth = getSAMLAuthenticatedUserFromSession(context);

        if (StringUtils.isEmpty(auth)) {
            // No SAML authentication, try standard authentication
            return super.checkAuth(context);
        } else {
            return checkAuth(context);
        }
    }

    private AuthnRequest setupAuthenticationRequest(String randId, XWikiContext context)
    {
        // Create Issuer: who is making the request? This XWiki instance.
        IssuerBuilder issuerBuilder = (IssuerBuilder) this.builders.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(getSAMLIssuer(context));

        // Create NameIDPolicy: what type of identity to return? A persistent identifier.
        NameIDPolicyBuilder nameIdPolicyBuilder =
            (NameIDPolicyBuilder) this.builders.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME);
        NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
        nameIdPolicy.setFormat(NameIDType.PERSISTENT);
        nameIdPolicy.setSPNameQualifier(getSAMLNameQualifier(context));
        nameIdPolicy.setAllowCreate(true);

        // Create AuthnContextClassRef: what type of authentication is allowed? Password check over a secure connection.
        AuthnContextClassRefBuilder authnContextClassRefBuilder =
            (AuthnContextClassRefBuilder) this.builders.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PPT_AUTHN_CTX);

        // Create RequestedAuthnContext: what type of authentication is requested? At least PPT.
        RequestedAuthnContextBuilder requestedAuthnContextBuilder =
            (RequestedAuthnContextBuilder) this.builders.getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
        RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        // Create AuthnRequest: the actual authentication request.
        AuthnRequestBuilder authRequestBuilder =
            (AuthnRequestBuilder) this.builders.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest authRequest = authRequestBuilder.buildObject();
        authRequest.setVersion(SAMLVersion.VERSION_20);
        authRequest.setID(randId);
        authRequest.setIssueInstant(new DateTime());
        // Accept a previous authentication, don't force a re-check of the credentials
        authRequest.setForceAuthn(false);
        // Allow user interaction
        authRequest.setIsPassive(false);
        // Use POST-ed HTML forms for communication between the IdP and SP
        authRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        // Request a persistent identifier
        authRequest.setNameIDPolicy(nameIdPolicy);
        // Request at least a secure password check
        authRequest.setRequestedAuthnContext(requestedAuthnContext);

        // We made the request
        authRequest.setIssuer(issuer);
        // Send the response back to this server
        authRequest.setAssertionConsumerServiceURL(getSAMLAuthenticatorURL(context));

        return authRequest;
    }

    private boolean checkSAMLResponse(XWikiContext context) throws XWikiException
    {
        // Read from SAMLResponse
        XWikiRequest request = context.getRequest();
        Map<String, String> attributes = new HashMap<String, String>();

        String samlResponse = request.getParameter("SAMLResponse");
        if (samlResponse == null) {
            return false;
        }

        try {
            LOG.debug("Reading SAML Response");
            samlResponse = new String(Base64.decode(samlResponse), XWiki.DEFAULT_ENCODING);

            LOG.debug("SAML Response is [{}]", samlResponse);

            // Parse the response into a DOM tree
            Element responseRoot = this.parsers.parse(new StringReader(samlResponse)).getDocumentElement();
            // Get appropriate unmarshaller
            Unmarshaller unmarshaller = this.unmarshallers.getUnmarshaller(responseRoot);
            // Unmarshall into Java objects
            Response response = (Response) unmarshaller.unmarshall(responseRoot);
            if (!validateResponse(response, (String) request.getSession().getAttribute(REQUEST_ID_SESSION_KEY))) {
                return false;
            }

            // Process all attributes
            LOG.debug("Reading SAML User data");
            for (Assertion a : response.getAssertions()) {
                for (AttributeStatement attStatement : a.getAttributeStatements()) {
                    for (Attribute att : attStatement.getAttributes()) {
                        for (XMLObject val : att.getAttributeValues()) {
                            if (val instanceof XSStringImpl) {
                                attributes.put(att.getName(), ((XSStringImpl) val).getValue());
                            }
                        }
                    }
                }
            }
        } catch (Exception e1) {
            LOG.error("Failed Reading SAML Response", e1);
            return false;
        }

        // let's map the data
        Map<String, String> userData = getExtendedInformations(attributes, context);

        String nameID = attributes.get(getIdFieldName(context));
        if (LOG.isDebugEnabled()) {
            LOG.debug("SAML ID is [{}]", nameID);
            LOG.debug("SAML attributes are [{}]", attributes);
            LOG.debug("SAML user data are [{}]", userData);
        }
        DocumentReference userReference = getLocalUsername(nameID, userData, context);
        // we found a user or generated a unique user name
        if (userReference != null) {
            // check if we need to create/update a user page
            String database = context.getDatabase();
            try {
                // Switch to main wiki to force users to be global users
                context.setDatabase(context.getMainXWiki());

                XWiki xwiki = context.getWiki();
                // test if user already exists
                if (!xwiki.exists(userReference, context)) {
                    LOG.debug("Need to create user [{}]", userReference);

                    // create user
                    userData.put("active", "1");

                    String content = "{{include document=\"XWiki.XWikiUserSheet\"/}}";
                    Syntax syntax = Syntax.XWIKI_2_1;
                    if (xwiki.getDefaultDocumentSyntax().equals(Syntax.XWIKI_1_0.toIdString())) {
                        content = "#includeForm(\"XWiki.XWikiUserSheet\")";
                        syntax = Syntax.XWIKI_1_0;
                    }
                    int result = context.getWiki().createUser(userReference.getName(), userData, PROFILE_PARENT,
                        content, syntax, "edit", context);
                    if (result < 0) {
                        LOG.error("Failed to create user [{}] with code [{}]", userReference, result);
                        return false;
                    }
                    XWikiDocument userDoc = context.getWiki().getDocument(userReference, context);
                    BaseObject obj = userDoc.newXObject(SAML_XCLASS, context);
                    obj.set(SAML_ID_XPROPERTY_NAME, nameID, context);
                    context.getWiki().saveDocument(userDoc, context);
                    LOG.debug("User [{}] has been successfully created", userReference);
                } else {
                    XWikiDocument userDoc = context.getWiki().getDocument(userReference, context);
                    BaseObject userObj = userDoc.getXObject(USER_XCLASS);
                    boolean updated = false;

                    for (Map.Entry<String, String> entry : userData.entrySet()) {
                        String field = entry.getKey();
                        String value = entry.getValue();
                        BaseProperty<?> prop = (BaseProperty<?>) userObj.get(field);
                        String currentValue =
                            (prop == null || prop.getValue() == null) ? null : prop.getValue().toString();
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
            } catch (Exception e) {
                LOG.error("Failed to create user [{}]", userReference, e);
                return false;
            } finally {
                context.setDatabase(database);
            }
        }

        // Mark in the current session that we have authenticated the user
        LOG.debug("Setting authentication in session for user [{}]" + userReference);
        if (userReference != null) {
            context.getRequest().getSession().setAttribute(getAuthFieldName(context),
                this.compactStringEntityReferenceSerializer.serialize(userReference));
        } else {
            context.getRequest().getSession().setAttribute(getAuthFieldName(context), null);
        }

        // Successfully logged in, redirect to the originally requested URL
        try {
            String sourceurl = (String) request.getSession().getAttribute(ORIGINAL_URL_SESSION_KEY);
            LOG.debug("Redirecting after valid authentication to [{}]", sourceurl);
            context.getResponse().sendRedirect(sourceurl);
            context.setFinished(true);
            return true;
        } catch (IOException e) {
            // Should never happen
        }
        return false;
    }

    private boolean validateResponse(Response response, String expectedSamlId) throws ValidationException
    {
        response.validate(true);
        Signature signature = response.getSignature();
        this.sigProfileValidator.validate(signature);
        this.sigValidator.validate(signature);

        boolean isValidDate = true;

        // Verify date assertions
        for (Assertion a : response.getAssertions()) {
            if (a.getAuthnStatements().size() > 0 && a.getConditions() != null
                && a.getConditions().getNotOnOrAfter() != null) {
                if (a.getConditions().getNotOnOrAfter().isBeforeNow()) {
                    isValidDate = false;
                }
            }
        }

        String samlId = response.getInResponseTo();
        if (!isValidDate) {
            // Invalid date
            LOG.error("SAML Dates are invalid");
            return false;
        }
        if (!samlId.equals(expectedSamlId)) {
            // Invalid ID
            LOG.error("SAML ID do not match [{}] - [{}]", expectedSamlId, samlId);
            return false;
        }
        return true;
    }

    private DocumentReference getLocalUsername(String nameID, Map<String, String> userData, XWikiContext context)
        throws XWikiException
    {
        String sql = "select distinct obj.name from BaseObject as obj, StringProperty as nameidprop "
            + "where obj.className=? and obj.id=nameidprop.id.id and nameidprop.id.name=? and nameidprop.value=?";
        List<String> list = context.getWiki().getStore().search(sql, 1, 0,
            Arrays.asList(this.compactStringEntityReferenceSerializer.serialize(SAML_XCLASS),
                SAML_ID_XPROPERTY_NAME, nameID), context);
        String validUserName = null;

        if (list.size() == 0) {
            // User does not exist. Let's generate a unique page name
            LOG.debug("Did not find XWiki User. Generating it.");
            String userName = generateXWikiUsername(userData, context);
            if (userName.equals("")) {
                userName = "user";
            }
            validUserName = context.getWiki().getUniquePageName("XWiki", userName, context);
            LOG.debug("Generated XWiki User Name [{}]", validUserName);
        } else {
            validUserName = list.get(0);
            LOG.debug("Found XWiki User [{}]", validUserName);
        }

        if (validUserName != null) {
            return this.currentMixedDocumentReferenceResolver.resolve(validUserName, PROFILE_PARENT);
        }
        return null;
    }

    private String getSAMLCertificate(XWikiContext context)
    {
        return context.getWiki().Param(CONFIG_KEY_IDP_CERTIFICATE);
    }

    private String getSAMLAuthenticatorURL(XWikiContext context)
    {
        return context.getWiki().Param(CONFIG_KEY_IDP_URL);
    }

    private String getSAMLIssuer(XWikiContext context)
    {
        return context.getWiki().Param("xwiki.authentication.saml.issuer");
    }

    private String getSAMLNameQualifier(XWikiContext context)
    {
        return context.getWiki().Param("xwiki.authentication.saml.namequalifier");
    }

    private String getSAMLAuthenticatedUserFromSession(XWikiContext context)
    {
        return (String) context.getRequest().getSession(true).getAttribute(getAuthFieldName(context));
    }

    private String getAuthFieldName(XWikiContext context)
    {
        return context.getWiki().Param("xwiki.authentication.saml.auth_field", DEFAULT_AUTH_FIELD);
    }

    private String getIdFieldName(XWikiContext context)
    {
        return context.getWiki().Param("xwiki.authentication.saml.id_field", DEFAULT_ID_FIELD);
    }

    private Map<String, String> getExtendedInformations(Map<String, String> data, XWikiContext context)
    {
        Map<String, String> extInfos = new HashMap<String, String>();

        for (Map.Entry<String, String> entry : getFieldMapping(context).entrySet()) {
            String dataValue = data.get(entry.getKey());

            if (dataValue != null) {
                extInfos.put(entry.getValue(), dataValue);
            }
        }

        return extInfos;
    }

    /**
     * @param context the XWiki context
     * @return the fields to use to generate the username
     */
    private String[] getXWikiUsernameRule(XWikiContext context)
    {
        String userFields =
            context.getWiki().Param("xwiki.authentication.saml.xwiki_user_rule", DEFAULT_XWIKI_USERNAME_RULE);
        return userFields.split(",");
    }

    /**
     * @param context the XWiki context
     * @return {@code true} if the fields should be capitalized
     */
    private boolean getXWikiUsernameRuleCapitalization(XWikiContext context)
    {
        String capitalize =
            context.getWiki().Param("xwiki.authentication.saml.xwiki_user_rule_capitalize",
                DEFAULT_XWIKI_USERNAME_RULE_CAPITALIZE);
        return "1".equals(capitalize);
    }

    private String generateXWikiUsername(Map<String, String> userData, XWikiContext context)
    {
        String[] userFields = getXWikiUsernameRule(context);
        boolean capitalize = getXWikiUsernameRuleCapitalization(context);
        String userName = "";

        for (String field : userFields) {
            String value = userData.get(field);
            if (StringUtils.isNotBlank(value)) {
                if (capitalize) {
                    userName += StringUtils.trim(StringUtils.capitalize(value));
                } else {
                    userName += StringUtils.trim(value);
                }
            }
        }
        return userName;
    }

    /**
     * @param context the XWiki context
     * @return the mapping between HTTP header fields names and XWiki user profile fields names.
     */
    private Map<String, String> getFieldMapping(XWikiContext context)
    {
        if (this.userPropertiesMapping == null) {
            this.userPropertiesMapping = new HashMap<String, String>();

            String fieldMapping =
                context.getWiki().Param("xwiki.authentication.saml.fields_mapping", DEFAULT_FIELDS_MAPPING);

            String[] fields = fieldMapping.split(",");

            for (String field2 : fields) {
                String[] field = field2.split("=");
                if (2 == field.length) {
                    String xwikiPropertyName = field[0].trim();
                    String samlAttributeName = field[1].trim();

                    this.userPropertiesMapping.put(samlAttributeName, xwikiPropertyName);
                } else {
                    LOG.error("Error parsing SAML fields_mapping attribute in xwiki.cfg: [{}]", field2);
                }
            }
        }

        return this.userPropertiesMapping;
    }
}
