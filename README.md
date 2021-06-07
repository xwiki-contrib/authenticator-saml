= SAML 2.0 Authenticator =

This module has been developed to provide a working SAML 2.0 Authenticator and is mostly based on
[https://github.com/xwiki-contrib/authenticator-saml], but replaces OpenSAML by OneLogin 
[https://github.com/onelogin/java-saml] for the SAML authentication.

It has been tested with Google Workspace SAML authentication. The following configurations
are supported in the xwiki.cfg file:

```sh
# Required properties
xwiki.authentication.authclass=com.xwiki.authentication.saml.XWikiSAML20Authenticator

xwiki.authentication.saml2.idp.single_sign_on_service.url=https://accounts.google.com/o/saml2/idp?idpid=<Copy from google>
xwiki.authentication.saml2.idp.entityid=https://accounts.google.com/o/saml2?idpid=<Copy from google>
xwiki.authentication.saml2.sp.entityid=<any arbitrary string - you must use this when google asks>
xwiki.authentication.saml2.idp.x509cert=the certificate to validate\
requests. Use backslash\
for line breaks

xwiki.authentication.saml2.sp.assertion_consumer_service.url=https://<you wiki domain>/bin/loginsubmit/XWiki/XWikiLogin

# All properties below are optional - The assigned values are the default values

# Mapping of XWiki user fields and identity provider
xwiki.authentication.saml2.fields_mapping=email=email,first_name=firstName,last_name=lastName

# Default group for new users
xwiki.authentication.saml2.defaultGroupForNewUsers=XWiki.SamlGroup

# The name of the attribute used to cache the authentication result in the current session; optional
xwiki.authentication.saml2.auth_field=saml_user

# List of fields to use for generating an XWiki username
xwiki.authentication.saml2.xwiki_user_rule=first_name,last_name

# Capitalize each field value when generating the username
xwiki.authentication.saml2.xwiki_user_rule_capitalize=true

# NameIDFormat format; recommend leaving the default
xwiki.authentication.saml2.sp.nameidformat=urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
```

== Google Workspace set up instructions ==

When setting up with Google Workspace SAML, follow these instructions:

0. Optional step:

If you want, you can create a custom field for your users names XWikiGroups, single value, text. 
This can be used to specify the user groups.

1. Create a SAML Custom App

2. In the second page download the metadata file. The format will look like the following:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://accounts.google.com/o/saml2?idpid=<IDPID>" validUntil="...">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>Copy this value to property xwiki.authentication.saml2.idp.x509cert</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://accounts.google.com/o/saml2/idp?idpid=<IDPID>"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://accounts.google.com/o/saml2/idp?idpid=<IDPID>"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
```

The value of Location field of `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST` is xwiki.authentication.saml2.idp.single_sign_on_service.url.

`entityID` value in the first line should be set on `xwiki.authentication.saml2.idp.entityid`.

2. Next to the second page:
   
* ACS URL: https://<you wiki domain>/bin/loginsubmit/XWiki/XWikiLogin
* Entity ID: the same value present on xwiki.authentication.saml2.sp.entityid
* Name ID Format: EMAIL
* Name ID Field: Basic Information > Primary email

3. Attribute mapping:

* Primary Email -> email
* First Name -> firstName
* Last Name -> lastName

If you created the custom field XWikiGroups, set up the following attribute mapping:
* XWikiGroups -> XWikiGroups 

== Installing on XWiki ==

1. Build the project

```sh
mvn clean install
```

2. Create a folder to store the maven repository files for you wiki. Let's assume for this example it will be in the following place

```sh
/usr/local/xwiki/data/repo/org/xwiki/contrib/authentication/xwiki-authenticator-saml20/1.0-SNAPSHOT
```   

3. Copy all files from your maven local repo

```sh   
$M2_HOME/repository/org/xwiki/contrib/authentication/xwiki-authenticator-saml20/1.0-SNAPSHOT
```

to the directory created on step 2.

4. Add the following lines to xwiki.properties

```sh
extension.repositories=local:maven:file:///usr/local/xwiki/data/repo
extension.repositories=maven-xwiki:maven:https://nexus.xwiki.org/nexus/content/groups/public/
extension.repositories=extensions.xwiki.org:xwiki:https://extensions.xwiki.org/xwiki/rest/
```

5. For Google Workspace, you need to make sure you are behind https. If you are behind a reverse proxy, you might
face issues with wrong http redirections. Try adding the following to your web.xml 
   
```sh
    <filter>
        <filter-name>RemoteIpFilter</filter-name>
        <filter-class>org.apache.catalina.filters.RemoteIpFilter</filter-class>
        <init-param>
            <param-name>protocolHeader</param-name>
            <param-value>x-forwarded-proto</param-value>
        </init-param>
       <init-param>
            <param-name>remoteIpHeader</param-name>
            <param-value>x-forwarded-for</param-value>
       </init-param>
    </filter>
```

== Notice ==

It is still possible to authenticate against the local authentication. To do that, open the login form URL directly:

    https://<your wiki domain>/bin/login/XWiki/XWikiLogin
