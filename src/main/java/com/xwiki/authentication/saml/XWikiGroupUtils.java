package com.xwiki.authentication.saml;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.rendering.syntax.Syntax;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class XWikiGroupUtils {
    private static final Logger LOG = LoggerFactory.getLogger(XWikiGroupUtils.class);
    private static final String XWIKI_GROUP_MEMBERFIELD = "member";

    private static final EntityReference GROUP_PARENT = new EntityReference("XWikiGroups", EntityType.DOCUMENT,
            new EntityReference(XWiki.SYSTEM_SPACE, EntityType.SPACE));
    private final DocumentReferenceResolver<String> groupResolver;

    public XWikiGroupUtils(DocumentReferenceResolver<String> groupResolver) {
        this.groupResolver = groupResolver;
    }

    /**
     * Add user name to provided XWiki group.
     *
     * @param xwikiUserName the full name of the user.
     * @param groupName the name of the group.
     * @param context the XWiki context.
     */
    protected synchronized void addUserToXWikiGroup(String xwikiUserName, String groupName, XWikiContext context)
    {
        try {
            if (groupName.trim().isEmpty()) {
                LOG.warn("Tried to add user [{}] to empty group. Ignoring", xwikiUserName);
                return;
            }
            LOG.debug("Adding user [{}] to xwiki group [{}]", xwikiUserName, groupName);

            BaseClass groupClass = context.getWiki().getGroupClass(context);

            // Get document representing group
            XWikiDocument groupDoc = context.getWiki().getDocument(getGroupReferenceForName(groupName), context);

            // Make extra sure the group cannot contain duplicate (even if this method is not supposed to be called
            // in this case)
            if (isUserAlreadyMember(xwikiUserName, groupClass, groupDoc)) return;

            // Add a member object to document
            BaseObject memberObj = groupDoc.newXObject(groupClass.getDocumentReference(), context);
            Map<String, String> map = new HashMap<>();
            map.put(XWIKI_GROUP_MEMBERFIELD, xwikiUserName);
            groupClass.fromMap(map, memberObj);

            // If the document is new, set its content
            if (groupDoc.isNew()) {
                groupDoc.setSyntax(Syntax.XWIKI_2_0);
                groupDoc.setContent("{{include reference='XWiki.XWikiGroupSheet' /}}");
            }

            // Save modifications
            context.getWiki().saveDocument(groupDoc, context);

            LOG.debug("Finished adding user [{}] to xwiki group [{}]", xwikiUserName, groupName);
        } catch (Exception e) {
            LOG.error("Failed to add a user [{}] to a group [{}]", xwikiUserName, groupName, e);
        }
    }

    /**
     * Remove user name from provided XWiki group.
     *
     * @param xwikiUserName the full name of the user.
     * @param groupName the name of the group.
     * @param context the XWiki context.
     */
    protected void removeUserFromXWikiGroup(String xwikiUserName, String groupName, XWikiContext context)
    {
        try {
            if (groupName.trim().isEmpty()) {
                LOG.warn("Tried to remove user [{}] from empty group. Ignoring", xwikiUserName);
                return;
            }
            BaseClass groupClass = context.getWiki().getGroupClass(context);

            // Get the XWiki document holding the objects comprising the group membership list
            XWikiDocument groupDoc = context.getWiki().getDocument(getGroupReferenceForName(groupName), context);

            synchronized (groupDoc) {
                // Get and remove the specific group membership object for the user
                BaseObject groupObj =
                        groupDoc.getXObject(groupClass.getDocumentReference(), XWIKI_GROUP_MEMBERFIELD, xwikiUserName);
                if (groupObj != null) {
                    groupDoc.removeXObject(groupObj);
                }

                // Save modifications
                context.getWiki().saveDocument(groupDoc, context);
            }
        } catch (Exception e) {
            LOG.error("Failed to remove a user from a group [{}] group: [{}]", xwikiUserName, groupName, e);
        }
    }

    protected static boolean isUserAlreadyMember(String xwikiUserName, BaseClass groupClass, XWikiDocument groupDoc) {
        List<BaseObject> currentObjects = groupDoc.getXObjects(groupClass.getDocumentReference());
        if (currentObjects == null) return  false;

        for (BaseObject memberObj : currentObjects) {
            if (memberObj == null) continue;
            String existingMember = memberObj.getStringValue(XWIKI_GROUP_MEMBERFIELD);
            if (existingMember != null && existingMember.equals(xwikiUserName)) {
                LOG.warn("User [{}] already exist in group [{}]", xwikiUserName,
                        groupDoc.getDocumentReference());
                return true;
            }
        }
        return false;
    }

    private DocumentReference getGroupReferenceForName(String validGroupName) {
        return this.groupResolver.resolve(validGroupName, GROUP_PARENT);
    }
}
