package org.pentaho.platform.spring.security.saml.groups;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.opensaml.saml2.core.Attribute;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.opensaml.xml.schema.impl.XSStringImpl;
import org.pentaho.platform.api.engine.IPentahoSession;
import org.pentaho.platform.api.mt.ITenantedPrincipleNameResolver;
import org.pentaho.platform.engine.core.system.PentahoSessionHolder;
import org.pentaho.platform.spring.security.saml.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

/**
 * Checks the users attributes list, to try and fetch the roles from there The user credentials are those sent within
 * the SAML Authentication Response
 */
public class PentahoSamlNativeUserDetailsService implements SAMLUserDetailsService, UserDetailsService {

	private static final Logger logger = LoggerFactory.getLogger(PentahoSamlNativeUserDetailsService.class);

	/**
	 * The attribute in the users' attribute list that corresponds to our Pentaho Roles. A user may carry a multitude of
	 * attributes ( age, email, drivers' license, list of favourite books , .. One such attribute will be a 'list of
	 * Pentaho Roles'
	 */
	private String roleRelatedUserAttributeName;

	/**
	 * (optional) attribute values may hold a prefix that helps to contextualize that specific value; Example: in a
	 * attribute such as 'List of OKTA SSO-based Application Roles' the values may be: 'Pentaho:Report Author',
	 * 'Zendesk:CTools Support', 'Office365:Contributor C1', 'Pentaho:Authenticated', ...
	 */
	private String roleRelatedAttributePrefix;

	/**
	 * Regular expression which defines which attributes from the SAML credentials will be registered in the user's
	 * session.
	 */
	private String sessionAttributePattern;

	ITenantedPrincipleNameResolver tenantedPrincipleNameResolver;

	public String getRoleRelatedAttributePrefix() {
		return roleRelatedAttributePrefix;
	}

	public String getRoleRelatedUserAttributeName() {
		return roleRelatedUserAttributeName;
	}

	public String getSessionAttributePattern() {
		return sessionAttributePattern;
	}

	public ITenantedPrincipleNameResolver getTenantedPrincipleNameResolver() {
		return tenantedPrincipleNameResolver;
	}

	@Override
	public Object loadUserBySAML(SAMLCredential credential) throws UsernameNotFoundException {
		if (credential != null && credential.getNameID() != null && credential.getNameID().getValue() != null) {
			String username = credential.getNameID().getValue();
			logger.debug(String.format("Setting up SAML user details for user [%s]", username));
			Collection<GrantedAuthority> authorities = new ArrayList();
			authorities.add(Utils.getDefaultRole());
			if (this.getRoleRelatedUserAttributeName() != null && !this.getRoleRelatedUserAttributeName().isEmpty()
					&& credential.getAttribute(this.getRoleRelatedUserAttributeName()) != null) {
				authorities.addAll(this.roleRelatedAttributeToGrantedAuthorities(credential.getAttribute(this.getRoleRelatedUserAttributeName())));
			}

			UserDetails userDetails = new User(username, "ignored", true, true, true, true, authorities);
			Utils.getUserMap().put(username, userDetails);
			if (this.getSessionAttributePattern() != null && !this.getSessionAttributePattern().isEmpty()) {
				this.loadSessionAttributes(PentahoSessionHolder.getSession(), credential.getAttributes(), Pattern.compile(this.getSessionAttributePattern()),
						this.getRoleRelatedUserAttributeName());
			}

			logger.debug(String.format("Attached SAML attributes to session[%s] for user [%s]", PentahoSessionHolder.getSession().getId(), username));
			return userDetails;
		} else {
			throw new UsernameNotFoundException("invalid/null SAMLCredential");
		}
	}

	@Override
	public UserDetails loadUserByUsername(String user) throws UsernameNotFoundException {

		if (user != null) {

			if (getTenantedPrincipleNameResolver() != null) {
				user = getTenantedPrincipleNameResolver().getPrincipleName(user);
			}

			UserDetails userDetails = Utils.getUserMap().get(user);
			if (userDetails != null) {
				return userDetails;
			}
		}
		throw new UsernameNotFoundException(user);
	}

	public void setRoleRelatedAttributePrefix(String roleRelatedAttributePrefix) {
		this.roleRelatedAttributePrefix = roleRelatedAttributePrefix;
	}

	public void setRoleRelatedUserAttributeName(String roleRelatedUserAttributeName) {
		this.roleRelatedUserAttributeName = roleRelatedUserAttributeName;
	}

	public void setSessionAttributePattern(String aSessionAttributePattern) {
		sessionAttributePattern = aSessionAttributePattern;
		if (sessionAttributePattern != null && !sessionAttributePattern.isEmpty()) {
			try {
				Pattern.compile(sessionAttributePattern);
			} catch (PatternSyntaxException e) {
				throw new IllegalArgumentException("Not a valid session attribute pattern: " + sessionAttributePattern, e);
			}
		}
	}

	public void setTenantedPrincipleNameResolver(ITenantedPrincipleNameResolver tenantedPrincipleNameResolver) {
		this.tenantedPrincipleNameResolver = tenantedPrincipleNameResolver;
	}

	private List<String> extractValues(List<XMLObject> aValues) {
		List<String> result = new ArrayList<>();
		for (XMLObject val : aValues) {
			String strval = null;
			if (val instanceof XSString) {
				strval = ((XSString) val).getValue();
			} else if (val instanceof XSAny) {
				strval = ((XSAny) val).getTextContent();
			}
			if (strval != null) {
				result.add(strval);
			}
		}
		return result;
	}

	private void loadSessionAttributes(IPentahoSession session, List<Attribute> attributes, Pattern pattern, String aRoleAttribute) {
		for (Attribute attr : attributes) {
			String attrName = attr.getName();
			if (!attrName.equals(aRoleAttribute) && pattern.matcher(attrName).matches()) {
				List<String> values = this.extractValues(attr.getAttributeValues());
				if (values.size() == 1) {
					session.setAttribute(attr.getName(), values.get(0));
					logger.debug(String.format("Setting session attribute [%30s] : %s", attr.getName(), values.get(0)));
				} else if (!values.isEmpty()) {
					session.setAttribute(attr.getName(), values);
					logger.debug(String.format("Setting session attribute [%30s] : %s", attr.getName(), values));
				}
			}
		}
	}

	private Collection<GrantedAuthority> roleRelatedAttributeToGrantedAuthorities(Attribute roleRelatedAttribute) {

		Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

		if (roleRelatedAttribute != null && roleRelatedAttribute.hasChildren()) {

			List<XMLObject> roleXmlValues = roleRelatedAttribute.getAttributeValues();

			for (XMLObject xmlValue : roleXmlValues) {

				if (xmlValue == null) {
					logger.warn("Empty value for attribute '" + roleRelatedAttribute + "'");
					continue;
				}

				String sanitizedValue = "";

				if (xmlValue instanceof XSStringImpl) {
					sanitizedValue = ((XSStringImpl) xmlValue).getValue();
				} else if (xmlValue instanceof XSAnyImpl) {
					sanitizedValue = ((XSAnyImpl) xmlValue).getTextContent();
				} else {
					logger.warn("Unknown attribute type: " + xmlValue.toString());
					continue;
				}

				// if there's a prefix configured, check it ( and trim it )
				if (getRoleRelatedAttributePrefix() != null && !getRoleRelatedAttributePrefix().isEmpty()
						&& sanitizedValue.startsWith(getRoleRelatedAttributePrefix())) {

					sanitizedValue = sanitizedValue.replace(getRoleRelatedAttributePrefix(), "");
				}

				// finally, add it to the authorities list as a granted authority
				if (sanitizedValue != null && !sanitizedValue.isEmpty()) {
					authorities.add(new SimpleGrantedAuthority(sanitizedValue));
				}
			}
		}

		return authorities;
	}
}
