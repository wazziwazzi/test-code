package com.dsmentoring.ldapsync.ldap;

import javax.net.ssl.SSLSocketFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.dsmentoring.ldapsync.util.EnvProperties;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;

public class LDAPConnectionHandler {
	private static Logger log = LogManager.getLogger(LDAPConnectionHandler.class);
	protected LDAPConnection _ldapConn = null;

	public LDAPConnectionHandler(EnvProperties prop) {
		log.info("Check LDAP Connection...");
		
		log.debug("----------------------------------------------------------------");
		log.debug("LDAP_URL: " + prop.getValues("LDAP_Server_Primary_IP") + ":" + prop.getValues("LDAP_Server_Primary_Port")
					+ "(LDAPS: " + prop.getValues("LDAPS_Enable") + ")");
		log.debug("LDAP_ID: " + prop.getValues("LDAP_AdminDN"));
		log.debug("LDAP_PWD: " + prop.getValues("LDAP_AdminPasswd"));
		log.debug("----------------------------------------------------------------");
		
		String LDAPS_Enable = prop.getValues("LDAPS_Enable");
		
		if(LDAPS_Enable.equalsIgnoreCase("true")) {
			try {
				SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
			    SSLSocketFactory sslSocketFactory = sslUtil.createSSLSocketFactory();
			    _ldapConn = new LDAPConnection(sslSocketFactory);
			    _ldapConn.connect(prop.getValues("LDAP_Server_Primary_IP"), Integer.parseInt(prop.getValues("LDAP_Server_Primary_Port")));
			    _ldapConn.bind(prop.getValues("LDAP_AdminDN"), prop.getValues("LDAP_AdminPasswd"));
			    
				log.info(prop.getValues("LDAP_Server_Primary_IP") + ":" + prop.getValues("LDAP_Server_Primary_Port") + " LDAPS connection successful");
			} catch (Exception ldapAuthEx) {
				log.error(ldapAuthEx);
				log.error("Failed to connect to primary LDAP server. Try connect to secondary LDAP server.");
				
				try {
					log.debug("----------------------------------------------------------------");
					log.debug("LDAP_URL: " + prop.getValues("LDAP_Server_Secondary_IP") + ":" + prop.getValues("LDAP_Server_Secondary_Port"));
					log.debug("LDAP_ID: " + prop.getValues("LDAP_AdminDN"));
					log.debug("LDAP_PWD: " + prop.getValues("LDAP_AdminPasswd"));
					log.debug("----------------------------------------------------------------");
					SSLUtil sslUtil = new SSLUtil(new TrustAllTrustManager());
				    SSLSocketFactory sslSocketFactory = sslUtil.createSSLSocketFactory();
				    _ldapConn = new LDAPConnection(sslSocketFactory);
				    _ldapConn.connect(prop.getValues("LDAP_Server_Primary_IP"), Integer.parseInt(prop.getValues("LDAP_Server_Primary_Port")));
				    _ldapConn.bind(prop.getValues("LDAP_AdminDN"), prop.getValues("LDAP_AdminPasswd"));
					
					log.info(prop.getValues("LDAP_Server_Secondary_IP") + ":" + prop.getValues("LDAP_Server_Secondary_Port") + " LDAPS connection successful");
				} catch (Exception ldapAuthEx2) {
					log.error("Failed to connect to secondary LDAP Server. Check the both ldap status or ldap connection info or network.");
					log.error(ldapAuthEx2);
					System.exit(1);
				} 
			} finally {
				log.info("----------------------------------------------------------------");
			}
 		} else {
 			try {
				_ldapConn = new LDAPConnection(prop.getValues("LDAP_Server_Primary_IP"),
						Integer.parseInt(prop.getValues("LDAP_Server_Primary_Port")),
						prop.getValues("LDAP_AdminDN"),
						prop.getValues("LDAP_AdminPasswd"));
				
				log.info(prop.getValues("LDAP_Server_Primary_IP") + ":" + prop.getValues("LDAP_Server_Primary_Port") + " LDAP connection successful");
			} catch (Exception ldapAuthEx) {
				log.error(ldapAuthEx);
				log.error("Failed to connect to primary LDAP server. Try connect to secondary LDAP server.");
				
				try {
					log.debug("----------------------------------------------------------------");
					log.debug("LDAP_URL: " + prop.getValues("LDAP_Server_Secondary_IP") + ":" + prop.getValues("LDAP_Server_Secondary_Port"));
					log.debug("LDAP_ID: " + prop.getValues("LDAP_AdminDN"));
					log.debug("LDAP_PWD: " + prop.getValues("LDAP_AdminPasswd"));
					log.debug("----------------------------------------------------------------");
					_ldapConn = new LDAPConnection(prop.getValues("LDAP_Server_Secondary_IP"),
							Integer.parseInt(prop.getValues("LDAP_Server_Secondary_Port")),
							(prop.getValues("LDAP_AdminDN")),
							(prop.getValues("LDAP_AdminPasswd")));
					
					log.info(prop.getValues("LDAP_Server_Secondary_IP") + ":" + prop.getValues("LDAP_Server_Secondary_Port") + " LDAP connection successful");
				} catch (Exception ldapAuthEx2) {
					log.error("Failed to connect to secondary LDAP Server. Check the both ldap status or ldap connection info or network.");
					log.error(ldapAuthEx2);
					System.exit(1);
				}
			} finally {
				log.info("----------------------------------------------------------------");
			}
		}
	}

	public LDAPConnection GetLDAPConnection() {
		return _ldapConn;
	}
}
