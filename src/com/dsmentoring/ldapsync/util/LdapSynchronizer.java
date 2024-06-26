package com.dsmentoring.ldapsync.util;

import com.dsmentoring.ldapsync.ldap.LDAPConnectionHandler;
import com.dsmentoring.ldapsync.web.WEBCheckHandler;
import com.dsmentoring.ldapsync.web.WEBSessionHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.unboundid.ldap.sdk.LDAPConnection;

public class LdapSynchronizer {
	protected EnvProperties _env = null;
	protected WEBSessionHandler _webSessionHandler = null;
	protected WEBCheckHandler _webCheckHandler = null;
	
	protected LDAPConnectionHandler _ldapConnectionHandler = null;
	
	public LdapSynchronizer() {
		InitSynchronizer(null);
	}
	
	public LdapSynchronizer(String envFile) {
		InitSynchronizer(envFile);
	}

	protected void InitSynchronizer(String envFile) {
		_env = new EnvProperties(envFile);
	}
	
	protected EnvProperties GetEnv() {
		return _env;
	}
	
	protected int LoginWEB() {
		_webSessionHandler = new WEBSessionHandler(_env);
		return 0;
	}
	
	protected String GetWEBSessionID() {
		return _webSessionHandler.GetWEBSessionID();
	}
	
	protected int LogoutWEB() {
		_webSessionHandler.logout(_env);
		return 0;
	}
	
	protected int ConnectLDAP() {
		_ldapConnectionHandler = new LDAPConnectionHandler(_env);
		return 0;
	}
	
	protected LDAPConnection GetLDAPConn() {
		return _ldapConnectionHandler.GetLDAPConnection();
	}
	
	protected int SearchWEBUsers(String webSessionID) {
		_webCheckHandler = new WEBCheckHandler(webSessionID, _env);
		return 0;
	}
	
	protected JsonNode GetWEBUsers() {
		return _webCheckHandler.GetWEBUsers();
	}
}
