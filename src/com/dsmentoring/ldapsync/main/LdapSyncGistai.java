package com.dsmentoring.ldapsync.main;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;

import com.dsmentoring.ldapsync.ldap.LDAPOperation;
import com.dsmentoring.ldapsync.util.EnvProperties;
import com.dsmentoring.ldapsync.util.LdapSynchronizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.SearchResultEntry;

public class LdapSyncGistai extends LdapSynchronizer {
	
	private static Logger log = LogManager.getLogger(LdapSyncGistai.class);
	private static EnvProperties prop = null;
	
	private static int total_count = 0;
	private static int skip_count = 0;
	private static int LDAP_d_skip_count = 0;
	private static int a_succ_count = 0;
	private static int a_err_count = 0;
	private static int m_succ_count = 0;
	private static int m_err_count = 0;
	private static int d_succ_count = 0;
	private static int d_err_count = 0;

	public static void main(String[] args) {
		LoggerContext context = (org.apache.logging.log4j.core.LoggerContext) LogManager.getContext(false);
		File file = new File("conf/LdapSync-log4j2.xml");
		context.setConfigLocation(file.toURI());
		
		try {
			log.info(" ***** WEB to Chakan LDAP Sync ***** ");
			LdapSyncGistai Sync = new LdapSyncGistai();
			Sync.SynctoLDAP();
			log.info("");
		} catch (Exception e) {
			log.error("Init Failed.", e);
		}
	}
	
	public LdapSyncGistai() {
		LoginWEB();
		ConnectLDAP();
		log.info("Properties File Loading...");
		prop = GetEnv();
		log.info("The properties file was successfully loaded");
	}
	
	public void SynctoLDAP() {
		SearchWEBUsers(GetWEBSessionID());
		JsonNode jn = GetWEBUsers();
		
		String WEB_Columns = prop.getValues("Master_WEB_Column");
		String Master_WEB_Column[] = WEB_Columns.split(",");
		
		String LDAP_Attributes = prop.getValues("Master_LDAP_Attribute");
		String Master_LDAP_Attribute[] = LDAP_Attributes.split(",");
		
		String RDN = "";
		String UserDN = prop.getValues("USER_DN");
		String Suffix = prop.getValues("SUFFIX");
		String FullDN = "";
		String RDN_Attr = prop.getValues("RDN_ATTR");
		String RDN_colu = prop.getValues("RDN_COLU");
		String isWlanOnlyAttr = prop.getValues("IS_WLAN_ONLY_ATTR");
		
		List<String> webUsersDN = new ArrayList<>();
		LDAPOperation LOP = new LDAPOperation();
					
		log.info("----------------------------------------------------------------");
		for (int i=0; i<jn.size(); i++) {
			total_count++;
			Collection<Attribute> AttrSet = new ArrayList<Attribute>();
			
			for (int j=0; j<Master_WEB_Column.length; j++) {
				String TMP = Master_WEB_Column[j];
				if(TMP.equalsIgnoreCase(RDN_colu)){
					RDN = jn.get(i).get(TMP).textValue();
					FullDN = RDN_Attr + "=" + RDN + "," + UserDN + "," + Suffix;
					webUsersDN.add(FullDN);
				}
				if(jn.get(i).hasNonNull(TMP) == true) {
					AttrSet.add(new Attribute(Master_LDAP_Attribute[j], jn.get(i).get(TMP).textValue()));
				} else {
					continue;
				}
			}
			
			log.debug(AttrSet.toString());
//			log.debug(jn.get(i).toPrettyString());
			
			Entry Diff_Entry = new Entry(FullDN);
			for(Attribute ATMP : AttrSet){
				Diff_Entry.setAttribute(ATMP);
			}
			
			boolean Check_Entry = LOP.SearchEntryBoolean(GetLDAPConn(), FullDN);
			
			if(Check_Entry) {
				log.debug(FullDN + " Entry is exist in LDAP.");
				
				List<Modification> SameCheck = LOP.DiffEntry(GetLDAPConn(), Diff_Entry);
				
				if(SameCheck.isEmpty()) {
					log.info(FullDN + " Entry is exist same data in LDAP. Will be skip..");
					skip_count++;
				} else {
					log.info(FullDN + " Entry is exist different data in LDAP. Will be update");
					int num = LOP.modify(GetLDAPConn(), FullDN, SameCheck);
					if(num == 0) {
						m_succ_count++;
					} else {
						m_err_count++;
					}
				}
			} else {
				log.info(RDN + " Entry is not exist in LDAP. Will be add");
				String OBJ_Val = prop.getValues("DEFAULT_ORG_VALS");
				String[] T = OBJ_Val.split(",");
				String OBJ_Vals[] = new String[T.length];
				
				int h = 0;
				for(String OVT : T){
					OBJ_Vals[h] = OVT.split(":")[1];
					h++;
				}
				h = 0;
				
				Diff_Entry.setAttribute("objectclass", OBJ_Vals);
				int num = LOP.add(GetLDAPConn(), Diff_Entry);
				if(num == 0) {
					a_succ_count++;
				} else {
					a_err_count++;
				}
			}
		}
		
		String[] attrs = {};
		List<SearchResultEntry> SearchUserEntries = LOP.SearchEntry(GetLDAPConn(), (UserDN+","+Suffix), "ONE", "objectclass=gistaiUser", attrs);
		
		for(Entry a : SearchUserEntries) {
			boolean isEquals = false;
			for(String b : webUsersDN) {
				if(a.getDN().equals(b)) isEquals = true;
			}
			if(!isEquals) {
				total_count++;
				String isWlanOnlyAttrValue = "";
				if(a.hasAttribute(isWlanOnlyAttr)) {
					isWlanOnlyAttrValue = a.getAttributeValue(isWlanOnlyAttr);
				}
				if(!(isWlanOnlyAttrValue.equalsIgnoreCase("Y"))) {
					log.debug(a.getDN() + " Entry Will be delete");
					int num = LOP.delete(GetLDAPConn(), a.getDN());
					if(num == 0) {
						d_succ_count++;
					} else {
						d_err_count++;
					}
				} else {
					log.info(a.getDN() + " Entry exists in LDAP, but is a Wlan-Only User. Will be skip..");
					LDAP_d_skip_count++;
				}
			} 
		}
		
		log.info("================================================================");
		log.info("GET     WEB   Entry : " + total_count);
		log.info("----------------------------------------------------------------");
		log.info("SUCCESS TOTAL Entry : " + (a_succ_count + m_succ_count + d_succ_count));
		log.info("SKIP          Entry : " + (skip_count + LDAP_d_skip_count));
		log.info("ERROR   TOTAL Entry : " + (a_err_count + m_err_count + d_err_count));
		log.info("================================================================");
		log.info("SUCCESS ADD   Entry : " + a_succ_count);
		log.info("FAIL    ADD   Entry : " + a_err_count);
		log.info("----------------------------------------------------------------");
		log.info("SUCCESS MOD   Entry : " + m_succ_count);
		log.info("FAIL    MOD   Entry : " + m_err_count);
		log.info("SKIP    MOD   Entry : " + skip_count);
		log.info("----------------------------------------------------------------");
		log.info("SUCCESS DEL   Entry : " + d_succ_count);
		log.info("FAIL    DEL   Entry : " + d_err_count);
		log.info("SKIP    DEL   Entry : " + LDAP_d_skip_count);
		log.info("================================================================");
		
	}
}
