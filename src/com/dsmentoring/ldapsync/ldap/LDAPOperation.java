package com.dsmentoring.ldapsync.ldap;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;

public class LDAPOperation {
	private static Logger log = LogManager.getLogger(LDAPOperation.class);
	
	public boolean SearchEntryBoolean(LDAPConnection conn, String DN) {
		boolean isExist = false;
		
		try{
			SearchResult SRE = conn.search(DN, SearchScope.BASE, "objectclass=*");
			if(!(SRE.getEntryCount() == 0)){
				isExist = true;
			}
		}catch(LDAPException E){
			if(E.getResultCode().intValue() == 32){
			}else{
				log.error("Entry Search fail...");
				log.error(E);
			}			
		}
		return isExist;
	}
	
	public List<SearchResultEntry> SearchEntry(LDAPConnection conn, String searchBase, String scope, String filter, String[] attrs) {
		SearchScope srchScope = SearchScope.BASE;
		switch (scope.toUpperCase()) {
			case "BASE":
				srchScope = SearchScope.BASE;
				break;
			case "ONE":
				srchScope = SearchScope.ONE;
				break;
			case "SUB":
				srchScope = SearchScope.SUB;
		}

		List<SearchResultEntry> srchEntries = null;
		try {
			SearchResult srchResults = conn.search(searchBase, srchScope, filter, attrs);
			srchEntries = srchResults.getSearchEntries();
		} catch(LDAPException le) {
			log.error(le.getResultCode() + ": " + le.getResultString());
		}
		
		return srchEntries;

	}
	
	public List<Modification> DiffEntry(LDAPConnection conn, Entry Diff_Entry) {
		String[] AttributeNames = new String[Diff_Entry.getAttributes().size()];
		Collection<Attribute> Attrs = Diff_Entry.getAttributes();
		Iterator<Attribute> AI = Attrs.iterator();
		
		int k = 0;
		while(AI.hasNext()){
			Attribute A = AI.next();
			AttributeNames[k] = A.getName();
			k++;
		}
		k = 0;
		
		List<Modification> LM = new ArrayList<Modification>();
		
		try{
			SearchResult SRE = conn.search(Diff_Entry.getDN(), SearchScope.BASE, "objectclass=*");
			List<SearchResultEntry> List_RE = SRE.getSearchEntries();
			
			for(SearchResultEntry RE : List_RE){
				LM = Entry.diff(RE, Diff_Entry, false, false, AttributeNames);				
			}
		}catch(Exception E){
			log.error("Entry Diff fail...");
			log.error(E);
		}
		return LM;
	}
	
	public int modify(LDAPConnection conn, String DN, List<Modification> Mod){
		int num = 0;
		try{
			conn.modify(DN, Mod);
			log.info(DN.split("=")[1] + " Entry update success");
		}catch(Exception E){
			num = 1;
			log.error(DN.split("=")[1] + " Entry update fail");
			log.error(E);
		}
		return num;
	}
	
	public int add(LDAPConnection conn, Entry Entry){
		int num = 0;
		try{
			conn.add(Entry);
			log.info(Entry.getDN().split("=")[1].split(",")[0] + " Entry add success");
		}catch(Exception E){
			num = 1;
			log.error(Entry.getDN().split("=")[1] + " Entry add fail");
			log.error(E);
		}
		return num;
	}
	
	public int delete(LDAPConnection conn, String DN){
		int num = 0;
		try{
			conn.delete(DN);
			log.info(DN.split("=")[1] + " Entry delete success");
		}catch(LDAPException E){
			if(E.getResultCode().intValue() == 32){
				log.debug("Entry is already Deleted");
			}else{
				log.error(DN.split("=")[1] + " Entry delete fail");
				log.error(E);
				num = 1;
			}
		}
		return num;
	}
}
