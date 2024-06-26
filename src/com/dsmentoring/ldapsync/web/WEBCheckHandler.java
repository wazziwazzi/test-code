package com.dsmentoring.ldapsync.web;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.dsmentoring.ldapsync.util.EnvProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class WEBCheckHandler {
	private static Logger log = LogManager.getLogger(WEBCheckHandler.class);
	protected JsonNode jn = null;
	
	public WEBCheckHandler(String webSessionID, EnvProperties prop) {
		String WEB_URL = prop.getValues("WEB_URL");
		String WEB_SRCHUSER_URI = prop.getValues("WEB_SRCHUSER_URI");
		
		try {
			log.debug("----------------------------------------------------------------");
			log.debug("WEB_SRCHUSER_URI: " + (WEB_URL + WEB_SRCHUSER_URI));
			log.debug("----------------------------------------------------------------");
			
			if (webSessionID == null) {
				log.error("You must login first... Session ID not found!");
				System.exit(1);
			}

	//		URL url = new URL("https://127.0.0.1:443/api/users/1002010");
			URL url = new URL(WEB_URL + WEB_SRCHUSER_URI);
			ignoreSsl();
			HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
	
			con.setRequestMethod("GET");
			con.setRequestProperty("Accept-Charset", "UTF-8");
			con.setRequestProperty("bs-session-id", webSessionID);
			con.setConnectTimeout(10000);	// ms
			con.setReadTimeout(10000);		// ms

			int responseCode = con.getResponseCode();
			
			Map<String, List<String>> map = con.getHeaderFields();
			log.debug("Search Users Response Header: " + map.toString());	
			
			InputStream inputStream = null;
			if (responseCode == 200) {
				inputStream = con.getInputStream();
				BufferedReader in = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
				String inputLine;
				StringBuffer response = new StringBuffer();
				
				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine);
				}
				
				in.close();
				
				ObjectMapper mapper = new ObjectMapper();
				jn = mapper.readTree(response.toString()).get("UserCollection").get("rows");
			} else {
				inputStream = con.getErrorStream();
				log.info("Failed to search users to " + WEB_URL);
			}
		} catch (Exception ex) {
			log.error("Failed to search users... Check the web status or web connection info or network.");
			log.error(ex);
			System.exit(1);
		}
	}
	
	public JsonNode GetWEBUsers(){
		return jn;
	}
	
	public static void ignoreSsl() throws Exception {
        HostnameVerifier hv = new HostnameVerifier() {
        	public boolean verify(String urlHostName, SSLSession session) { return true; }
        };
        trustAllHttpsCertificates();
        HttpsURLConnection.setDefaultHostnameVerifier(hv);
    }

	private static void trustAllHttpsCertificates() throws Exception {
	    TrustManager[] trustAllCerts = new TrustManager[1];
	    TrustManager tm = new miTM();
	    trustAllCerts[0] = tm;
	    SSLContext sc = SSLContext.getInstance("SSL");
	    sc.init(null, trustAllCerts, null);
	    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
	}
	
	static class miTM implements TrustManager,X509TrustManager {
	    public X509Certificate[] getAcceptedIssuers() {
	        return null;
	    }
	
	    public boolean isServerTrusted(X509Certificate[] certs) {
	        return true;
	    }
	
	    public boolean isClientTrusted(X509Certificate[] certs) {
	        return true;
	    }
	
	    public void checkServerTrusted(X509Certificate[] certs, String authType)
	            throws CertificateException {
	        return;
	    }
	
	    public void checkClientTrusted(X509Certificate[] certs, String authType)
	            throws CertificateException {
	        return;
	    }
	}
}
