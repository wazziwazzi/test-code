package com.dsmentoring.ldapsync.web;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
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
import com.fasterxml.jackson.databind.ObjectMapper;

public class WEBSessionHandler {
	private static Logger log = LogManager.getLogger(WEBSessionHandler.class);
	protected String _webSessionID = null;
	
	public WEBSessionHandler(EnvProperties prop) {
		log.info("Check BioStar2 API Login...");
		
		String WEB_URL = prop.getValues("WEB_URL");
		String WEB_LOGIN_URI = prop.getValues("WEB_LOGIN_URI");
		String WEB_ID = prop.getValues("WEB_ID");
		String WEB_PWD = prop.getValues("WEB_PWD");
		
		try {
			log.debug("----------------------------------------------------------------");
			log.debug("WEB_LOGIN_URL: " + (WEB_URL + WEB_LOGIN_URI));
			log.debug("WEB_ID: " + WEB_ID);
			log.debug("WEB_PWD: " + WEB_PWD);
			log.debug("----------------------------------------------------------------");

			HashMap<String,String> loginUser = new HashMap<String,String>();
			loginUser.put("login_id", WEB_ID);
			loginUser.put("password", WEB_PWD);
			
			HashMap<String,Object> login = new HashMap<String,Object>();
			login.put("User", loginUser);

			ObjectMapper mapper = new ObjectMapper();
			String json = mapper.writeValueAsString(login);
			log.debug("Login Request Body(Json): " + json);
			
			URL url = new URL(WEB_URL + WEB_LOGIN_URI);
			ignoreSsl();
			HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
			
			con.setDoOutput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-Type", "application/json"); 
			con.setRequestProperty("Accept-Charset", "UTF-8");
			con.setConnectTimeout(10000);	// ms
			con.setReadTimeout(10000);		// ms
			
			OutputStream os = con.getOutputStream();
			os.write(json.getBytes("UTF-8"));
			os.flush();
			
			int responseCode = con.getResponseCode();			
			
			Map<String, List<String>> map = con.getHeaderFields();
			log.debug("Login Response Header: " + map.toString());
			
			InputStream inputStream = null;
			if (responseCode == 200) {
				inputStream = con.getInputStream();
				log.info(WEB_URL + " login succeeded");	
			} else {
				inputStream = con.getErrorStream();
				log.error("Failed to login to " + WEB_URL);
			}
			
			BufferedReader in = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
			String inputLine;
			StringBuffer response = new StringBuffer();

			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			
			in.close();
			
			log.debug("Login Response Body(Json): " + response.toString());
			
			_webSessionID = con.getHeaderField("bs-session-id");
			
			if (_webSessionID != null) {
				log.debug("bs-session-id: " + _webSessionID);
			} else {
				log.error("Session ID not found");
				System.exit(1);
			}
		} catch (Exception ex) {
			log.error("Failed to login... Check the web status or web connection info or network.");
			log.error(ex);
			System.exit(1);
		} finally {
			log.info("----------------------------------------------------------------");
		}
	}
	
	public String GetWEBSessionID() {
		return _webSessionID;
	}
	
	public void logout(EnvProperties prop) {
		String WEB_URL = prop.getValues("WEB_URL");
		String WEB_LOGOUT_URI = prop.getValues("WEB_LOGOUT_URI");
		
		try {
			log.debug("----------------------------------------------------------------");
			log.debug("WEB_LOGOUT_URL: " + (WEB_URL + WEB_LOGOUT_URI));
			log.debug("----------------------------------------------------------------");
			
			URL url = new URL(WEB_URL + WEB_LOGOUT_URI);
			ignoreSsl();
			HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
			
			con.setRequestMethod("POST");
			con.setRequestProperty("Accept-Charset", "UTF-8");
			con.setRequestProperty("bs-session-id", _webSessionID);
			con.setConnectTimeout(10000);	// ms
			con.setReadTimeout(10000);		// ms
			
			int responseCode = con.getResponseCode();			
			
			Map<String, List<String>> map = con.getHeaderFields();
			log.debug("Logout Response Header: " + map.toString());
			
			if (responseCode == 200) {
				log.info(WEB_URL + " logout completed");
			} else {
				log.info("You must login first...");
			}
		} catch (Exception ex) {
			log.error("Failed to logout... Check the web status or web connection info or network.");
			log.error(ex);
			System.exit(1);
		}
		
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
