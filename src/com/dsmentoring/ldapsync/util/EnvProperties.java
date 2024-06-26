package com.dsmentoring.ldapsync.util;

import java.io.FileInputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.jasypt.properties.EncryptableProperties;

public class EnvProperties {
	private Hashtable<String, String> _env = new Hashtable<String, String>();
	private final String _defaultEnvFile = "conf/LdapSync.properties";
	private boolean _isEnvLoadFailed = false;
	private static final String ENCRYPT_KEY = "gistaiWEBtoLDAPProperties";
	
	public EnvProperties(String userFile) {
		String algorithm = "PBEWITHSHA256AND128BITAES-CBC-BC";
	    SimpleStringPBEConfig pbeConfig = new SimpleStringPBEConfig();
	    pbeConfig.setAlgorithm(algorithm);
	    pbeConfig.setPassword(ENCRYPT_KEY);
	    BouncyCastleProvider bcprov = new BouncyCastleProvider();
	    pbeConfig.setProvider(bcprov);
	    
	    StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
	    encryptor.setConfig(pbeConfig);
		
		Properties properties = new EncryptableProperties(encryptor);
		FileInputStream fin = null;
		
		try {
			if (userFile != null && userFile.length() > 0){
				fin = new FileInputStream(userFile);
			}else{
				fin = new FileInputStream(_defaultEnvFile);
			}
			properties.load(fin);
		} catch (Exception ex) {
			//ex.printStackTrace();
			_isEnvLoadFailed = true;
		} finally {
			try {
				if (fin != null){
					fin.close();
				}
			}catch(Exception e) {
			}
		}

		if (!_isEnvLoadFailed) {
			try {
				Enumeration<?> keys = properties.propertyNames();
				while (keys.hasMoreElements()) {
					String key = (String) keys.nextElement();
					String value = new String(properties.getProperty(key).getBytes("8859_1"), "KSC5601");
					_env.put(key, value);
				}
			}catch(Exception e) {
			}
		}
	}
	
	public String getValues(String name) {
		String value = (String) _env.get(name);
		return value;
	}
}
