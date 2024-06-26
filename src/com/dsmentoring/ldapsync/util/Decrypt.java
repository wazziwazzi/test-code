package com.dsmentoring.ldapsync.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.FilenameFilter;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;

public class Decrypt {
	private static Logger log = LogManager.getLogger(Encrypt.class);
	private static final String ENCRYPT_KEY = "gistaiWEBtoLDAPProperties";
	private static String OS = System.getProperty("os.name").toLowerCase();
	private static Properties properties = new Properties();
	
	public static void main(String[] args) {
		LoggerContext context = (org.apache.logging.log4j.core.LoggerContext) LogManager.getContext(false);
		File file = new File("conf/Module-log4j2.xml");
		context.setConfigLocation(file.toURI());
		
		log.info(" ***** Decrypt Module Start ***** ");
		
		GetEnv();
		
		String IN_Path = "";
		String OUT_Path = "";
		try {
			IN_Path = new String(properties.getProperty("Dec_Path_In").getBytes("ISO-8859-1"),"utf-8");
			OUT_Path = new String(properties.getProperty("Dec_Path_Out").getBytes("ISO-8859-1"),"utf-8");
		} catch (UnsupportedEncodingException uee) {
			log.error(uee);
		}
		log.debug("Load Path: " + IN_Path);
		log.debug("Save Path: " + OUT_Path);
		log.debug("----------------------------------------------------------------");
		
		File IN_Files = new File(IN_Path);
		File[] IN_File = null;

		FilenameFilter filter = new FilenameFilter() {
		    public boolean accept(File f, String name) {
		    	String Dec_File_Name = properties.getProperty("Dec_File_Name_Filter");
		    	if (Dec_File_Name.length() == 0) {
		    		Dec_File_Name = "(.*)";
		    	}
		        return name.matches("(.*)" + Dec_File_Name + "(.*)");
		    }
		};
		
		IN_File = IN_Files.listFiles(filter);
		for (File inF : IN_File) {
			String File_Name = inF.getName();
			log.debug(File_Name + " File will be decrypted");
			
			String outF_String = "";
			if(OS.indexOf("win") >= 0) {
				outF_String = OUT_Path + "\\"+ File_Name;						
			} else {
				outF_String = OUT_Path + "/"+ File_Name;
			}
			
			File outF = new File(outF_String);
			if(outF.exists()) {
				log.info(outF_String + " is exist. This file will be skip");
				continue;
			}
			
			try {
				BufferedReader line = new BufferedReader(new FileReader(inF));
				String line_tmp = "";

				String algorithm = "PBEWITHSHA256AND128BITAES-CBC-BC";
			    SimpleStringPBEConfig pbeConfig = new SimpleStringPBEConfig();
			    pbeConfig.setAlgorithm(algorithm);
			    pbeConfig.setPassword(ENCRYPT_KEY);
			    BouncyCastleProvider bcprov = new BouncyCastleProvider();
			    pbeConfig.setProvider(bcprov);
			    
			    StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
			    encryptor.setConfig(pbeConfig);
			    
			    FileWriter write_mapping = new FileWriter(outF_String);
			    
				while((line_tmp = line.readLine()) != null){
					if(line_tmp.contains("=")){
						String Name = line_tmp.split("=", 2)[0];
						String Value = line_tmp.split("=", 2)[1].substring(4);
						write_mapping.write(Name + "=" + encryptor.decrypt(Value.substring(0, Value.length() -1)) + "\n");
					}else{
						write_mapping.write(line_tmp + "\n");
					}
				}
				line.close();
			    write_mapping.flush();
			    write_mapping.close();
			    log.info(File_Name + " File was successfully decrypted");
			}catch(Exception e){
				e.printStackTrace();
			}
		}
		log.info("");
	}
	
	public static void GetEnv() {
		log.info("Properties File Loading...");
		try {
			FileInputStream fin = new FileInputStream("conf/Module.properties");
			int read = 0;
			StringBuilder sb = new StringBuilder();
			while ((read = fin.read()) != -1) {
				sb.append((char)read);
			}
			fin.close();
			properties.load(new StringReader(sb.toString().replace("\\", "\\\\")));
			log.info("The properties file was successfully loaded");
		} catch(Exception PE) {
			log.error("Failed to load properties file");
			log.error(PE);
		} finally {
			log.info("----------------------------------------------------------------");
		}
	}
}
