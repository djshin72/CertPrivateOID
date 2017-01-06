package com.etax;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;

import javax.crypto.EncryptedPrivateKeyInfo;

public class PrivateKeyOIDCheck {

	private static SimpleDateFormat dateformat = new SimpleDateFormat("yyyy-MM-dd");
	private static final Object X509_AlgorithmId = "1.2.410.200004.1.15";
	private static final CharSequence SHA256withRSA_OID = "1.2.840.113549.1.1.11";

	public static void main(String[] args) throws Exception {
		
		//getPublicKey("C:/temp/cert/signCert_dj.der");
		//getPrivateKey("C://temp//cert//signPri_dj.key");
		
		getPublicKey("SignCert_yj.der");
		getPrivateKey("SignPri_yj.key");
		
		//PublicKey publicKey = getPublicKey("signCert.der");
		//getPrivateKey("signPri.key");
		
	}
	
	public static PublicKey getPublicKey(String file) throws Exception {
		X509Certificate cert = null;
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(new File(file));
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
			cert = (X509Certificate) certificateFactory.generateCertificate(fis);
		} finally {
			if (fis != null) try {fis.close();} catch(IOException ie) {}
		}
		
		System.out.println("1. Cert Information    				: " + cert.getSubjectX500Principal());
		System.out.println("2. Effective Date      				: " + dateformat.format(cert.getNotBefore()));
		System.out.println("3. Expire Date         				: " + dateformat.format(cert.getNotAfter()));

		if (cert.getSigAlgOID().contains(SHA256withRSA_OID)) {
			System.out.println("4. Sign Algorithm OID  				: SHA256withRSA(" + cert.getSigAlgOID() + ")");
		}
		return cert.getPublicKey();
	}

	public static PrivateKey getPrivateKey(String file) {
			
		try {
			byte[] encodedKey = null;
			FileInputStream fis = null;
			ByteArrayOutputStream bos = null;
			try {
				fis = new FileInputStream(new File(file));
				bos = new ByteArrayOutputStream();
				byte[] buffer = new byte[1024];
				int read = -1;
				while ((read = fis.read(buffer)) != -1) {
					bos.write(buffer, 0, read);
				}
				encodedKey = bos.toByteArray();
			} finally {
				if (bos != null) try {bos.close();} catch(IOException ie) {}
				if (fis != null) try {fis.close();} catch(IOException ie) {}
			}
			
			//System.out.println("EncodedKey : " + ByteUtils.toHexString(encodedKey));
			//1.2.840.113549.1.5.13
					
		
			EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(encodedKey);
			System.out.println("6. Encrypted PrivateKey Info(OID)   	        : " + encryptedPrivateKeyInfo.getAlgName());
			
			if (encryptedPrivateKeyInfo.getAlgName().equals(X509_AlgorithmId)) {
				System.out.println("   > check private key......OK");
			} else {
				System.out.println("   > check private key......Fail");
			}
					
		} catch (Exception e) {
			System.out.println("6. Encrypted PrivateKey Info(OID)   	        : " + e.getMessage());
			System.out.println("   > check private key......Fail");
			e.printStackTrace();
		}
		return null;
	}
	

}
