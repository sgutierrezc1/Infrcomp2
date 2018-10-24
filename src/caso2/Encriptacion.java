package caso2;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Encriptacion {
	public static byte[] descifrar(byte [] data, Key llave, String algoritmo) throws Exception
	{ 
		Cipher cipher = Cipher.getInstance(algoritmo); 
		cipher.init(Cipher.DECRYPT_MODE, llave);
		return cipher.doFinal(data); 
	}

	public static byte[] cifrar(byte[] data, Key llave, String algoritmo) throws Exception
	{
		Cipher cipher = Cipher.getInstance(algoritmo);
		cipher.init(Cipher.ENCRYPT_MODE, llave);
		return cipher.doFinal(data);
	}
	
	public static byte[] calcularMAC(byte[] data, Key llave, String algoritmo) throws Exception
	{
	    Mac mac = Mac.getInstance(algoritmo);
	    mac.init(llave);
	    return mac.doFinal(data);
	}
	
	public static KeyPair crearLlaves() throws Exception
	{
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024, new SecureRandom());
	    return keyGen.generateKeyPair();
	}
	
	public static X509Certificate crearCertificado(KeyPair pair) throws Exception
	{
		Date startDate = new Date();
		System.out.println(startDate);

		Date expiryDate = new Date(119,0,1);              
		BigInteger serialNumber = new BigInteger(32,new Random());
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal subjectName = new X500Principal("CN=Test V3 Certificate");
		 
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(subjectName);
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		
		
		Security.addProvider(new BouncyCastleProvider());
		
		return  certGen.generate(pair.getPrivate(), "BC");  
		  
	}
	
	public static Key generarLlave(String algoritmo) throws NoSuchAlgorithmException
	{
		KeyGenerator keygen = KeyGenerator.getInstance(algoritmo);
		return keygen.generateKey();
	}
}
