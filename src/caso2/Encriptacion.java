package caso2;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Encriptacion {
	

	public static KeyPair generacionDeLlaves() throws Exception
	{
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024, new SecureRandom());
		return gen.generateKeyPair();
	}


	public static byte[] calculoDelMac(byte[] mensaje, Key llave1, String alg) throws Exception
	{
		Mac mac = Mac.getInstance(alg);
		mac.init(llave1);
		return mac.doFinal(mensaje);
	}
	

	public static byte[] decriptar(byte [] mensaje, Key llave11, String alg) throws Exception
	{ 
		Cipher cifrado = Cipher.getInstance(alg); 
		cifrado.init(Cipher.DECRYPT_MODE, llave11);
		return cifrado.doFinal(mensaje); 
	}

	
	public static X509Certificate crearCertificadoCliente(KeyPair par) throws Exception
	{
		Date fecha= new Date();
		System.out.println(fecha);

		Date fechaVenc = new Date(119,0,1);              
		BigInteger num = new BigInteger(32,new Random());
		X509V3CertificateGenerator certif = new X509V3CertificateGenerator();
		X500Principal  nombre= new X500Principal("CN=Test V3 Certificate");

		certif.setSerialNumber(num);
		certif.setIssuerDN(new X500Principal("CN=Test Certificate"));
		certif.setNotBefore(fecha);
		certif.setNotAfter(fechaVenc);
		certif.setSubjectDN(nombre);
		certif.setPublicKey(par.getPublic());
		certif.setSignatureAlgorithm("SHA256WithRSAEncryption");


		Security.addProvider(new BouncyCastleProvider());

		return  certif.generate(par.getPrivate(), "BC");  

	}


	public static byte[] encriptar(byte[] mensaje, Key llave1, String alg) throws Exception
	{
		Cipher cifrado = Cipher.getInstance(alg);
		cifrado.init(Cipher.ENCRYPT_MODE, llave1);
		return cifrado.doFinal(mensaje);
	}
}