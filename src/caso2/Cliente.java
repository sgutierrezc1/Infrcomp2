package caso2;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Cliente {

	//atributos
	/**
	 * 
	 */
	private final static String PADDING="/ECB/PKCS5Padding";

	/**
	 * 
	 */
	private final static String[] ALGORITMOS = {"AES", "RSA", "HMACMD5"};

	/**
	 * 
	 */
	private static PrintWriter pw;

	/**
	 * 
	 */
	private SecretKey secretKey;

	/**
	 * 
	 */
	private X509Certificate certificadoServidor;

	/**
	 * 
	 */
	private X509Certificate certificadoCliente;

	/**
	 * 
	 */
	private BufferedReader reader;

	/**
	 * 
	 */
	private Socket socket;

	/**
	 * 
	 */
	private KeyPair keyPair;


	public Cliente() throws Exception{
		keyPair = Encriptacion.generacionDeLlaves();
		certificadoServidor = Encriptacion.crearCertificadoCliente(keyPair);
	}


	private void conectar() throws Exception{
		socket = new Socket("localhost", 6000);
		reader = new BufferedReader( new InputStreamReader( socket.getInputStream( ) ) );
		pw = new PrintWriter( socket.getOutputStream( ), true );

	}

	private boolean inicio() throws IOException
	{
		pw.println("HOLA");
		String rta = reader.readLine();
		return rta.equals("OK");
	}

	private boolean enviarAlgoritmos() throws Exception
	{
		String msj = "ALGORITMOS";
		for(String s: ALGORITMOS) msj+= ":"+s;

		pw.println(msj);
		String rta=  reader.readLine();
		return rta.equals("ESTADO:OK");
	}

	private void enviarCertificado() throws Exception
	{
		pw.println("CERTCLNT");
		socket.getOutputStream().write(certificadoCliente.getEncoded());
		socket.getOutputStream().flush();
		System.out.println("SRV: "+reader.readLine());
		System.out.println("SRV: "+reader.readLine());
		pw.println("ESTADO:OK");


	}

	private void recibirCertServer() throws Exception
	{
		byte[] bytes2 = new byte[1000];
		bytes2= Arrays.copyOf(bytes2, socket.getInputStream().read(bytes2));
		System.out.print(new String(bytes2));
		certificadoServidor = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes2));
	}

	private void recibirLlave() throws Exception
	{
		String linea = reader.readLine();
		byte[] data = extraer(linea.split(":")[1]);

		byte[] llave = Encriptacion.decriptar(data , keyPair.getPrivate(),ALGORITMOS[1]);

		secretKey =  new SecretKeySpec(llave, 0, llave.length, ALGORITMOS[1]);
	}

	private String pasarAString(byte[] data)
	{
		String rta = "";
		for (byte b: data)
			rta+= String.format("%2s",Integer.toHexString((char)b & 0xFF)).replace(' ', '0');
		return rta;
	}

	private byte[] extraer(String data)
	{
		byte[] rta = new byte[data.length() / 2];
		for (int i = 0; i < rta.length; i++) 
			rta[i] = Integer.decode("#"+data.substring(i * 2, (i + 1) * 2)).byteValue();
		return rta;
	}
	
	public boolean enviarPosicion(String posicion) throws Exception
	{	
		conectar();
		inicio();
		enviarAlgoritmos();
		enviarCertificado();
		recibirCertServer();
		recibirLlave();
		
		
		byte[] cipher = Encriptacion.encriptar(posicion.getBytes(),secretKey, ALGORITMOS[0]+PADDING);
		pw.println("ACT1:"+pasarAString(cipher));
		
		
		byte[] mac = Encriptacion.calculoDelMac(posicion.getBytes(), secretKey, ALGORITMOS[2]);
		pw.println("ACT2:"+pasarAString(Encriptacion.encriptar(mac, certificadoServidor.getPublicKey(),ALGORITMOS[1])));
		
		String linea = reader.readLine();
		
		
		return linea.equals("ESTADO:OK");
	}

	public static void main(String[] args) {
		try{
			Cliente c = new Cliente();
			c.enviarPosicion("41 24.2028, 2 10.4418");
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}

}
