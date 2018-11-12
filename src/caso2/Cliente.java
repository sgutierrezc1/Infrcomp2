package caso2;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.spi.TimeZoneNameProvider;

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
	
	private long tiempoRespuesta = 0; 	


	//constructor
	/**
	 * 
	 * @throws Exception
	 */
	public Cliente() throws Exception{
		
		keyPair = Encriptacion.generacionDeLlaves();
		certificadoCliente = Encriptacion.crearCertificadoCliente(keyPair);
	}

	/**
	 * 
	 * @throws Exception
	 */
	private void conectar() throws Exception{
		
		long ini= System.currentTimeMillis();
		socket = new Socket("localhost", 6000);
		reader = new BufferedReader( new InputStreamReader( socket.getInputStream( ) ) );
		pw = new PrintWriter( socket.getOutputStream( ), true );
		long fin= System.currentTimeMillis();
		tiempoRespuesta= fin-ini;
		System.out.println("Timepo en conectar: "+tiempoRespuesta+"ms");

	}

	/**
	 * 
	 * @return
	 * @throws IOException	
	 */
	private boolean inicio() throws IOException{

		pw.println("HOLA");
		String rta = reader.readLine();
		return rta.equals("OK");
	}

	/**
	 * 
	 * @return
	 * @throws Exception
	 */
	private boolean enviarAlgoritmos() throws Exception{

		String msj = "ALGORITMOS";
		for(String s: ALGORITMOS) msj+= ":"+s;

		pw.println(msj);
		String rta=  reader.readLine();
		return rta.equals("ESTADO:OK");
	}

	/**
	 * 
	 * @throws Exception
	 */
	private void enviarCertificado() throws Exception{

		long ini= System.currentTimeMillis();
		pw.println("CERTCLNT");
		socket.getOutputStream().write(certificadoCliente.getEncoded());
		socket.getOutputStream().flush();
		System.out.println("SRV: "+reader.readLine());
		pw.println("ESTADO:OK");
		long fin= System.currentTimeMillis();
		tiempoRespuesta= fin-ini;
		System.out.println("Timepo de envío del certificado: "+tiempoRespuesta+"ms");
	}

	/**
	 * 
	 * @throws Exception
	 */
	private void recibirCertificado() throws Exception{

		
		long ini= System.currentTimeMillis();
		byte[] bytes = new byte[5000];
		socket.getInputStream().read(bytes);
		InputStream input= new ByteArrayInputStream(bytes);
		CertificateFactory factory;
		try {
			factory = CertificateFactory.getInstance("X.509");
			X509Certificate server= (X509Certificate)factory.generateCertificate(input);
			certificadoServidor= server;		
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		long fin= System.currentTimeMillis();
		tiempoRespuesta= fin -ini;
		System.out.println("Tiempo recepción de certificado: "+tiempoRespuesta+"ms");
	}

	/**
	 * 
	 * @throws Exception
	 */
	private void recibirKey() throws Exception{
		String leido = reader.readLine();
		byte[] data = extraer(leido.split(":")[1]);

		byte[] llave = Encriptacion.decriptar(data , keyPair.getPrivate(),ALGORITMOS[1]);

		secretKey =  new SecretKeySpec(llave, 0, llave.length, ALGORITMOS[1]);
	}

	/**
	 * 
	 * @param data
	 * @return
	 */
	private String convertToString(byte[] data){
		String rta = "";
		for (byte b: data)
			rta+= String.format("%2s",Integer.toHexString((char)b & 0xFF)).replace(' ', '0');
		return rta;
	}

	/**
	 * 
	 * @param data
	 * @return
	 */
	private byte[] extraer(String data)
	{
		byte[] rta = new byte[data.length() / 2];
		for (int i = 0; i < rta.length; i++) 
			rta[i] = Integer.decode("#"+data.substring(i * 2, (i + 1) * 2)).byteValue();
		return rta;
	}

	/**
	 * 
	 * @param posicion
	 * @return
	 * @throws Exception
	 */
	public boolean enviarPosicion(String posicion) throws Exception
	{	
		conectar();
		inicio();
		enviarAlgoritmos();
		enviarCertificado();
		recibirCertificado();
		recibirKey();

		byte[] cifrado = Encriptacion.encriptar(posicion.getBytes(),secretKey, ALGORITMOS[0]+PADDING);
		pw.println("ACT1:"+convertToString(cifrado));

		byte[] mac = Encriptacion.calculoDelMac(posicion.getBytes(), secretKey, ALGORITMOS[2]);
		pw.println("ACT2:"+convertToString(Encriptacion.encriptar(mac, certificadoServidor.getPublicKey(),ALGORITMOS[1])));

		String linea = reader.readLine();


		return linea.equals("ESTADO:OK");
	}

	//main
	/**
	 * 
	 * @param args
	 */
	public static void main(String[] args) {
		
//		Generator gen= new Generator();
		ClientServerTask cst= new ClientServerTask();
		cst.execute();
		try{
			Cliente cliente = new Cliente();
			cliente.enviarPosicion("41 24.2028, 2 10.4418");
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}

}
