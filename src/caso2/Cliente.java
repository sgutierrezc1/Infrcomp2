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
	private final static String[] ALGORITMOS = {"AES","RSA","HMACSHA1"};
	private final static String PADDING="/ECB/PKCS5Padding";
	private Socket socket;
	private BufferedReader reader; 
	private static PrintWriter writer;
	private SecretKey llaveSesion;
	private X509Certificate serverCert;
	private X509Certificate clientCert;
	private KeyPair kp;
	
	
	public Cliente() throws Exception{
		kp = Encriptacion.crearLlaves();
		clientCert = Encriptacion.crearCertificado(kp);
	}
	
	public boolean enviarPosicion(String posicion) throws Exception
	{	
		conectar();
		inicar();
		enviarAlgoritmos();
		enviarCertificado();
		recibirCertServer();
		recibirLlave();
		
		
		byte[] cipher = Encriptacion.cifrar(posicion.getBytes(),llaveSesion, ALGORITMOS[0]+PADDING);
		writer.println("ACT1:"+pasarAString(cipher));
		
		
		byte[] mac = Encriptacion.calcularMAC(posicion.getBytes(), llaveSesion, ALGORITMOS[2]);
	    writer.println("ACT2:"+pasarAString(Encriptacion.cifrar(mac, serverCert.getPublicKey(),ALGORITMOS[1])));
	    
	    String linea = reader.readLine();
	   
	    
	    return linea.equals("ESTADO:OK");
	}
	
	private void conectar() throws Exception{
		socket = new Socket("localhost", 6000);
		reader = new BufferedReader( new InputStreamReader( socket.getInputStream( ) ) );
		writer = new PrintWriter( socket.getOutputStream( ), true );
		
	}
	
	private boolean inicar() throws IOException
	{
		writer.println("HOLA");
		String rta = reader.readLine();
		return rta.equals("INICIO");
	}
	
	private boolean enviarAlgoritmos() throws Exception
	{
		String msj = null;
		for(String s: ALGORITMOS)
			if(msj==null)
				msj="ALGORITMOS:"+s;
			else msj+= ":"+s;
		writer.println(msj);
		String rta=  reader.readLine();
		return rta.equals("ESTADO:OK");
	}
	
	private void enviarCertificado() throws Exception
	{
		writer.println("CERTCLNT");
		socket.getOutputStream().write(clientCert.getEncoded());
		socket.getOutputStream().flush();
		System.out.println("SRV: "+reader.readLine());
		System.out.println("SRV: "+reader.readLine());
		writer.println("ESTADO:OK");
		
		
	}
	
	private void recibirCertServer() throws Exception
	{
		byte[] bytes2 = new byte[1000];
		bytes2= Arrays.copyOf(bytes2, socket.getInputStream().read(bytes2));
		System.out.print(new String(bytes2));
		serverCert = (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes2));
	}
	
	private void recibirLlave() throws Exception
	{
		String linea = reader.readLine();
        byte[] data = extraer(linea.split(":")[1]);
        
	    byte[] llave = Encriptacion.descifrar(data , kp.getPrivate(),ALGORITMOS[1]);
	    
		llaveSesion =  new SecretKeySpec(llave, 0, llave.length, ALGORITMOS[1]);
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
