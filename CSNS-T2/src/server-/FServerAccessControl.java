import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.KeyStore;
import java.util.Properties;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class FServerAccessControl {

	private static final String SERVERTLS_CONFIG_PATH = "/home/sd2018/git/SRSC_T2/CSNS-T2/src/server-/servertls.conf";
	private static final String ROOT = "/home/sd2018/git/SRSC_T2/CSNS-T2/src/server-/";
	private static Properties properties, accessprops;


	public static void main(String[] args) {
//		System.setProperty("javax.net.debug", "all");   

		try {
			properties = loadProperties(SERVERTLS_CONFIG_PATH);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		String ksName = "fserveraccess.jks";
		char[]  ksPass = "fserveraccess1".toCharArray();   // password da keystore
		char[]  ctPass = "fserveraccess1".toCharArray();  // password entry
		int port= Integer.parseInt("9002");
		String[] confciphersuites= {properties.getProperty("CIPHERSUITS")};
		String confprotocols=properties.getProperty("TLS-PROT-ENF");

		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(ksName), ksPass);
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, ctPass);

			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(kmf.getKeyManagers(), null, null);

			SSLServerSocketFactory ssf = sc.getServerSocketFactory();
			SSLServerSocket s = (SSLServerSocket) ssf.createServerSocket(port);

			if ( confprotocols.equals("TLS-1.1") ) {
				String[] protocols={"TLSv1.1"};
				s.setEnabledProtocols(protocols);
			}
			else if ( confprotocols.equals("TLS-1.2") ) {
				String[] protocols={"TLSv1.2"};
				s.setEnabledProtocols(protocols);
			}

			s.setEnabledCipherSuites(confciphersuites);

			System.out.println("Server ready...");
			SSLSocket c = (SSLSocket) s.accept();

			BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
					c.getOutputStream()));
			BufferedReader r = new BufferedReader(new InputStreamReader(
					c.getInputStream()));
			
			String m = null;
			String[] arr = null;
			while ( true ) {
				
				m = r.readLine();
				arr = m.split(" ");
				
				String path = arr[0];
				String user = arr[1];
				
				try {
					path = ROOT + "/" + path + "access.conf";
					System.out.println("a tentar aceder: path");
					accessprops = loadProperties(path);
				}catch (Exception e) {
					System.err.println(e.toString());
				}
				
				m = accessprops.getProperty(user);
				System.out.println("permissoes de (" + user + "): " + m);
				
				w.write(m,0,m.length());
				w.newLine();
				w.flush();
				System.out.println("Access checked... waiting");
			}
			
			
		}catch (Exception e) {
			System.err.println(e.toString());
		}
	}
	
	private static Properties loadProperties(String path) throws IOException {
		InputStream inputStream = new FileInputStream(path);

		Properties properties = new Properties();
		properties.load(inputStream);

		inputStream.close();
		return properties;
	}
}