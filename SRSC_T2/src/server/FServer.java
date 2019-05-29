package server;

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

public class FServer {

	private static final String SERVERTLS_CONFIG_PATH = "//servertls.config";

	private static Properties properties;

	public static void main(String[] args) throws IOException {

		properties = loadProperties(SERVERTLS_CONFIG_PATH);
		String ksName = args[0];    // serverkeystore
		char[]  ksPass = args[1].toCharArray();   // password da keystore
		char[]  ctPass = args[2].toCharArray();  // password entry
		int port= Integer.parseInt(args[3]);
		String[] confciphersuites={properties.getProperty("CIPHERSUITS")};
		String[] confprotocols={properties.getProperty("TLS-PROT-ENF")};
		
		try {
			//ver
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(ksName), ksPass);
			KeyManagerFactory kmf = 
					KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, ctPass);
			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(kmf.getKeyManagers(), null, null);
			SSLServerSocketFactory ssf = sc.getServerSocketFactory();
			SSLServerSocket s 
			= (SSLServerSocket) ssf.createServerSocket(port);
			
			s.setEnabledProtocols(confprotocols);
			s.setEnabledCipherSuites(confciphersuites);

			SSLSocket c = (SSLSocket) s.accept();

			BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
					c.getOutputStream()));
			BufferedReader r = new BufferedReader(new InputStreamReader(
					c.getInputStream()));c
		}
		catch (Exception e) {
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