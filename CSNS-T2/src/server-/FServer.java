//package server;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Properties;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class FServer {

	private static final String SERVERTLS_CONFIG_PATH = "/home/sd2018/git/SRSC_T2/CSNS-T2/src/server-/servertls.conf";
	private static Properties properties;

	public static void main(String[] args) {

		System.setProperty("javax.net.debug", "all");   

		try {
			properties = loadProperties(SERVERTLS_CONFIG_PATH);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		String ksName = "fserver.jks";
		char[]  ksPass = "fserver1".toCharArray();   // password da keystore
		char[]  ctPass = "fserver1".toCharArray();  // password entry
		int port= Integer.parseInt("9000");
		String[] confciphersuites= {properties.getProperty("CIPHERSUITS")};
		String confprotocols=properties.getProperty("TLS-PROT-ENF");
		String authType = properties.getProperty("TLS-AUTH");
		HashMap<String,String> tokens = new HashMap<String,String>();

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

			if ( authType.equals("MUTUAL")) {
				s.setNeedClientAuth(true);
			}

			System.out.println("Server ready...");
			SSLSocket c = (SSLSocket) s.accept();
			
			BufferedWriter w = new BufferedWriter(new OutputStreamWriter(
					c.getOutputStream()));
			BufferedReader r = new BufferedReader(new InputStreamReader(
					c.getInputStream()));


			String m = "Welcome!";
			w.write(m,0,m.length());
			w.newLine();
			w.flush();

			while ( (m=r.readLine())!= null ) {


				if (m.equals("logout")) break;

				String[] arr = m.split(" ");

				if ( arr[0].equals("login") ) {
					if ( arr.length == 3) {
						String username = arr[1];
						String pw = arr[2];

						try {
							SSLSocketFactory f = sc.getSocketFactory();
							SSLSocket tempc = (SSLSocket) f.createSocket("localhost", 9001 );

							tempc.startHandshake();

							System.out.println("handshaked");
							BufferedWriter tempw = new BufferedWriter(new OutputStreamWriter(
									tempc.getOutputStream()));
							BufferedReader tempr = new BufferedReader(new InputStreamReader(
									tempc.getInputStream()));


							System.out.println("crieiwriters");
							m = username + " " + pw;

							System.out.println("valor de m = " + m);
							tempw.write(m,0,m.length());
							tempw.newLine();
							tempw.flush();

							System.out.println("esperando resposta de auth");
							m = tempr.readLine();

							//check
							System.out.println(m);


							String[] tmp = m.split(":");
							if ( tmp[5].equals("FALSE")) {
								System.out.println("failed login");
								m = "Login failed :(";
								w.write(m,0,m.length());
							}
							else {
								SecureRandom random = new SecureRandom();
								byte[] bytes = new byte[2048];
								random.nextBytes(bytes);
								tokens.put( tmp[1],(System.currentTimeMillis() + 300000) + " " + bytes );
								m = "Success " + bytes;
								w.write(m, 0, m.length());
								System.out.println(m);
							}
						}catch (Exception e) {
							System.err.println(e.toString());
						}
					}
					else {
						m = "arg size != 3";
						w.write(m,0,m.length());
					}
				}

				else if ( arr[0].equals("ls") ) {
					String username = arr[1];
				}

				else if ( arr[0].equals("put") ) {
					if ( arr.length != 3) {
						String username = arr[1];
						String path = arr[2];
					}
					else {
						m = "arg size != 3";
						w.write(m,0,m.length());
					}

				}

				else if ( arr[0].equals("get") ) {
					if ( arr.length != 3) {
						String username = arr[1];
						String path = arr[2];
					}
					else {
						m = "arg size != 3";
						w.write(m,0,m.length());
					}
				}

				else if ( arr[0].equals("cp") ) {
					if ( arr.length != 4) {
						String username = arr[1];
						String path1 = arr[2];
						String path2 = arr[3];
					}
					else {
						m = "arg size != 4";
						w.write(m,0,m.length());
					}
				}

				else if ( arr[0].equals("rm") ) {
					if ( arr.length != 3) {
						String username = arr[1];
						String path = arr[2];
					}
					else {
						m = "arg size != 3";
						w.write(m,0,m.length());
					}
				}

				w.newLine();
				w.flush();

			}

			w.close();
			r.close();
			c.close();
			s.close();
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