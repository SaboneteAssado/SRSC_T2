//package server;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
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

		//		System.setProperty("javax.net.debug", "all");   

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
		HashMap<String,Tokeninfo> tokens = new HashMap<String, Tokeninfo>();

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

			//server clientsocket
			SSLSocketFactory f = sc.getSocketFactory();

			String m = "Welcome!";
			w.write(m,0,m.length());
			w.newLine();
			w.flush();

			while ( (m=r.readLine())!= null ) {
				if (m.equals(".")) break;

				System.out.println("recebi m = " + m);
				String[] arr = m.split(" ");

				if ( arr[0].equals("login") ) {
					if ( arr.length == 3) {
						String username = arr[1];
						String pw = arr[2];
						login( username, pw, f, w, tokens);
					}
					else {
						m = "arg size != 3";
						w.write(m,0,m.length());
					}
				}
				else if ( arr[0].equals("ls") ) {
					if ( arr.length == 3) {
						String username = arr[1];
						if ( arr[2] == null ) {
							m = "Please login first";
							w.write(m,0,m.length());
						}
						else {
							String token = arr[2];
							Tokeninfo info = tokens.get(token);
							ls(username, info, f, w);
						}

					}
					else {
						m = "arg size != 2";
						w.write(m,0,m.length());
					}
				}

				else if ( arr[0].equals("put") ) {
					if ( arr.length == 5) {
						String username = arr[1];
						String path = arr[2];
						String token = arr[3];
						String filename = arr[4];
						Tokeninfo info = tokens.get(token);
						put(username, info, path, filename, f, w, r, c);
					}
					else {
						m = "arg size != 3";
						w.write(m,0,m.length());
					}

				}

				else if ( arr[0].equals("get") ) {
					if ( arr.length == 4) {
						String username = arr[1];
						String path = arr[2];
						String token = arr[3];
						Tokeninfo info = tokens.get(token);
					}
					else {
						m = "arg size != 3";
						w.write(m,0,m.length());
					}
				}

				else if ( arr[0].equals("cp") ) {
					if ( arr.length == 5) {
						String username = arr[1];
						String path1 = arr[2];
						String path2 = arr[3];
						String token = arr[4];
						Tokeninfo info = tokens.get(token);
					}
					else {
						m = "arg size != 4";
						w.write(m,0,m.length());
					}
				}

				else if ( arr[0].equals("rm") ) {
					if ( arr.length == 4) {
						String username = arr[1];
						String path = arr[2];
						String token = arr[3];
						Tokeninfo info = tokens.get(token);
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

	private static void ls(String username, Tokeninfo info, SSLSocketFactory f, BufferedWriter w)
			throws UnknownHostException, IOException {
		String m;
		if ( info != null ) {
			if ( tokenCheck(info.expire)){
				m = "Token revoked, please reauthenticate";
				w.write(m);
			}
			else {
				SSLSocket tempc = (SSLSocket) f.createSocket("localhost", 9002 );

				tempc.startHandshake();

				BufferedWriter tempw = new BufferedWriter(new OutputStreamWriter(
						tempc.getOutputStream()));
				BufferedReader tempr = new BufferedReader(new InputStreamReader(
						tempc.getInputStream()));

				m = username + " " + info.nome;

				tempw.write(m,0,m.length());
				tempw.newLine();
				tempw.flush();

				m = tempr.readLine();
				String[] arr = m.split(" ");

				if ( arr[0].equals("denied")) {
					m = "Access Denied";
					w.write(m,0,m.length());
				}
				else if ( arr[0].equals("allow") ){
					for ( int i = 1; i<arr.length; i++) {
						if( arr[i].equals("read")) {

							tempc = (SSLSocket) f.createSocket("localhost", 9003 );
							tempc.startHandshake();

							tempw = new BufferedWriter(new OutputStreamWriter(
									tempc.getOutputStream()));
							tempr = new BufferedReader(new InputStreamReader(
									tempc.getInputStream()));

							m = "ls " + username;

							tempw.write(m,0,m.length());
							tempw.newLine();
							tempw.flush();

							m = tempr.readLine();
							w.write(m,0,m.length());
						}
					}
				}
			}

		}
	}
	
	private static void put(String username, Tokeninfo info, String path, String filename,
			SSLSocketFactory f, BufferedWriter w, BufferedReader r, SSLSocket c)
			throws UnknownHostException, IOException {
		String m;
		if ( info != null ) {
			if ( tokenCheck(info.expire)){
				m = "Token revoked, please reauthenticate";
				w.write(m);
			}
			else {
				SSLSocket tempc = (SSLSocket) f.createSocket("localhost", 9002 );

				tempc.startHandshake();

				BufferedWriter tempw = new BufferedWriter(new OutputStreamWriter(
						tempc.getOutputStream()));
				BufferedReader tempr = new BufferedReader(new InputStreamReader(
						tempc.getInputStream()));

				m = username + " " + info.nome;

				tempw.write(m,0,m.length());
				tempw.newLine();
				tempw.flush();

				m = tempr.readLine();
				String[] arr = m.split(" ");

				if ( arr[0].equals("denied")) {
					m = "Access Denied";
					w.write(m,0,m.length());
				}
				else if ( arr[0].equals("allow")){
					for ( int i = 1; i<arr.length; i++) {
						if( arr[i].equals("write")) {
							
							tempc = (SSLSocket) f.createSocket("localhost", 9003 );
							tempc.startHandshake();

							tempw = new BufferedWriter(new OutputStreamWriter(
									tempc.getOutputStream()));
							tempr = new BufferedReader(new InputStreamReader(
									tempc.getInputStream()));

							m = "put " + username + " " + filename;

							tempw.write(m,0,m.length());
							tempw.newLine();
							tempw.flush();

							m = tempr.readLine();
							
							m = "file";
							w.write(m,0,m.length());
					        
					        InputStream is = c.getInputStream();
					        OutputStream os = tempc.getOutputStream();
					        copy(is, os);
					        os.close();
					        is.close();
					        
							w.write(m,0,m.length());
						}
					}
				}
			}

		}
	}

	private static void login( String username, String pw, SSLSocketFactory f,
			BufferedWriter w, HashMap<String,Tokeninfo> tokens) throws UnknownHostException, IOException, NoSuchAlgorithmException {
		
		String m;
		SSLSocket tempc = (SSLSocket) f.createSocket("localhost", 9001 );

		tempc.startHandshake();

		BufferedWriter tempw = new BufferedWriter(new OutputStreamWriter(
				tempc.getOutputStream()));
		BufferedReader tempr = new BufferedReader(new InputStreamReader(
				tempc.getInputStream()));

		m = username + " " + pw;

		tempw.write(m,0,m.length());
		tempw.newLine();
		tempw.flush();

		m = tempr.readLine();

		String[] tmp = m.split(":");
		if ( tmp[0].equals("FALSE")) {
			System.out.println("Failed Login Attempt");
			m = "LoginFailed";
			w.write(m,0,m.length());
		}
		else {
			SecureRandom random = new SecureRandom();
			byte[] bytes = new byte[64];
			random.nextBytes(bytes);
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] hash = md.digest(bytes);
			String token = Base64.getEncoder().encodeToString(hash);
			tokens.put( token, new Tokeninfo(username, System.currentTimeMillis()+ 300000) );
			m = "LoginSuccess " + token;
			w.write(m, 0, m.length());
		}
	}

	private static boolean tokenCheck( Long expire) {
		if ( System.currentTimeMillis() >	expire ) {
			System.out.println("tempo do sistema = " + System.currentTimeMillis());
			System.out.println("tempo limite do token = " + expire);
			return false;
		}
		else return true;
	}
	
	static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int len = 0;
        while ((len = in.read(buf)) != -1) {
            out.write(buf, 0, len);
        }
    }
	
	private static class Tokeninfo {
		long expire;
		String nome;
		
		public Tokeninfo ( String nome, long expire ) {
			this.nome = nome;
			this.expire = expire;
		}
	}
}
