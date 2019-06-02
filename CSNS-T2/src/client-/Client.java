import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Client {

	public static void main(String[] args) {

		System.setProperty("javax.net.debug", "all");
		
		BufferedReader in = new BufferedReader(
				new InputStreamReader(System.in));
		PrintStream out = System.out;

		String token = null;
		
		try {

			/*
			 * Set up a key manager for client authentication
			 * if asked by the server.  Use the implementation's
			 * default TrustStore and secureRandom routines.
			 */
			SSLSocketFactory f = null;
			try {
				SSLContext ctx;
				KeyManagerFactory kmf;
				KeyStore ks;
				
				char[] passphrase = "client1".toCharArray();//		

				ctx = SSLContext.getInstance("TLS");
				kmf = KeyManagerFactory.getInstance("SunX509");
				ks = KeyStore.getInstance("JKS");

				ks.load(new FileInputStream("client.jks"), passphrase);

				kmf.init(ks, passphrase);
				ctx.init(kmf.getKeyManagers(), null, null);

				f = ctx.getSocketFactory();
			} catch (Exception e) {
				throw new IOException(e.getMessage());
			}

			SSLSocket c = (SSLSocket) f.createSocket(args[0], Integer.parseInt(args[1]));

			c.startHandshake();

			BufferedWriter w = new BufferedWriter(
					new OutputStreamWriter(c.getOutputStream()));
			BufferedReader r = new BufferedReader(
					new InputStreamReader(c.getInputStream()));

			String m = null;
			String[] arr = null;
			
			while ((m=r.readLine())!= null) {
				
				arr = m.split(" ");
				
				if ( arr[0].equals("LoginSuccess") ) {
					token = arr[1];
					System.out.println("Successful Login Attempt");
				}
				if ( arr[0].equals("LoginFailed") ) {
					System.out.println("Failed Login Attempt");
				}
				
				
				
				
				out.println(m);
				m = in.readLine();
				arr = m.split(" ");
				
				if ( arr[0].equals("ls") || arr[0].equals("put") ||
						arr[0].equals("get") || arr[0].equals("cp") ||
						arr[0].equals("rm"))
				{
					m = m + " " + token;
					w.write(m,0,m.length());
				}
				else if ( arr[0].equals("login")) {
					w.write(m,0,m.length());
				}
				else System.out.println("Invalid command");
				
				w.newLine();
				w.flush();
	
			}

		}catch (IOException e) {
			System.err.println(e.toString());
		}
	}
}

