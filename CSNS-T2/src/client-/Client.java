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
				//		char[] passphrase = "passphrase".toCharArray();
				char[] passphrase = "client1".toCharArray();//		

				ctx = SSLContext.getInstance("TLS");
				kmf = KeyManagerFactory.getInstance("SunX509");
				ks = KeyStore.getInstance("JKS");

				ks.load(new FileInputStream("clientkeystore.jks"), passphrase);

				kmf.init(ks, passphrase);
				ctx.init(kmf.getKeyManagers(), null, null);

				f = ctx.getSocketFactory();
			} catch (Exception e) {
				throw new IOException(e.getMessage());
			}

			f =  (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket c = (SSLSocket) f.createSocket(args[0], Integer.parseInt(args[1]));

			
			
			c.startHandshake();

			BufferedWriter w = new BufferedWriter(
					new OutputStreamWriter(c.getOutputStream()));
			BufferedReader r = new BufferedReader(
					new InputStreamReader(c.getInputStream()));

			String m = null;
			while ((m=r.readLine())!= "!quit") {
				out.println(m);
				m = in.readLine();
				System.out.println("input:"+ m);

				w.write(m,0,m.length());
				w.newLine();
				w.flush();
			}

		}catch (IOException e) {
			System.err.println(e.toString());
		}
	}
}

