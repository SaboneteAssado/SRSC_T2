import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Client {

	public static void main(String[] args) throws NoSuchAlgorithmException {

		//		System.setProperty("javax.net.debug", "all");

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
//				String[] trimtoken = m.split(" ");
//				trimtoken[trimtoken.length-1] = "";
//				m =trimtoken.toString();
				
				out.println(m);
				arr = m.split(" ");

				if ( arr[0].equals("LoginSuccess") ) {
					token = arr[1];
					System.out.println(token);
					out.println("Successful Login Attempt");
				}
				else if ( arr[0].equals("LoginFailed") ) {
					out.println("Failed Login Attempt");
				}
				else if ( arr[0].equals("allow") ) {
					arr = m.split(" ");
					for ( int i = 0; i<arr.length; i++) {
						out.println(arr[i]);
					}
				}
				else if ( arr[0].equals("deny") ) {
					out.println("Access Denied");
				}

				m=in.readLine();
				arr = m.split(" ");

				if ( arr[0].equals("ls")){
					m = m + " " + token;
					w.write(m, 0, m.length());
				}
				//apenas nome do ficheiro root folder
				else if ( arr[0].equals("put") ) {
					m = m + " " + token ;
					w.write(m, 0, m.length());
					if ( r.readLine().equals("file")){
						InputStream is = new FileInputStream(arr[2]);
				        OutputStream os = c.getOutputStream();
				        copy(is, os);
				        os.close();
				        is.close();
					}
				}
				else if ( arr[0].equals("get") ) {
					
				}
				else if ( arr[0].equals("rm") ) {
					
				}
				else if ( arr[0].equals("cp")) {
					
				}
				else if ( arr[0].equals("login")) {
					MessageDigest md = MessageDigest.getInstance("MD5");
					byte[] hashedpw = md.digest(arr[2].getBytes());
					arr[2] = Base64.getEncoder().encodeToString(hashedpw);
					System.out.println(arr[2]);
					m = String.join(" ", arr);
					System.out.println(m);
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
	
	static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int len = 0;
        while ((len = in.read(buf)) != -1) {
            out.write(buf, 0, len);
        }
    }
}

