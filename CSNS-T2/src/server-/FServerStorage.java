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
import java.nio.channels.FileChannel;
import java.security.KeyStore;
import java.util.Properties;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class FServerStorage {

	private static final String SERVERTLS_CONFIG_PATH = "/home/sd2018/git/SRSC_T2/CSNS-T2/src/server-/servertls.conf";
	private static Properties properties;
	private static final String ROOT = "/home/sd2018/git/SRSC_T2/CSNS-T2/src/storage-/";

	public static void main(String[] args) {

		//		System.setProperty("javax.net.debug", "all");   

		try {
			properties = loadProperties(SERVERTLS_CONFIG_PATH);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		String ksName = "fserverstorage.jks";
		char[]  ksPass = "fserverstorage1".toCharArray();   // password da keystore
		char[]  ctPass = "fserverstorage1".toCharArray();  // password entry
		int port= Integer.parseInt("9003");
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

			while ( true ) {

				m = r.readLine();
				System.out.println("m = " + m);
				String[] arr = m.split(" ");

				if( arr[0].equals("ls")) {
					String user = arr[1];
					File folder = new File(ROOT + user);
					File[] listOfFiles = folder.listFiles();
					if ( listOfFiles.length == 0){
						m = "Folder empty";
						w.write(m,0,m.length());
					}else {
						m = "";
						for ( int i = 0; i< listOfFiles.length; i++) {
							if ( i == 0)
								m = listOfFiles[i].getName();
							else m = m + " " + listOfFiles[i].getName();
							w.write(m,0,m.length());
						}
					}
				}
				else if( arr[0].equals("put")) {
					String username = arr[1];
					String filename = arr[2];
					InputStream is = c.getInputStream();
					OutputStream os = new FileOutputStream(ROOT + username + "/" + filename);
					copy(is, os);
					os.close();
					is.close();
				}
				else if( arr[0].equals("get")) {
					String username = arr[1];
					String filename = arr[2];
					InputStream is = new FileInputStream(ROOT + username + "/" + filename);
					System.out.println("houve input");
					OutputStream os = c.getOutputStream();
					System.out.println("houve output");
					
					copy(is, os);
					
					System.out.println("consegui copiar");
					os.close();
					System.out.println("fechei os");
					
			        is.close();
					System.out.println("fechei is");
					m = "conseguido";
					w.write(m,0,m.length());
				}
				else if( arr[0].equals("rm")) {
					String username = arr[1];
					String filename = arr[2];
					File file = new File(ROOT + username + "/" + filename);
					file.delete();
					m = "removed";
					w.write(m,0,m.length());
				}
				else if( arr[0].equals("cp")) {
					String username = arr[1];
					String filename1 = arr[2];
					String filename2 = arr[3];
					FileChannel sourceChannel = null;
					FileChannel destinationChannel = null;

					FileInputStream is = new FileInputStream(ROOT + username + "/" + filename1);
					FileOutputStream os = new FileOutputStream(ROOT + username + "/" + filename2);
					sourceChannel = is.getChannel();
					destinationChannel = os.getChannel();
					destinationChannel.transferFrom(sourceChannel, 0, sourceChannel.size());

					sourceChannel.close();
					destinationChannel.close();
					is.close();
					os.close();

					m = "copied";
					w.write(m,0,m.length());
				}

				w.newLine();
				w.flush();
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

	static void copy(InputStream in, OutputStream out) throws IOException {
		byte[] buf = new byte[8192];
		int len = 0;
		while ((len = in.read(buf)) != -1) {
			out.write(buf, 0, len);
		}
	}
}

