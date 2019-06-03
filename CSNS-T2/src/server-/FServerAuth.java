import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Properties;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class FServerAuth {

	private static final String SERVERTLS_CONFIG_PATH = "/home/sd2018/git/SRSC_T2/CSNS-T2/src/server-/servertls.conf";
	private static Properties properties;

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {

		//efeito de teste (1 utilizador pode-se add +)
		String username = "miguel";
		String email = "miguel@g.com";
		String nome = "Miguel Araujo";
		byte[] salt = generateSalt();
		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] hashedpw = md.digest("1234".getBytes());
		byte[] pw = getEncryptedPassword( Base64.getEncoder().encodeToString(hashedpw), salt);

		HashMap < String, Account > accounts = new HashMap<String, Account >();
		accounts.put( username, new Account(username, email, nome, pw, salt));

		//debug
		//		System.setProperty("javax.net.debug", "all");   

		try {
			properties = loadProperties(SERVERTLS_CONFIG_PATH);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		String ksName = "fserverauth.jks";
		char[]  ksPass = "fserverauth1".toCharArray();   // password da keystore
		char[]  ctPass = "fserverauth1".toCharArray();  // password entry
		int port= Integer.parseInt("9001");
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
				String[] arr = m.split(" ");

				username = arr[0];
				Account acc = accounts.get(username);

				if ( authenticate(arr[1], acc.pw, acc.salt) ) {

					m = username + ":" + email + ":" + nome + ":" + Base64.getEncoder().encodeToString(acc.pw) + ":" + Base64.getEncoder().encodeToString(acc.salt) + ":" + "TRUE";
					System.out.println(m);
				}
				else {
					m = "FALSE";
					System.out.println(m);
				}

				w.write(m,0,m.length());
				w.newLine();
				w.flush();
				System.out.println("Auth finished, waiting");
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

	//code gotten from: https://www.javacodegeeks.com/2012/05/secure-password-storage-donts-dos-and.html
	public static boolean authenticate(String attemptedPassword, byte[] encryptedPassword, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		// Encrypt the clear-text password using the same salt that was used to
		// encrypt the original password
		byte[] encryptedAttemptedPassword = getEncryptedPassword(attemptedPassword, salt);

		// Authentication succeeds if encrypted password that the user entered
		// is equal to the stored hash
		return Arrays.equals(encryptedPassword, encryptedAttemptedPassword);
	}

	public static byte[] getEncryptedPassword(String password, byte[] salt)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		// PBKDF2 with SHA-1 as the hashing algorithm. Note that the NIST
		// specifically names SHA-1 as an acceptable hashing algorithm for PBKDF2
		String algorithm = "PBKDF2WithHmacSHA1";
		// SHA-1 generates 160 bit hashes, so that's what makes sense here
		int derivedKeyLength = 160;
		// Pick an iteration count that works for you. The NIST recommends at
		// least 1,000 iterations:
		// http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
		// iOS 4.x reportedly uses 10,000:
		// http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-passwords/
		int iterations = 20000;

		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, derivedKeyLength);

		SecretKeyFactory f = SecretKeyFactory.getInstance(algorithm);

		return f.generateSecret(spec).getEncoded();
	}

	public static byte[] generateSalt() throws NoSuchAlgorithmException{
		// VERY important to use SecureRandom instead of just Random
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

		// Generate a 8 byte (64 bit) salt as recommended by RSA PKCS5
		byte[] salt = new byte[8];
		random.nextBytes(salt);

		return salt;
	}

	private static class Account {

		String username,email, nome;
		byte[] pw, salt;

		public Account ( String username, String email, String nome, byte[] pw, byte[] salt ) {
			this.username = username;
			this.email = email;
			this.nome = nome;
			this.pw = pw;
			this.salt = salt;
		}
	}
}

