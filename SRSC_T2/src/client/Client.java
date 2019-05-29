package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Client {

	public static void main(String[] args) {

		BufferedReader in = new BufferedReader(
				new InputStreamReader(System.in));
		PrintStream out = System.out;

		SSLSocketFactory f = 
				(SSLSocketFactory) SSLSocketFactory.getDefault();
		try {
			SSLSocket c = (SSLSocket) f.createSocket(args[0], Integer.parseInt(args[1]));
			
			
			
		}catch (IOException e) {
			System.err.println(e.toString());
		}
	}
}
