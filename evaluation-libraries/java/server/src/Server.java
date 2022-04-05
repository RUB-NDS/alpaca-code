import java.io.*;
import java.security.KeyStore;
import java.util.*;
import javax.net.ssl.*;

import gnu.getopt.Getopt;

public class Server {
    public static String keyFile = "/etc/ssl/cert-data/tls-server.com.p12";
    public static String keyPassword = "123456";
    public static String[] protocols = new String[] { "TLSv1.2", "TLSv1.3" };
    public static String[] alpn = { "http/1.1" };
    public static String servername = "tls-server.com";
    public static int port = 4433;

    public static void main(String[] argv) throws Exception {

        // Get commandline arguments with GetOpt
        Getopt g = new Getopt("Server", argv, "a:s:k:p:");
        int opt;
        while ((opt = g.getopt()) != -1) {
            switch (opt) {
                case 'a':
                    alpn[0] = g.getOptarg();
                    break;
                case 's':
                    servername = g.getOptarg();
                    break;
                case 'k':
                    keyFile = g.getOptarg();
                    break;
                case 'p':
                    port = Integer.parseInt(g.getOptarg());
                    break;
                default:
                    System.out.print("Usage: %s [-a alpn] [-s servername] [-t target] [-c certfile] [-p port]");
            }
        }
        System.out.println(
                "Parameters servername=" + servername + " alpn=" + alpn[0] + " key=" + keyFile + " port=" + port);

        SSLContext ctx = SSLContext.getInstance("TLS");

        // Create Keystore
        KeyStore keyKS = KeyStore.getInstance("PKCS12");
        keyKS.load(new FileInputStream(keyFile), keyPassword.toCharArray());

        // Generate KeyManager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(keyKS, keyPassword.toCharArray());
        KeyManager[] kms = kmf.getKeyManagers();

        // Initialize SSLContext using the new KeyManager
        ctx.init(kms, null, null);

        // Instead of using SSLServerSocketFactory.getDefault(),
        // get a SSLServerSocketFactory based on the SSLContext
        SSLServerSocketFactory sslssf = ctx.getServerSocketFactory();
        SSLServerSocket sslServerSocket = (SSLServerSocket) sslssf.createServerSocket(port);

        while (true) {
            // Listen for connectionss
            SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
            SSLParameters sslp = sslSocket.getSSLParameters();

            // Set SNI hostname, the matcher aborts the connection if the servername is not
            // found
            SNIMatcher matcher = SNIHostName.createSNIMatcher(servername);
            Collection<SNIMatcher> matchers = new ArrayList<>(1);
            matchers.add(matcher);
            sslp.setSNIMatchers(matchers);

            // Add ALPN to the SSL parameters
            // Java will abort the connection if there is a mismatch in the Protocols
            sslp.setApplicationProtocols(alpn);

            sslSocket.setSSLParameters(sslp);
            sslSocket.setEnabledProtocols(protocols);

            // Do the handshake
            try {
                sslSocket.startHandshake();

                String ap = sslSocket.getApplicationProtocol();
                System.out.println("ALPN: \"" + ap + "\"");

                // Send message to client
                PrintWriter out = new PrintWriter(
                        new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream())));
                out.println("Hello from Server!");
                out.flush();

                // Get message from client
                BufferedReader in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
                String inputLine;
                while ((inputLine = in.readLine()) != null)
                    System.out.println(inputLine);
            } catch (javax.net.ssl.SSLHandshakeException e) {
                System.out.println(e);
                sslSocket.close();
                continue;
            } catch (java.net.SocketException e) {
                System.out.println(e);
                sslSocket.close();
                continue;
            } catch (javax.net.ssl.SSLException e) {
                System.out.println(e);
                sslSocket.close();
                continue;
            }

            sslSocket.close();
        }
    }
}