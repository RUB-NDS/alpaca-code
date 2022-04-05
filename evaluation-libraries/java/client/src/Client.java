import java.io.*;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.naming.InvalidNameException;

import gnu.getopt.Getopt;

public class Client {
    public static String cert = "/etc/ssl/certs/ca.crt";
    public static String[] tls_versions = new String[] { "TLSv1.2", "TLSv1.3" };
    public static String[] alpn = { "http/1.1" };
    public static String servername = "tls-server.com";
    public static String host = "127.0.0.1";
    public static int port = 4433;

    public static void main(String[] argv) throws Exception {

        // Get commandline arguments with GetOpt
        Getopt g = new Getopt("Client", argv, "a:s:c:h:p:");
        int opt;
        while ((opt = g.getopt()) != -1) {
            switch (opt) {
                case 'a':
                    alpn[0] = g.getOptarg();
                    break;
                case 's':
                    servername = g.getOptarg();
                    break;
                case 'h':
                    host = g.getOptarg();
                    break;
                case 'c':
                    cert = g.getOptarg();
                    break;
                case 'p':
                    port = Integer.parseInt(g.getOptarg());
                    break;
                default:
                    System.out.print("Usage: %s [-a alpn] [-s servername] [-t target] [-c certfile] [-p port]");
            }
        }
        System.out.println("Parameters servername=" + servername + " alpn=" + alpn[0] + " cert=" + cert + " host="
                + host + " port=" + port);

        // Create custom Keystore
        File crtFile = new File(cert);
        Certificate certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(new FileInputStream(crtFile));

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("asd", certificate);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        // Use Custom Keystore
        SSLSocketFactory sslsf = (SSLSocketFactory) sslContext.getSocketFactory();
        // SSLSocketFactory sslsf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket sslSocket = (SSLSocket) sslsf.createSocket(host, port);
        SSLParameters sslp = sslSocket.getSSLParameters();

        // set ALPN
        sslp.setApplicationProtocols(alpn);

        // set SNI
        SNIHostName serverName = new SNIHostName(servername);
        List<SNIServerName> serverNames = new ArrayList<>(1);
        serverNames.add(serverName);
        sslp.setServerNames(serverNames);

        sslSocket.setSSLParameters(sslp);
        sslSocket.setEnabledProtocols(tls_versions);

        // do Handshake
        try {
            sslSocket.startHandshake();
        } catch (javax.net.ssl.SSLHandshakeException e) {
            System.out.println(e);
            sslSocket.close();
            System.exit(1);
        } catch (javax.net.ssl.SSLProtocolException e) {
            System.out.println(e);
            sslSocket.close();
            if (e.getMessage().startsWith("Invalid application_layer_protocol_negotiation")) {
                System.exit(120);
            }
            System.exit(1);
        }

        // Hostname verification
        String peerCNname = getCommonName((X509Certificate) sslSocket.getSession().getPeerCertificates()[0]);
        if (!peerCNname.equals(servername)) {
            System.out.println("Hostname Verification failed: " + peerCNname);
            System.exit(42);
        }
        System.out.println("Hostname Verification succeded: " + peerCNname);

        // ALPN verification
        String ap = sslSocket.getApplicationProtocol();
        if (!ap.equals(alpn[0])) {
            System.out.println("INVALID ALPN: \"" + ap + "\"");
            System.exit(120);
        }
        System.out.println("ALPN: \"" + ap + "\"");

        // Send message to server
        PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream())));
        out.println("Hello from Client!");
        out.flush();

        // Receive message from server
        BufferedReader in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
        String inputLine;
        inputLine = in.readLine();
        // while ((inputLine = in.readLine()) != null)
        System.out.println(inputLine);

        sslSocket.close();
    }

    public static String getCommonName(X509Certificate cert) {
        try {
            LdapName ldapName = new LdapName(cert.getSubjectX500Principal().getName());
            /*
             * Looking for the "most specific CN" (i.e. the last).
             */
            String cn = null;
            for (Rdn rdn : ldapName.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    cn = rdn.getValue().toString();
                }
            }
            return cn;
        } catch (InvalidNameException e) {
            return null;
        }
    }
}