package nth347.commonclient;

import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * RMI/LDAP lookup client that simulates an application vulnerable to JNDI injection
 * This client is used for quick testing of JNDI injection
 */
public class RmiLdapClient {
    public static void main(String[] args) throws NamingException {
        InitialContext context = new InitialContext();

        Object obj = context.lookup("rmi://192.168.93.128:1099/Object");
        //Object obj = context.lookup("ldap://192.168.93.128:6366/Object");

        System.out.println(obj);
    }
}
