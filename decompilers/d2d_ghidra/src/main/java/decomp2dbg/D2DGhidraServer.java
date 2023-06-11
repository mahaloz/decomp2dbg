package decomp2dbg;

import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.server.PropertyHandlerMapping;
import org.apache.xmlrpc.webserver.WebServer;


public class D2DGhidraServer {
    public D2DPlugin plugin;
    public D2DGhidraServerAPI api;
    private WebServer server;
    public Boolean uiConfiguredCorrectly;
    
    public int port;
    public String host;
    
    public D2DGhidraServer(String host, int port, D2DPlugin plugin)
    {
        this.server = new WebServer(port);
    	this.plugin = plugin;
    	this.uiConfiguredCorrectly = null;
    	this.port = port;
    	this.host = host;
    	
        PropertyHandlerMapping phm = new PropertyHandlerMapping();
        api = new D2DGhidraServerAPI(this);
        phm.setRequestProcessorFactoryFactory(new D2DGhidraProcessorFactoryFactory(api));
        phm.setVoidMethodEnabled(true);
        
        try {
			phm.addHandler("d2d", D2DGhidraServerAPI.class);
			this.server.getXmlRpcServer().setHandlerMapping(phm);
		} catch (XmlRpcException e) {
    		System.out.println("Error in phm config: " + e);
			this.server = null;
		}
    }
    
    public Boolean start_server() {
    	if(this.server == null) {
    		return false;
    	}
    	
    	try {
    		this.server.start();
    		return true;
    	} catch (Exception exception){
    		System.out.println("Error starting Server: " + exception);
    		return false;
       }
    }
    
    public Boolean stop_server() {
    	if(this.server == null)
    		return false;
    	
    	this.server.shutdown();
    	return true;
    }
}
