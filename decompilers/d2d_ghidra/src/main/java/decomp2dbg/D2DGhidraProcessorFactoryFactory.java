package decomp2dbg;

import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.XmlRpcRequest;
import org.apache.xmlrpc.server.RequestProcessorFactoryFactory;

public class D2DGhidraProcessorFactoryFactory implements RequestProcessorFactoryFactory {
	private final RequestProcessorFactory factory = new D2DGhidraProcessorFactory();
	private final D2DGhidraServerAPI api;

	public D2DGhidraProcessorFactoryFactory(D2DGhidraServerAPI api) {
		this.api = api;
	}

	@Override
	public RequestProcessorFactory getRequestProcessorFactory(Class aClass) 
			throws XmlRpcException {
		return factory;
	}

	private class D2DGhidraProcessorFactory implements RequestProcessorFactory {
		@Override
		public Object getRequestProcessor(XmlRpcRequest xmlRpcRequest)
				throws XmlRpcException {
			return api;
		}
	}

}
