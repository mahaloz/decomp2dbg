package decomp2dbg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;

public class D2DGhidraServerAPI {
    private D2DGhidraServer server;
	
	public D2DGhidraServerAPI(D2DGhidraServer server) {
		this.server = server;
	}
	
	/*
	 * Server Manipulation API 
	 */
	
	public Boolean ping() {
		return true;
	}
	
	public Boolean stop() {
		this.server.stop_server();
		return true;
	}
	
	/*
	 * 
	 * Decompiler API
	 *
	 */
	
	public Map<String, Object> decompile(Integer addr) {
		Map<String, Object> resp = new HashMap<>();
		resp.put("decompilation", "");
		resp.put("curr_line", -1);
		resp.put("func_name", "");
		
		var rebasedAddr = this.server.plugin.rebaseAddr(addr, false);
		var func = this.server.plugin.getNearestFunction(this.server.plugin.rebaseAddr(addr, false));
		var rebasedAddrLong = rebasedAddr.getOffset();
		
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);
			return resp;
		}
		
		resp.put("func_name", func.getName());
		
		var dec = this.server.plugin.decompileFunc(func);
		if(dec == null) {
			Msg.warn(server, "Failed to decompile function by the address " + addr);
			return resp;
		}
	    
		// create a nice string
	    var decLines = dec.getDecompiledFunction().getC().split("\n");
	    resp.put("decompilation", decLines);
		
		PrettyPrinter pp = new PrettyPrinter(func, dec.getCCodeMarkup());
	    ArrayList<ClangLine> lines = pp.getLines();
	    
	    // locate the decompilation line
	    Boolean lineFound = false;
	    Integer lineNumber = 0;
	    for (ClangLine line : lines) {
	    	for (int i = 0; i < line.getNumTokens(); i++) {
				if (line.getToken(i).getMinAddress() == null) {
					continue; 
				}
				long tokenMinAddr = line.getToken(i).getMinAddress().getOffset();
				long tokenMaxAddr = line.getToken(i).getMaxAddress().getOffset();
				if(tokenMinAddr == rebasedAddrLong || tokenMaxAddr == rebasedAddrLong || 
						(rebasedAddrLong > tokenMinAddr && rebasedAddrLong < tokenMaxAddr)) {
					lineFound = true;
					lineNumber = line.getLineNumber();
					break;
				}
	    	}
	    	
	    	if(lineFound)
				break;
	    }
	    
	    // unable to locate the decompilation line
	    if(!lineFound)
	    	return resp;
	    
	    resp.put("curr_line", lineNumber-1);
		return resp;
	}
	
	
	public Map<String, Object> function_data(Integer addr) {
		var cache = this.server.plugin.funcDataCache.get(addr);
		if(cache != null)
			return (Map<String, Object>) cache;
		
		var resp = this.server.plugin.getFuncData(addr);
		this.server.plugin.funcDataCache.put(addr, resp);
		return resp;
	}

	public Map<String, Object> function_headers() {
		// always check cache first
		if(!this.server.plugin.funcSymCache.isEmpty())
			return this.server.plugin.funcSymCache;
		
		Map<String, Object> resp = new HashMap<>();
		var program = this.server.plugin.getCurrentProgram();
		var fm = program.getFunctionManager();
		var functions = fm.getFunctions(true);
		for (Function func : functions) {
			Map<String, Object> funcInfo = new HashMap<>();
			funcInfo.put("name", func.getName());
			funcInfo.put("size", (int) func.getBody().getNumAddresses());
			var rebasedAddr = this.server.plugin.rebaseAddr((int) func.getEntryPoint().getOffset(), true);
			resp.put("0x" + rebasedAddr.toString(), funcInfo);
			
		}
		
		this.server.plugin.funcSymCache = resp;
		return resp;
	}
	
	public Map<String, Object> global_vars() {
		// check the cache before doing hard work!
		if(!this.server.plugin.gVarCache.isEmpty())
			return this.server.plugin.gVarCache;
		
		// if we are here, this is first connection!
		Map<String, Object> resp = new HashMap<>();
		var symTab = this.server.plugin.getCurrentProgram().getSymbolTable();
		for (Symbol sym: symTab.getAllSymbols(true)) {
			if (sym.getSymbolType() != SymbolType.LABEL || !sym.isExternal())
				continue;
			
			Map<String, Object> varInfo = new HashMap<>();
			varInfo.put("name", sym.getName());
			var rebasedAddr = this.server.plugin.rebaseAddr((int) sym.getAddress().getOffset(), true);
			resp.put("0x" + rebasedAddr.toString(), varInfo);
		}
		
		// cache it for next request
		this.server.plugin.gVarCache = resp;
		return resp;
	}
	
}
