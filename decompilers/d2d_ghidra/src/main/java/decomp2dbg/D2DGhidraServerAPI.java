package decomp2dbg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;
import ghidra.framework.Application;

public class D2DGhidraServerAPI {
    private final D2DGhidraServer server;
	
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
		var func = this.server.plugin.getNearestFunction(rebasedAddr);
		long rebasedAddrLong = rebasedAddr.getOffset();
		
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
		
		PrettyPrinter pp = new PrettyPrinter(func, dec.getCCodeMarkup(), null);
	    ArrayList<ClangLine> lines = (ArrayList<ClangLine>) pp.getLines();
	    
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
		FunctionIterator functions = fm.getFunctions(true);
		for (Function func : functions) {
		    if(func == null)
                continue;

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
			if (sym.getSymbolType() != SymbolType.LABEL)
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

	public Map<String, Object> structs() {
		// check the cache before doing hard work!
		if(!this.server.plugin.structCache.isEmpty())
			return this.server.plugin.structCache;
	
		// if we are here, this is first connection!
		ArrayList<Object> structInfos = new ArrayList<>();
		var program = this.server.plugin.getCurrentProgram();
		var dtm = program.getDataTypeManager();
		var structs = dtm.getAllStructures();

		while (structs.hasNext()) {
			var struct = structs.next();
			Map<String, Object> structInfo = new HashMap<>();
			structInfo.put("name", struct.getName());
			// Enumerate members
			DataTypeComponent[] members = struct.getComponents();
			// For unknown reasons, the API claims that some targets have structures with a crazy number of members (in the millions).
			// This causes an infinite loop.
			// May be caused by a bug in some other plugin, not sure.
			if (members.length > 1000) {
				continue;
			}
			ArrayList<Object> memberInfo = new ArrayList<>();
			var unnamedMembers = 0;
			for (var member : members) {
				Map<String, Object> memberData = new HashMap<>();
				// Some fields don't have names, and the XMLRPC impl does not like that.
				// Work around by assigning a surrogate name.
				var name = member.getFieldName();
				if (name == null) {
					name = "unnamed" + unnamedMembers;
					unnamedMembers++;
				}
				memberData.put("name", name);
				memberData.put("size", member.getLength());
				memberData.put("type", member.getDataType().getName());
				memberData.put("offset", member.getOffset());
				memberInfo.add(memberData);
			}
			structInfo.put("members", memberInfo);
			structInfos.add(structInfo);
		}
		Map<String, Object> resp = new HashMap<>();
		resp.put("struct_info", structInfos);

		// cache it for next request
		this.server.plugin.structCache = resp;
		return resp;
	}

	public Map<String, Object> type_aliases() {
		// check the cache before doing hard work!
		if(!this.server.plugin.typeAliasCache.isEmpty())
			return this.server.plugin.typeAliasCache;

		// if we are here, this is first connection!
		ArrayList<Object> aliasInfos = new ArrayList<>();
		var program = this.server.plugin.getCurrentProgram();
		var dtm = program.getDataTypeManager();
		var allTypes = dtm.getAllDataTypes();
		while (allTypes.hasNext()) {
			var type = allTypes.next();

			if (!(type instanceof ghidra.program.model.data.TypeDef))
				continue;
			var alias = ((ghidra.program.model.data.TypeDef) type);


			Map<String, Object> aliasInfo = new HashMap<>();
			aliasInfo.put("name", type.getName());
			aliasInfo.put("type", alias.getDataType().getName());
			aliasInfo.put("size", type.getLength());
			aliasInfos.add(aliasInfo);
		}
		Map<String, Object> resp = new HashMap<>();
		resp.put("alias_info", aliasInfos);

		// cache it for next request
		this.server.plugin.typeAliasCache = resp;
		return resp;
	}

	public Map<String, Object> unions() {
		// check the cache before doing hard work!
		if(!this.server.plugin.unionCache.isEmpty())
			return this.server.plugin.unionCache;

		// if we are here, this is first connection!
		ArrayList<Object> unionInfos = new ArrayList<>();
		var program = this.server.plugin.getCurrentProgram();
		var dtm = program.getDataTypeManager();
		var types = dtm.getAllDataTypes();
		while (types.hasNext()) {
			var type = types.next();

			if (!(type instanceof ghidra.program.model.data.Union))
				continue;
			var union = ((ghidra.program.model.data.Union) type);

			Map<String, Object> unionInfo = new HashMap<>();
			unionInfo.put("name", union.getName());
			// Enumerate members
			DataTypeComponent[] members = union.getComponents();
			ArrayList<Object> memberInfo = new ArrayList<>();
			for (var member : members) {
				Map<String, Object> memberData = new HashMap<>();
				memberData.put("name", member.getFieldName());
				memberData.put("size", member.getLength());
				memberData.put("type", member.getDataType().getName());
				memberData.put("offset", member.getOffset());
				memberInfo.add(memberData);
			}
			unionInfo.put("members", memberInfo);
			unionInfos.add(unionInfo);
		}
		Map<String, Object> resp = new HashMap<>();
		resp.put("union_info", unionInfos);

		// cache it for next request
		this.server.plugin.unionCache = resp;
		return resp;
	}

	public Map<String, Object> enums() {
		// check the cache before doing hard work!
		if(!this.server.plugin.enumCache.isEmpty())
			return this.server.plugin.enumCache;

		// if we are here, this is first connection!
		ArrayList<Object> enumInfos = new ArrayList<>();
		var program = this.server.plugin.getCurrentProgram();
		var dtm = program.getDataTypeManager();
		var types = dtm.getAllDataTypes();
		while (types.hasNext()) {
			var type = types.next();

			if (!(type instanceof ghidra.program.model.data.Enum))
				continue;
			var enumType = ((ghidra.program.model.data.Enum) type);

			Map<String, Object> enumInfo = new HashMap<>();
			enumInfo.put("name", enumType.getName());
			// Enumerate values
			var values = enumType.getValues();
			ArrayList<Object> valueInfo = new ArrayList<>();
			for (var value : values) {
				Map<String, Object> valueData = new HashMap<>();
				valueData.put("name", enumType.getName(value));
				// Apache XMLRPC doesn't support transport of long values without extensions,
				// therefore we have to cast truncate them here.
				// Alternatively we could enable extensions by configuring enabledForExtensions = true,
				// but some RPC clients may not like it.
				if (value > Integer.MAX_VALUE) {
					continue;
				}
				valueData.put("value", (int)value);
				valueInfo.add(valueData);
			}
			enumInfo.put("members", valueInfo);
			enumInfos.add(enumInfo);
		}
		
		Map<String, Object> resp = new HashMap<>();
		resp.put("enum_info", enumInfos);

		// cache it for next request
		this.server.plugin.enumCache = resp;
		return resp;
	}

	/// Get the filesystem path of the binary being decompiled.
	public String binary_path() {
		return this.server.plugin.getCurrentProgram().getExecutablePath();
	}

	/// Get version information about the decompiler environment.
	public Map<String, String> versions() {
			Map<String, String> res = new HashMap<>();
			res.put("name", "ghidra");
			res.put("version", Application.getApplicationVersion().toString());
			res.put("java", System.getProperty("java.version"));
			return res;
	}

	/// Navigate to this address in the GUI.
	public boolean focus_address(Integer addr) {
		return this.server.plugin.focus_address(addr);
  }

	public Map<String, Object> elf_info() {
		if(!this.server.plugin.elfInfoCache.isEmpty())
			return this.server.plugin.elfInfoCache;

		Map<String, Object> elf_info = new HashMap<>();

		var program = this.server.plugin.getCurrentProgram();
		var provider = new MemoryByteProvider(program.getMemory(), program.getMinAddress());
		ElfHeader header;
		try {
			header = new ElfHeader(provider, null);
		}
		catch (ElfException e) {
			elf_info.put("error", e.toString());
			return elf_info;
		}

		elf_info.put("flags", "0x" + Integer.toHexString(header.e_flags()));
		elf_info.put("machine", (int) header.e_machine());
		elf_info.put("is_big_endian", header.isBigEndian());
		elf_info.put("is_32_bit", header.is32Bit());
		elf_info.put("image_base", "0x" + Long.toHexString(program.getMinAddress().getOffset()));
		elf_info.put("name", program.getName());
		elf_info.put("error", "");

		this.server.plugin.elfInfoCache = elf_info;
		return elf_info;
	}
}
