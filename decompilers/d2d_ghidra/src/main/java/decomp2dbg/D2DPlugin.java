package decomp2dbg;

import java.awt.Event;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.database.symbol.VariableSymbolDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = D2DPluginPackage.NAME,
	category = PluginCategoryNames.DEBUGGER,
	shortDescription = "Syncronize symbols to a debugger",
	description = "This is the server for the decompiler side plugin of decomp2dbg "
			+ "which connects the decompiler to a debugger and syncronizes symbols "
			+ "and decompilation lines. See github.com/mahaloz/decomp2dbg for more info."
)
public class D2DPlugin extends ProgramPlugin implements DomainObjectListener {
	private DockingAction configureD2DAction;
	private D2DGhidraServer server;
	public Map<Long, DecompileResults> decompileCache;
	public Map<String, Object> gVarCache;
	public Map<String, Object> funcSymCache;
	public Map<Integer, Object> funcDataCache;
	
	public D2DPlugin(PluginTool tool) {
		super(tool);
		
		// Add a d2d button to 'Tools' in GUI menu
		configureD2DAction = this.createD2DMenuAction();
		tool.addAction(configureD2DAction);
		
		// cache maps
		decompileCache = new HashMap<>();
		gVarCache = new HashMap<>();
		funcSymCache = new HashMap<>();
		funcDataCache = new HashMap<>();
	}
	
	@Override
	protected void programActivated(Program program) {
		program.addListener(this);
	}

	@Override
	protected void programDeactivated(Program program) {
		program.removeListener(this);
	}
	
	private DockingAction createD2DMenuAction() {
		D2DPlugin plugin = this;
		configureD2DAction = new DockingAction("decomp2dbg", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.configureD2DServer();
			}
		};
		
		configureD2DAction.setEnabled(true);
		configureD2DAction.setMenuBarData(new MenuData(new String[] {"Tools", "Configure decomp2dbg..." }));
		configureD2DAction.setKeyBindingData(new KeyBindingData(KeyStroke.getKeyStroke('D', Event.CTRL_MASK + Event.SHIFT_MASK)));
		return configureD2DAction;
	}
	
	private void configureD2DServer() {
		Msg.info(this, "Configuring decomp2dbg...");
		JTextField hostField = new JTextField("localhost");
		JTextField portField = new JTextField("3662");
		Object[] message = {
		    "Host: ", hostField,
		    "Port: ", portField
		};

		int option = JOptionPane.showConfirmDialog(null, message, "Login", JOptionPane.OK_CANCEL_OPTION);
		String host = null;
		int port = 0;
		if (option == JOptionPane.OK_OPTION) {
			host = hostField.getText();
			try {
				port = Integer.parseInt(portField.getText());
			} catch(Exception e) {
				JOptionPane.showMessageDialog(null, "Unable to parse port: " + e.toString());
				return;
			}
		} else 
			return;
		
		this.server = new D2DGhidraServer(host, port, this);
		
		try {
			this.server.start_server();
		} catch(Exception e) {
			JOptionPane.showMessageDialog(null, "Encountered error: " + e.toString());
			return;
		}
		
		JOptionPane.showMessageDialog(null, "Sever configured and running!");
	}
	
	/*
	 * Decompiler Utils
	 */

	public Address strToAddr(String addrStr) {
		return this.getCurrentProgram().getAddressFactory().getAddress(addrStr);
	}
	
	public Address rebaseAddr(Integer addr, Boolean rebaseDown) {
		var program = this.getCurrentProgram();
		var base = (int) program.getImageBase().getOffset();
		Integer rebasedAddr = addr;
		if(rebaseDown) {
			rebasedAddr -= base;
		}
		else if(addr < base) {
			rebasedAddr += base;
		}
		
		return this.strToAddr(Integer.toHexString(rebasedAddr));
	}
	
	public Function getNearestFunction(Address addr) {
		if(addr == null) {
			Msg.warn(this, "Failed to parse Addr string earlier, got null addr.");
			return null;
		}
		
		var program = this.getCurrentProgram();
		var funcManager = program.getFunctionManager();
		var func =  funcManager.getFunctionContaining(addr);
		
		return func;
	}
	
	public DecompileResults decompileFunc(Function func) {
		var cacheRes = this.decompileCache.get(func.getEntryPoint().getOffset());
		if(cacheRes != null) 
			return (DecompileResults) cacheRes; 
		
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(new DecompileOptions());
		ifc.openProgram(this.getCurrentProgram());
		DecompileResults res = ifc.decompileFunction(func, 10, new ConsoleTaskMonitor());
		
		// cache it!
		this.decompileCache.put(func.getEntryPoint().getOffset(), res);
		return res;
	}
	
	public Map<String, Object> getFuncData(Integer addr) {
		Map<String, Object> funcInfo = new HashMap<>();
		funcInfo.put("stack_vars", new HashMap<>());
		funcInfo.put("reg_vars", new HashMap<>());
		var func = this.getNearestFunction(this.rebaseAddr(addr, false));
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);
			return funcInfo;
		}
		
		var dec = this.decompileFunc(func);
		if(dec == null) {
			Msg.warn(server, "Failed to decompile function by the address " + addr);
			return funcInfo;
		}
		
		ArrayList<HighSymbol> symbols = new ArrayList<HighSymbol>();
		Map<String, Object> regVars = new HashMap<>();
		Map<String, Object> stackVars = new HashMap<>();
		dec.getHighFunction().getLocalSymbolMap().getSymbols().forEachRemaining(symbols::add);
		for (HighSymbol sym: symbols) {
			if(sym.getStorage().isStackStorage()) {
				Map<String, String> sv = new HashMap<>();
				sv.put("name", sym.getName());
				sv.put("type", sym.getDataType().toString());
				stackVars.put(String.valueOf(sym.getStorage().getStackOffset()), sv);
			}
			else if(sym.getStorage().isRegisterStorage()) {
				Map<String, String> rv = new HashMap<>();
				rv.put("reg_name", sym.getStorage().getRegister().toString().toLowerCase());
				rv.put("type", sym.getDataType().toString());
				regVars.put(sym.getName(), rv);
			}
		}
		funcInfo.put("stack_vars", stackVars);
		funcInfo.put("reg_vars", regVars);
		
		return funcInfo;
	}
	
	/*
	 * Change Event Handler
	 */
	
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		// also look at:
		// https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/analysis/AutoAnalysisManager.java
		
		ArrayList<Integer> funcEvents = new ArrayList<>(Arrays.asList(
			ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.DOCR_FUNCTION_BODY_CHANGED,
			ChangeManager.DOCR_VARIABLE_REFERENCE_ADDED,
			ChangeManager.DOCR_VARIABLE_REFERENCE_REMOVED
		));

		ArrayList<Integer> symDelEvents = new ArrayList<>(Arrays.asList(
			ChangeManager.DOCR_SYMBOL_REMOVED	
		));
		
		ArrayList<Integer> symChgEvents = new ArrayList<>(Arrays.asList(
			ChangeManager.DOCR_SYMBOL_ADDED,
			ChangeManager.DOCR_SYMBOL_RENAMED,
			ChangeManager.DOCR_SYMBOL_DATA_CHANGED
		));
		
		
		for (DomainObjectChangeRecord record : ev) {
			// only analyze changes to the current program 
			if( !(record instanceof ProgramChangeRecord) )
				continue;
			
			int chgType = record.getEventType();
			var pcr = (ProgramChangeRecord) record;
			var obj = pcr.getObject();
			var newVal = pcr.getNewValue();
			
			/*
			 * Function Updates
			 */
			if(funcEvents.contains(chgType)) {
				// use record.getSubEvent() when checking if a FUNCTION_CHANGED
				// since it will be triggered if the signature of the function changes
				var funcAddr = pcr.getStart().getOffset();
				this.funcDataCache.put((int) funcAddr, null);
				this.decompileCache.put(funcAddr, null);
			}
			
			/*
			 * Symbol Removed (global variable)
			 */
			else if (symDelEvents.contains(chgType)) {
				var addr = pcr.getStart().getOffset();
				var rebasedAddrStr = "0x" + this.rebaseAddr((int) addr, true).toString();
				this.gVarCache.remove(rebasedAddrStr);
			}
			
			/*
			 * Symbol Updated or Created
			 */
			else if (symChgEvents.contains(chgType)) {
				if (obj == null && newVal != null)
					obj = newVal;
				
				/*
				 * Stack Variable
				 */
				if (obj instanceof VariableSymbolDB) {
					continue;
				}
				
				/*
				 * GlobalVar & Label
				 */
				else if(obj instanceof CodeSymbol) {
					if(this.gVarCache.isEmpty())
						continue;
					
					var sym = (CodeSymbol) obj;
					var newName = sym.getName();
					var addr = sym.getAddress().getOffset();
					
					Map<String, Object> varInfo = new HashMap<>();
					varInfo.put("name", newName);
					var rebasedAddr = this.rebaseAddr((int) addr, true);
					this.gVarCache.put("0x" + rebasedAddr.toString(), varInfo);
				}
				
				/*
				 * Function Name
				 */
				else if(obj instanceof FunctionSymbol) {
					if(this.funcSymCache.isEmpty())
						continue;
					
					var sym = (FunctionSymbol) obj;
					var newName = sym.getName();
					var addr = sym.getAddress().getOffset();
					
					var func = this.getCurrentProgram().getFunctionManager().getFunction(addr);
					Map<String, Object> funcInfo = new HashMap<>();
					funcInfo.put("name", newName);
					funcInfo.put("size", (int) func.getBody().getNumAddresses());
					var rebasedAddr = this.rebaseAddr((int) addr, true);
					this.funcSymCache.put("0x" + rebasedAddr.toString(), funcInfo);
				}
				else
					continue;
				
				this.decompileCache.clear();
			}
		}
	}
	
}
