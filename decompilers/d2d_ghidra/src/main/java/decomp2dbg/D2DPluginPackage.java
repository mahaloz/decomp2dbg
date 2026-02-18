package decomp2dbg;

import javax.swing.Icon;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

/**
 * The {@link PluginPackage} for the {@value #NAME}
 */
public class D2DPluginPackage extends PluginPackage {
	public static final String NAME = "decomp2dbg decompiler server";
	public static final String DESCRIPTION = "These plugins are for connecting a debugger to the decompiler syms";
	
	/*
	protected D2DPluginPackage(String name, Icon icon, String description, int priority) {
		super(NAME, icon, DESCRIPTION, priority);
	}
	*/
	
	public D2DPluginPackage() {
		super(NAME, ResourceManager.loadImage("data/d2d.png"), DESCRIPTION, DEVELOPER_PRIORITY);
	}
}