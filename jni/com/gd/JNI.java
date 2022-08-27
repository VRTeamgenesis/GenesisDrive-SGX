
package com.gd;
public class PassphraseSGX {
	static {
		File lib = new File(System.mapLibraryName("gdrive")); //No I18N
		System.load(lib.getAbsolutePath());
    }
	public native byte[] getPassphrase(String id);

	public static void main(String args[]){
		new PassphraseSGX().getPassphrase(args[0]);
	}
	 
}