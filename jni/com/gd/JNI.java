
package com.gd;

import java.io.*;
import java.lang.*;
public class JNI {
	static {
		File lib = new File(System.mapLibraryName("gdrive")); //No I18N
		System.load(lib.getAbsolutePath());
    }
	public native byte[] getPassphrase(String id);

	public static void main(String args[]){

		JNI jni = new JNI();
		
		byte[] pas = jni.getPassphrase(args[0]);

		System.out.println(pas);

	}
	 
}