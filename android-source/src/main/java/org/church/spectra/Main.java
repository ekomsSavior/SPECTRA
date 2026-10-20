package org.church.spectra;
import com.googlecode.d2j.reader.DexFileReader;
import com.googlecode.d2j.node.DexFileNode;
import com.googlecode.d2j.dex.Dex2Asm;
import org.objectweb.asm.*;
import org.teavm.jso.*;
import org.teavm.jso.core.*;
import org.teavm.jso.typedarrays.Uint8Array;
public class Main {
 private static DexFileReader reader;
 @JSBody(params={"data"}, script="return data;") private static native @JSByRef(optional=true) byte[] bytes(Uint8Array data);
 @JSBody(params={"data"}, script="return new Uint8Array(data);") private static native Uint8Array typed(@JSByRef byte[] data);
 @JSExport public static String[] open(Uint8Array data) { reader=new DexFileReader(bytes(data)); return reader.getClassNames().toArray(new String[0]); }
 @JSExport public static JSMapLike<Uint8Array> translate(int index) {
  if(reader==null) throw new IllegalStateException("Open a DEX first");
  DexFileNode node=new DexFileNode(); reader.accept(node,index,0);
  JSMapLike<Uint8Array> output=JSObjects.create();
  new Dex2Asm().convertDex(node,name -> {
   ClassWriter writer=new ClassWriter(ClassWriter.COMPUTE_MAXS) {
    @Override protected String getCommonSuperClass(String a,String b) { throw new IllegalStateException("Frame hierarchy resolution is not enabled; sample classes are never loaded"); }
   };
   return new ClassVisitor(Opcodes.ASM9,writer) {
    public void visitEnd() { super.visitEnd(); output.set(name,typed(writer.toByteArray())); }
   };
  }); return output;
 }
}
