namespace LocalLib;
public enum Mode { Off=0, Fast=7 }
public static class Calculator {
 static Calculator() { throw new System.InvalidOperationException("DEPENDENCY CODE WAS EXECUTED"); }
 public static int Read(Mode mode) => (int)mode;
}
