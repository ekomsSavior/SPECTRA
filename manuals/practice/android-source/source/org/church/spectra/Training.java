package org.church.spectra;
/** Benign SPECTRA fixture; no Android framework, file, network or device access. */
public class Training {
    private final int bias;
    public Training(int bias) { this.bias = bias; }
    public int add(int left, int right) { return left + right + bias; }
    public static int sum(int limit) { int total=0; for(int i=0;i<limit;i++) total+=i; return total; }
    public static String classify(int value) {
        switch(value) { case 1: return "one"; case 3: return "three"; case 7: return "seven"; default: return "other"; }
    }
    public static int divide(int numerator, int denominator) {
        try { return numerator/denominator; } catch(ArithmeticException zero) { return -1; }
    }
    public static String label(boolean allowed) { return allowed ? "SPECTRA_FIXTURE_ONLY.example" : "denied"; }
    public static byte[] decode(byte[] input, int key) {
        byte[] output = new byte[input.length]; for(int i=0;i<input.length;i++) output[i]=(byte)(input[i]^key); return output;
    }
    public static String unicode() { return "church \u0000 \u03bb \ud83d\ude80"; }
}
