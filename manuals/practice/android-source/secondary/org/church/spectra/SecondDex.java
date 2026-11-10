package org.church.spectra;
public class SecondDex {
    public static int total(int value) { return Training.sum(value); }
    public static int score(int value) { return value < 10 ? value * 2 : value + 5; }
}
