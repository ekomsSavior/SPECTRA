static const char marker[]="SPECTRA_FIXTURE_ONLY.example";
int fixture_helper(const char *s) { return s[0]; }
int main(void) { return fixture_helper(marker); }
