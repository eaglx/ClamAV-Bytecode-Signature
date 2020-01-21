# ClamAV-Bytecode-Signature

**Compile:** clambc-compiler <file_name>.c

**Test signature:** clamscan --debug -d <file_name>.cbc --bytecode-unsigned <file_to_scan>.exe

```c
VIRUSNAME_PREFIX("Malware.Foo")
VIRUSNAMES("Malw")
TARGET(1) // FILE TYPE: WINDOWS PE
// ********************************

// DECLARING PATTERNS
SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(PE_header)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(PE_header, "0:4D5A")
SIGNATURES_END
// *********************************

bool logical_trigger(void) {
    return matches(Signatures.PE_header);
}

int entrypoint(void) {
    int filePos = 0;	
    int tab[5];
    seek(filePos, SEEK_SET);

    unsigned char buf[5]; 
    int n, i;
    
    while(1){
        n = read(buf, sizeof(buf)); // Read data from the file
        if(n == 5) {           
            for(i=0; i<5; i++){
                unsigned char c = buf[i];
                tab[i] = (int)(c);
            }
            
            if((tab[0] == 52) && (tab[1] == 93) && (tab[2] == 19)){ // Check if the next numbers are: 0x34 0x5D 0x13
                debug("FOUND MALWARE");
                foundVirus("Malw");
                break;
            }
            else {
                debug("NO MALWARE FOUND");
                filePos += 1;
                seek(filePos, SEEK_SET);
            }
        }
        else {
            debug("FINISHED SCAN");
            break;
        }
    }

    return 0;
}
```
### References
* [ClamAV ByteCode Compiler](https://github.com/Cisco-Talos/clamav-bytecode-compiler)
