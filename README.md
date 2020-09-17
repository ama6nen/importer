# importer

###  Absolutely useless small asm program that finds kernel32.dll address and then imports functions from it

## Needs nasm and golink
* http://www.godevtool.com/Golink.zip
* https://www.nasm.us/pub/nasm/releasebuilds/2.15.05/win64/nasm-2.15.05-win64.zip

#### Useless "features"
  * positive sp value found for ida function decompilation
  * Actual program not shown func in ida because no ret
  * Start function returns indirectly to actual program thru ebp
  * Absolutely 0 imports
  * Gets kernel32 from call stack in a stupid way
  * Finds exported functions from kernel32 with fnv32 name hash
  * Has 0 practical usage
  * Uses convoluted macros that make everything harder to read for the coder for no reason
  * Only 2kb, wow, so useful!
  * Bad asm code
  
  ### Screenshots from IDA
  
  ![](https://i.imgur.com/ux7xD2x.png)
  ![](https://i.imgur.com/0stpOfN.png)
  ![](https://i.imgur.com/zxJb6ZQ.png)
  ![](https://i.imgur.com/A4aSH66.png)
