## ModifyExports
Proof-of-concept written in C for modifying export table names at runtime. This technique can be seen as "invasive" because it can pop up error messages to the end user, and can interrupt normal program flow. This technique can also potentially be leveraged by malware to redirect program flow.

# How it works:  

We can use the routines provided by `ImageHlp.h` and `dbghelp.h` to write over the string names of exported functions within any module, which can change the results returned from `GetProcAddress`. First we map an image of a DLL our program has loaded using the `MapAndLoad` routine, and then fetch the image's export directory. We then grab the list of exported function names from the export directory by using `ImageRvaToVa` routine with `ImageExportDirectory->AddressOfNames` as the third parameter. Exported name strings can now be iterated over and modified.

Additionally, we can stop DLL injection by writing over the export names for `LoadLibrary` routines. When trying to inject we will get an error saying 'The symbol for LoadLibrary could not be found'. An example of this can be seen in the third screencap.

# Screenshot examples:
The screencap following shows what it looks like to modify a function name at runtime: We can see that the disassembler thinks `MessageBoxA` is located at both 0x7FFBE37B90D0 and 0x7FFBE37B9750. 

The second screencap shows renaming `NtQueryObject` to `MyQueryObject`. Processes that try to query the address of `NtQueryObject` using `GetProcAddress` will now fail.

The third screencap shows an example of stopping basic DLL injection through the use of this technique (invasive to the end user).

![Alt text](MessageBoxA_Duplicate.PNG?raw=true "Two Addresses for MessageBoxA")   
![Alt text](MyQueryObject.PNG?raw=true "MyQueryObject vs. NtQueryObject")  
![Alt text](anti-DLL.PNG?raw=true "anti-dll")  

## Considerations
If you're writing a larger string name over the space of an export name, you'll need to shift all memory contents in the structure after that name by the delta number of bytes. For example, if you write `MessageBoxAGood` over `MessageBoxA`, you'll need to shift any following names by +4 bytes to maintain memory.

Thank you for reading and happy coding, I hope you learned something new!  
