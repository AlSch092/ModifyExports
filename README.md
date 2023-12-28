## ModifyExports
Proof-of-concept written in C for modifying export table names at runtime (anti-dll injection method)

# How it works:  

We can use the routines provided by ImageHlp.h and dbghelp.h to write over the string names of exported functions within any module, which can change the results returned from GetProcAddress(). First we map an image of a DLL our program has loaded using the MapAndLoad routine, we then fetch the image's export directory by using the routine ImageExportDirectory with the results of our MapAndLoad. We then grab the list of exported function names by using ImageRvaToVa with ImageExportDirectory->AddressOfNames as the third parameter, telling it that we want the address (VA) of the image export directory. Now that we have the address (VA) of exported function names we can iterate over the number of names and call ImageRvaToVa on each iteration (with the RVA of the name) to acquire the address of the string/function name.  

Additionally, we can stop DLL injection by many tools such as Cheat Engine by writing over the export strings for LoadLibraryA/W/ExA/ExW. When trying to inject we will get an error saying 'The symbol for LoadLibraryA could not be found'. Most homemade injectors will also fail to inject after this technique has been applied, and it's effects can be seen in the third screencap. A more detailed write-up intended for MITRE will accompany this topic when it's available, and can be found as "MITRE - ChangeExportNames.pdf". 

# Screenshot examples:
The screencap following shows what it looks like to modify a function name at runtime: certain tools will be fooled We can see that the disassembler thinks MessageBoxA is located at both 0x7FFBE37B90D0 and 0x7FFBE37B9750. 
The second screencap shows renaming "NtQueryObject" to "MyQueryObject".
The third screencap shows an example of stopping DLL Injection through the use of this technique.

![Alt text](MessageBoxA_Duplicate.PNG?raw=true "Two Addresses for MessageBoxA")   
![Alt text](MyQueryObject.PNG?raw=true "MyQueryObject vs. NtQueryObject")  
![Alt text](anti-DLL.PNG?raw=true "anti-dll")  

Thank you for reading, and I hope you learned something new!  
