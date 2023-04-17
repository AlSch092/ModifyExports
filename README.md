# ModifyExports
C++ Proof-of-concept of spoofing the results returned from GetProcAddress()  

How it works:  

We can use the routines provided by ImageHlp.h and dbghelp.h to write over the names of exported functions, which changes the results returned from GetProcAddress(). First we map an image of a DLL our program has loaded using the MapAndLoad routine, we then fetch the image's export directory by using the routine ImageExportDirectory with the results of our MapAndLoad. We then grab the list of exported function names by using ImageRvaToVa with ImageExportDirectory->AddressOfNames as the third parameter, telling it that we want the address (VA) of the image export directory. Now that we have the address (VA) of exported function names we can iterate over the number of names and call ImageRvaToVa on each iteration (with the RVA of the name) to acquire the address of the string/function name.  

In the example posted here we are mainly writing over WINAPI, but this trick works for any function name from any DLL loaded into our binary. We can load "MyDLL.dll" which exports the routines "A" and "B", and change those to "C" and "D", or even "C" and "C" (duplicate symbols). If you decide to write over WINAPI names, you might encounter error messages in your program depending on which DLL it's found in.  

We can also stop most debuggers from attaching to our process if we write over the function names of certain routines. This is an anti-debugging method I haven't seen elsewhere so far and will update more on this a bit later.  

The screencap following shows what it looks like to modify a function name at runtime: certain tools will be fooled, and this can be used in malware/evasion

![Alt text](MyQueryObject.PNG?raw=true "MyQueryObject vs. NtQueryObject")   
