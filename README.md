# Live Malware Reverse Engineering: WannaCry Ransomware

## Overview:

After becoming interested in malware analysis and reverse engineering, I decided to spin up a honeypot to collect live samples of malware. When analyzing the binaries that my honeypot managed to capture, I found that the most common one was detected as the infamous WannaCry Ransomware.
> *If you're interested, I have a report of my honeypot project [here]*

This repo will be going over my process of analysis for this sample, explaining common reverse engineering techniques with the goals of:
* Finding host-/ network-based signatures for detection
* Determining exactly what the malicious binary does from high to low level

---
> Tools Used:
> * [FLAREVM]
> * [Ghidra]
> * [CFF Explorer VIII]
> * [PEiD]
> * [Resource Hacker]

## Static Analysis:

To begin, I decided to isolate my malware analysis environment by working in a virtual machine and cutting off its connection to my network. WannaCry is commonly spread as a worm, which is exactly how I caught it. Setting up the vm environment without network connectivity is essential in ensuring that none of it leaked into my local network during analysis.
Due to our analysis being static, meaning we will not run the binary, there is low risk to us; however, it is a good habit to take precautions when working with actual malicious software.

Before disassembling the binary, I wanted to take a look at the file headers to see what I may be dealing with. This information will let me know if the malware is packed or obfuscated at all. I was introduced to a nice tool for this called, CFF Explorer VIII, which comes standard in the FLAREVM.

One place I like to start is in the import directory to see what .exe's or .dll's that this malware tries to use. There are two imported, `KERNEL32.dll` and `MSVCRT.dll`.

### File Header Info
![image](https://user-images.githubusercontent.com/66766340/152454687-38cf8643-3eb8-41f1-91a3-3424f62b41ed.png)

So far, that's actually nothing too bad; however, KERNEL32.dll is used for core functions such as handling memory, files, and hardware. A closer look at MSVCRT.dll and we can find ntdll.dll, which is unusual for regular programs to import. And, it is used as an interface to the Windows kernel. I wanted to double check that the binary wasn't packed, with PEiD. Sure enough, it's detected as a C++ binary.

### Dependency Walker 
![image](https://user-images.githubusercontent.com/66766340/152458168-f3759bd1-95ad-473c-890a-0093446fe2a1.png)

### PEiD Info
![image](https://user-images.githubusercontent.com/66766340/152456233-8c3edbfa-7107-4589-b90a-e4adac35fa81.png)

From here, I loaded the sample into a new Ghidra project and started poking around to gather basic information about the binary. I tend to like starting by taking a look at the functions, and in this instance, the one that pokes out is called `PlayGame()`.

### `PlayGame()` Fuction
![image](https://user-images.githubusercontent.com/66766340/152134039-51bc9b4d-5f93-45e8-ba7d-3d88f3ff2859.png)

A peek at its decompilation and we're greeted by a call to `sprintf`, meaning it begins by writing to a string. Its parameters are already pretty clear that it forms a path. I noted it as a pre-comment: `C:\WINDOWS\mssecsvc.exe`. I also decided to rename the string it was writing to as `mssecsvc_path`.

### Decompilation of `PlayGame()`
![image](https://user-images.githubusercontent.com/66766340/152135700-5f49524f-0737-41a4-a207-a2ce2850e2a9.png)

Out of curiosity, I decided to search up the name of this executable to see if it was a common Microsoft binary, or if it was a malicious one trying to hide in plain sight. Just to confirm that I am working with WannaCry, `mssecsvc.exe` is a known, common, [host-based signature]. 

Pressing further into this function, there is a call to `FUN_10001016()`. A quick glance at its decompilation and we can see that it's making use of the windows api to do some resource handling. It starts by trying to locate a resource, specifically one by the handle of `0x65` or `101` in decimal. I renamed this variable `rsrc_101_handle`. It then loads it into another variable, which I dubbed `rsrc_101_data` and locks it into another variable, `rsrc_101_ptr`. Lastly, it gets the size and stores it in my `rsrc_101_size` variable, and it writes to the `mssecsvc_path` we found in the previous function.

Since the function is all about resource handling, it was fitting to rename it to `write_101_to_mssecsvc()`. It also returned int values, so I changed the function signature to ensure that it was of the proper form in the decompilation.

### Decompilation of `write_101_to_mssecsvc()`
![image](https://user-images.githubusercontent.com/66766340/152451220-96d50783-ac11-4ac5-8922-940b2731ded6.png)

Onto the next function that gets called by `PlayGame()`, `FUN_100010ab()`. Within the declared variables, there are two structs, `_STATUPINFOA` and `_PROCESS_INFORMATION`, I renamed the local variables accordingly to `startup_info` and `process_type`. These two structs are used to create processes. I took the liberty to research exactly what the initialized flags do and commented the function above each line. Seeing that this function creates a process from the `mssecsvc_path`, it was fitting to rename it to `createBadProcess()`
> `CreateProcessA()` [documentation]

### Decompilation of `createBadProcess()`
![image](https://user-images.githubusercontent.com/66766340/152450092-c8f8c213-acb1-402a-b1fa-8b72ac505540.png)

With this information, hopping back into `PlayGame()`, we can see that it is the function responsible for unpacking the rest of the malware and running it as a process on the host machine.

### `PlayGame() Re-visited`
![image](https://user-images.githubusercontent.com/66766340/152451395-425a011a-1448-4fe6-81d6-54498124d5ae.png)

Essentially, this initial binary hides the rest of the malware by storing an embedded program into its resources, which it later calls upon to continue execution. This is more likely where we will see the main processes of WannaCry. We know for sure that it looked for a resource called 101. So, I deployed Resource Hacker on the binary to find resource 101 stored in a folder called "W". From here, I extracted the resource in to a separate .bin file, W101.bin. 

### Recap:

Just to solidify what we've observed so far, WannaCry begins stealthily by writing one of the binary's resources into an executable file, and executing it as a process.

![image](https://user-images.githubusercontent.com/66766340/153566969-82ea565e-d7b6-4eb0-b6a7-669a2eb84eb0.png)




[here]: https://github.com/colton-gabertan/xcjg-honeypot/blob/Index/README.md
[FLAREVM]: https://github.com/mandiant/flare-vm
[Ghidra]: https://ghidra-sre.org/
[host-based signature]: https://www.2-spyware.com/file-mssecsvc-exe.html
[documentation]: https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
[CFF Explorer VIII]: https://ntcore.com/?page_id=388
[PEiD]: https://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml
[Resource Hacker]: https://resource-hacker.en.softonic.com/
