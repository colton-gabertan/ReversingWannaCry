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

## Static Analysis:

To begin, I decided to isolate my malware analysis environment by working in a virtual machine and cutting off its connection to my network. WannaCry is commonly spread as a worm, which is exactly how I caught it. Setting up the vm environment without network connectivity is essential in ensuring that none of it leaked into my local network during analysis.
Due to our analysis being static, meaning we will not run the binary, there is low risk to us; however, it is a good habit to take precautions when working with actual malicious software.

From here, I loaded the sample into a new Ghidra project and started poking around to gather basic information about the binary. I tend to like starting by taking a look at the functions, and in this instance, the one that pokes out is called `PlayGame()`.

### `PlayGame()` Fuction
![image](https://user-images.githubusercontent.com/66766340/152134039-51bc9b4d-5f93-45e8-ba7d-3d88f3ff2859.png)

A peek at its decompilation and we're greeted by a call to `sprintf`, meaning it begins by writing to a string. Its parameters are already pretty clear that it forms a path. I noted it as a pre-comment: `C:\WINDOWS\mssecsvc.exe`. I also decided to rename the string it was writing to as `mssecsvc_path`.

### Decompilation of `PlayGame()`
![image](https://user-images.githubusercontent.com/66766340/152135700-5f49524f-0737-41a4-a207-a2ce2850e2a9.png)

Out of curiosity, I decided to search up the name of this executable to see if it was a common microsoft binary, or if it was a malicious one trying to hide in plain sight. Just to confirm that I am working with WannaCry, `mssecsvc.exe` is a known, common, [host-based signature]. 

Pressing further into this function, there is a call to `FUN_10001016()`. A quick glance at its decompilation and we can see that it's making use of the windows api to do some resource handling. It starts by trying to locate a resource, specifically one by the handle of `0x65` or `101` in decimal. I renamed this variable `rsrc_101_handle`. It then loads it into another variable, which I dubbed `rsrc_101_data` and locks it into another variable, `rsrc_101_ptr`. Lastly, it gets the size and stores it in my `rsrc_101_size` variable, and it writes to the `mssecsvc_path` we found in the previous function.

Since the function is all about resource handling, it was fitting to rename it to `handleResources()`. It also returned int values, so I changed the function signature to ensure that it was of the proper form in the decompilation.

### Decompilation of `handleResources()`
![image](https://user-images.githubusercontent.com/66766340/152139792-40b8cd74-2940-4bc7-b06d-645ceaf4a71f.png)

[here]: https://github.com/colton-gabertan/xcjg-honeypot/blob/Index/README.md
[FLAREVM]: https://github.com/mandiant/flare-vm
[Ghidra]: https://ghidra-sre.org/
[host-based signature]: https://www.2-spyware.com/file-mssecsvc-exe.html
