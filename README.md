# 🦠 Cordyceps
This project consists of a simple C++ self-Injecting dropper focused on EDR evasion. To implement it, I have combined the use of  **``Windows Thread Pooling``**  to hide the call stack and the use of  **``indirect syscalls``**  to avoid hooking in the NTDLL.
<br>

![2023-10-08-23-22-35-Trim](https://github.com/pard0p/Cordyceps/assets/79936108/060db2ad-2c02-4501-bc86-5be0cff78711)

![image](https://github.com/pard0p/Cordyceps/assets/79936108/5d2cb59c-0ea8-4f8b-ad68-298098e9b6c2)

![image](https://github.com/pard0p/Cordyceps/assets/79936108/1242c777-5c08-404d-8a7c-33da3e3cb478)

![image](https://github.com/pard0p/Cordyceps/assets/79936108/c74137be-8e4e-434b-b6c4-faf90baf7be2)

As can be seen in the images, from the Cordyceps code, it performs a jump to ntdll to utilize one of the syscall instructions. This should be considered a malicious action; however, upon executing the return in ntdll, we return to the code of tpWorker, which is located within ntdll. Thus, from the perspective of the antivirus (AV), ntdll would appear to be making a call to another part of ntdll, which is not considered malicious.

## Future Upgrades:
- [ ] Implement a mechanism to automatically search for the syscall number.
- [ ] In-memory payload decryption.

## To compile:

```bash
nasm -f win64 ./syscalls.asm -o ./syscalls.obj
g++ -o cordyceps.exe main.cpp syscalls.obj
```

## ⚠️Attention:

This POC has been developed for Windows 10. To use it in a real environment the syscalls should be adapted for the corresponding Windows version.

## Resources:

https://0xdarkvortex.dev/hiding-in-plainsight/
https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls
https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html
https://klezvirus.github.io/RedTeaming/AV_Evasion/StackSpoofing/
https://medium.com/@sruthk/cracking-assembly-fastcall-calling-convention-in-x64-c6d77b51ea86
