# Callstack spoofing + Indirect Syscalls POC
This project consists of a simple C++ self-Injecting dropper focused on EDR evasion POC. To implement it, I have combined the use of  **``Windows Thread Pooling``**  to hide the call stack and the use of  **``indirect syscalls``**  to avoid hooking in the NTDLL.
<br>

![2023-10-08-23-22-35-Trim](https://github.com/pard0p/Cordyceps/assets/79936108/060db2ad-2c02-4501-bc86-5be0cff78711)

![image](https://github.com/pard0p/Cordyceps/assets/79936108/231e3722-9190-4846-88d9-66870acb7eb2)

![image](https://github.com/pard0p/Cordyceps/assets/79936108/742dee9c-7c91-41cb-9dd9-4a22985bfc5b)

![image](https://github.com/pard0p/Cordyceps/assets/79936108/aeefb8d2-cf8a-4d79-969a-7e195e878731)

![image](https://github.com/pard0p/Cordyceps/assets/79936108/eac6158f-f1f6-41f7-878f-2c1333a06b54)

As can be seen in the images, from the Cordyceps code, it performs a jump to ntdll to utilize one of the syscall instructions. This should be considered a malicious action; however, upon executing the return in ntdll, we return to the code of tpWorker, which is located within ntdll. Thus, from the perspective of the antivirus (AV), ntdll would appear to be making a call to another part of ntdll, which is not considered malicious.

## Future Upgrades:
- [x] Implement a mechanism to automatically search for the syscall number.
- [ ] In-memory payload decryption.

## To compile:

```bash
nasm -f win64 .\Assembly.asm -o .\Assembly.obj
g++ -o poc.exe main.cpp Assembly.obj
```

## Resources:

https://0xdarkvortex.dev/hiding-in-plainsight/

https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls

https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html

https://klezvirus.github.io/RedTeaming/AV_Evasion/StackSpoofing/

https://medium.com/@sruthk/cracking-assembly-fastcall-calling-convention-in-x64-c6d77b51ea86
