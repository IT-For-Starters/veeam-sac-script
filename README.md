# Veeam Security & Compliance

This script will enable you to instantly pass all PC-related Security & Compliance checks in Veeam Backup & Replication Console

This script passes everything in Section 1 - Backup Infrastructure Security

## Prerequisites
You need to allow Powershell scripts to run on the system. The easiest way to do this is to run this **as admin**:

```powershell
Set-ExecutionPolicy Unrestricted
```

You will also need to run the script as admin.

## Features
:white_check_mark: All commands are ran locally, and no outputs are sent to anyone

:white_check_mark: All script actions are recorded and logged to C:\VeeamSecurityScript\

:white_check_mark: All changes need to be confirmed by you first, to stop the script breaking something that you need to keep on (or off)

## Usage

1. Download the script
2. Open Powershell **as admin**, ```Set-Location``` to your script file location, then run ```.\veeamsecurity.ps1``` 
3. Run through the script. Wherever something needs to be changed, it will first warn you of the change and prompt for confirmation. Press Y to change, or H to halt that command.
4. Once finished, it's a good idea to run it again and make sure it all comes back green. If you halt any commands previously, you will be prompted again for them.


## Common Oopsies

 - If you're using RDP to connect to your Veeam Server, disabling RDS (the first check) will kill RDP on your Veeam Server. This will kick you off the server and stop you from being able to reconnect remotely using RDP. The script warns you of this.

 ## Example Images
 ![Before and After](https://github.com/itfs-steve/veeam-sac-script/blob/main/img/before_after_script_20240119.png)

 ![Script Output](https://github.com/itfs-steve/veeam-sac-script/blob/main/img/script_ran_20230119.png)