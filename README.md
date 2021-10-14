# AWS-LFI

AWS-LFI is a  automatic tool able to scan  Local File Inclusion vulnerabilities using many different methods of attack.
#### A -> Arena  
#### W -> Web 
#### S -> Security 
#### LFI -> LFI

### Coded by [NosTa](https://t.me/NosTaMod)
### Channel Youtube : [Youtube](https://www.youtube.com/c/nostamod)

##### AWS-LFI IMAGE
![alt text](https://a.top4top.io/p_2113f3va81.png "AWS-LFI")






## Installation
``` 
$ cd AWS-LFI 
$ pip3 install -r requirements.txt
$ chmod +x AWS-LFI.py 

```
## Runing

#### help
```
$ ./AWS-LFI.py -h
```
#### Fast Scan Mod
```
$ ./AWS-LFI.py -u https://site.com/index.php?page=
$ ./AWS-LFI.py -u https://site.com/index.php?page= -p 127.0.0.1:9050
```
#### Scan /proc/Self/environ
```
$ ./AWS-LFI.py -u https://site.com/index.php?page= -s 
$ ./AWS-LFI.py -u https://site.com/index.php?page= -s -p 127.0.0.1:9050
```
#### Scan /etc/*
```
$ ./AWS-LFI.py -u https://site.com/index.php?page= -e
$ ./AWS-LFI.py -u https://site.com/index.php?page= -e -p 127.0.0.1:9050
```
#### Scan /proc/self/fd/*
```
$ ./AWS-LFI.py -u https://site.com/index.php?page= -f
$ ./AWS-LFI.py -u https://site.com/index.php?page= -f -p 127.0.0.1:9050
```
#### Deep Scan <> Scan All Path
```
$ ./AWS-LFI.py -u https://site.com/index.php?page= -d
$ ./AWS-LFI.py -u https://site.com/index.php?page= -d  -p 127.0.0.1:9050
``` 

