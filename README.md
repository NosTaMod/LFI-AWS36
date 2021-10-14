# LFI-scanner

LFI-scanner is a  automatic tool able to scan  Local File Inclusion vulnerabilities using many different methods of attack.
#### G -> Arena  
#### S -> Web 
#### T -> Security 
#### LFI -> LFI
### Coded by [NosTa](https://t.me/NosTaMod)
### Channel Youtube : [Youtube](https://www.youtube.com/c/nostamod)

##### LFI-scanner IMAGE
![alt text](https://a.top4top.io/p_2113f3va81.png "LFI-scanner")






## Installation
``` 
$ cd LFI-scanner 
$ pip3 install -r requirements.txt
$ chmod +x LFI-scanner.py 

```
## Runing

#### help
```
$ ./LFI-scanner.py -h
```
#### Fast Scan Mod
```
$ ./LFI-scanner.py -u https://site.com/index.php?page=
$ ./LFI-scanner.py -u https://site.com/index.php?page= -p 127.0.0.1:9050
```
#### Scan /proc/Self/environ
```
$ ./LFI-scanner.py -u https://site.com/index.php?page= -s 
$ ./LFI-scanner.py -u https://site.com/index.php?page= -s -p 127.0.0.1:9050
```
#### Scan /etc/*
```
$ ./LFI-scanner.py -u https://site.com/index.php?page= -e
$ ./LFI-scanner.py -u https://site.com/index.php?page= -e -p 127.0.0.1:9050
```
#### Scan /proc/self/fd/*
```
$ ./LFI-scanner.py -u https://site.com/index.php?page= -f
$ ./LFI-scanner.py -u https://site.com/index.php?page= -f -p 127.0.0.1:9050
```
#### Deep Scan <> Scan All Path
```
$ ./LFI-scanner.py -u https://site.com/index.php?page= -d
$ ./LFI-scanner.py -u https://site.com/index.php?page= -d  -p 127.0.0.1:9050
``` 

