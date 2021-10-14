# LFIscanner

LFIscanner is a  automatic tool able to scan  Local File Inclusion vulnerabilities using many different methods of attack.
#### A -> Arena  
#### W -> Web 
#### S -> Security 
#### LFI -> LFI
### Coded by [NosTa](https://t.me/NosTaMod)
### Channel Youtube : [Youtube](https://www.youtube.com/c/nostamod)

##### LFIscanner IMAGE
![alt text](https://a.top4top.io/p_2113f3va81.png "LFIscanner")






## Installation
``` 
$ cd LFIscanner 
$ pip3 install -r requirements.txt
$ chmod +x LFIscanner.py 

```
## Runing

#### help
```
$ ./LFIscanner.py -h
```
#### Fast Scan Mod
```
$ ./LFIscanner.py -u https://site.com/index.php?page=
$ ./LFIscanner.py -u https://site.com/index.php?page= -p 127.0.0.1:9050
```
#### Scan /proc/Self/environ
```
$ ./LFIscanner.py -u https://site.com/index.php?page= -s 
$ ./LFIscanner.py -u https://site.com/index.php?page= -s -p 127.0.0.1:9050
```
#### Scan /etc/*
```
$ ./LFIscanner.py -u https://site.com/index.php?page= -e
$ ./LFIscanner.py -u https://site.com/index.php?page= -e -p 127.0.0.1:9050
```
#### Scan /proc/self/fd/*
```
$ ./LFIscanner.py -u https://site.com/index.php?page= -f
$ ./LFIscanner.py -u https://site.com/index.php?page= -f -p 127.0.0.1:9050
```
#### Deep Scan <> Scan All Path
```
$ ./LFIscanner.py -u https://site.com/index.php?page= -d
$ ./LFIscanner.py -u https://site.com/index.php?page= -d  -p 127.0.0.1:9050
``` 

