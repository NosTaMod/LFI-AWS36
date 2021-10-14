# LFI-AWS36

LFI-AWS36 is a  automatic tool able to scan  Local File Inclusion vulnerabilities using many different methods of attack.
#### A -> Arena  
#### W -> Web 
#### S -> Security 
#### LFI -> LFI
#### 36-> Batch-36
### Coded by [NosTa](https://t.me/NosTaMod)
### Channel Youtube : [Youtube](https://www.youtube.com/c/nostamod)

##### LFI-AWS36 IMAGE
![alt text](https://a.top4top.io/p_2113f3va81.png "LFI-AWS36")






## Installation
``` 
$ cd LFI-AWS36 
$ pip3 install -r requirements.txt
$ chmod +x LFI-AWS36.py 

```
## Runing

#### help
```
$ ./LFI-AWS36.py -h
```
#### Fast Scan Mod
```
$ ./LFI-AWS36.py -u https://site.com/index.php?page=
$ ./LFI-AWS36.py -u https://site.com/index.php?page= -p 127.0.0.1:9050
```
#### Scan /proc/Self/environ
```
$ ./LFI-AWS36.py -u https://site.com/index.php?page= -s 
$ ./LFI-AWS36.py -u https://site.com/index.php?page= -s -p 127.0.0.1:9050
```
#### Scan /etc/*
```
$ ./LFI-AWS36.py -u https://site.com/index.php?page= -e
$ ./LFI-AWS36.py -u https://site.com/index.php?page= -e -p 127.0.0.1:9050
```
#### Scan /proc/self/fd/*
```
$ ./LFI-AWS36.py -u https://site.com/index.php?page= -f
$ ./LFI-AWS36.py -u https://site.com/index.php?page= -f -p 127.0.0.1:9050
```
#### Deep Scan <> Scan All Path
```
$ ./LFI-AWS36.py -u https://site.com/index.php?page= -d
$ ./LFI-AWS36.py -u https://site.com/index.php?page= -d  -p 127.0.0.1:9050
``` 

