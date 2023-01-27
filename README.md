# NetAnalyzer 
A Simple tool for analyzing network packets as well as performing ARP spoofing.

## Usage
```
git clone https://github.com/JussiKarkkainen/NetAnalyzer.git
cd NetAnalyzer
```
For passively sniffing network packets:
```
./run.sh -s
```

For performing ARP spoofing:
```
./run.sh -i [Own IP] [Own MAC] [Interface] [Target one IP] [Target two IP]
```


