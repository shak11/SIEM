# SIEM
## _Security Information and Event Managment_


SIEM is a project that helps identify attacks from network.
This project collect logs from different endpoint machines and translates it 


## Features

- Intuative UI
- Works with every platform
- Easy to use


## Requirments
- [Python] - Python 3
- [evt2syslog] - Event log to Syslog

## Installation
If you would like to monitor windows endpoints you need to install [evt2syslog] by the following steps:
1. Download the .exe file
2. run cmd and go to the folder location
3. Install this as a service and enter the IP of the computer that runs SIEM
It should look like this
```sh
evt.exe -h xxx.xxx.xxx.xxx
```


## Tech

SIEM uses an open source library :
- [sklearn] - Scikit-learn


## Running the program

Open 3 terminals or 3 cmd 
First run:

```sh
python3 sys_logger.py
```
This will run the syslog server to capture all data on network

Second Tab:

```sh
python3 FW.py
```
This will run Machine Learning on all firewall logs

Third tab:

```sh
python3 WebUI.py
```
This will allow you to monitor your current network

## License
Ronen Vaaleni , Netanel Levi, Shaked Beno
   [Python]: <https://www.python.org/>
   [sklearn]:<https://scikit-learn.org/stable/>

