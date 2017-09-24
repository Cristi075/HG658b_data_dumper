# Huawei HG658b data dumper

This is a script that can be used for extracting data from your Huawei HG658b router.
No credentials are required, you just have to be connected to the router (and see its web interface).
This might be useful if you forgot the credentials that you set up or that were provided to you by your ISP and you want to recover them.

## Quickstart

To use this script just follow these steps:
* Connect to your Huawei HG658b router by Wi-Fi or by using an ethernet cable
* Clone this repository
* Make sure that you have python (2.7) and pip installed on your computer
* Go into the folder where you cloned this repository and run 'pip install -r requirements.txt'
* Run 'python dump_data.py'
Your default gateway (which should be your router) should be auto-detected and if the error used to grab the config was not fixed on your router (by a firmware update maybe?) you should see your data.

## Prerequisites

This script uses python2.7 and it was tested on Windows and Ubuntu.
It requires some packages that can be installed with pip. There are two ways to install them.
The first one would be to manually install every required package by running.
```
pip install lxml
pip install requests
pip install pyaes
pip install netifaces
```
The second method would be to use the provided requirements file and install all of them at once:
```
pip install -r requirements.txt
```

## Arguments

If you run the script without specifying any argument it will try to get the config from your default gateway (which should be the router if you are connected to it).
You can also use the following arguments:
* target - use it to specify the IP of your router
* complete_data - use it to dump more data that might not be of interest for most users (data related to the management server for example)
* dump_config - use it to write the xml config to a file. Some bytes at the beginning will be removed so this config cannot be uploaded back into the router

Example using all the arguments (assuming the IP address of your router is 192.168.100.1):
```
python dump_data.py --target=192.168.100.1 --complete_data --dump_config=cfg.xml
```

## Possible improvements

Things that might be added if I decide to improve this script:
* More data printed out for the user. The main challenge would be to decide what data is relevant
* A better way of printing the data. (Maybe some tables?)
* Support for more HG658 models. Only the encryption data should be different. However, I don't have any other routers.

## Acknowledgments

I read about the bug that allowed me to create this script on this page: https://hg658c.wordpress.com/2015/07/07/directory-traversal-bug/