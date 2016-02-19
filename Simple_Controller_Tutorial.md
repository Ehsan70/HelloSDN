<b>Goal</b>: Controlling Pakcet network using simple Ryu app. 

<b>Requirements:</b>
A basic knowlege of Ryu and OpenFlow is required. 

<b>Dependencies</b>: This tutorial only uses `Simple_Controller.py` from the repo.

<b>Environment: </b> I have used the VM from sdn hub, I recommond you do the same. Link for installation is provided below: http://sdnhub.org/tutorials/sdn-tutorial-vm/

<b>Road Map: </b>This document has three sections for setup: 

 1. Setup 
 2. Doing tests </br>

<b>Notations: </b>
 - `>` means the linuc command line <br>
 - `mininet>` means the mininet command line


<b>Order of tutorials: </b>
 1. First install SDN hub virtual machine and do the excercise. follow the instructions on http://sdnhub.org/tutorials/ryu/  
 2. Then read http://osrg.github.io/ryu-book/en/html/switching_hub.html
 3. Read through the code on `Simple_Controller.py` and understand the commands and fucntions.
 
# 1. Setup
 
### a. Run Ryu
Run the RYU controller using this command. 
```shell
> sudo ryu-manager --verbose --observe-links < Address of Simple_controller.py>
```

In my case it is: 
```shell
> ~/ryu/bin/ryu-manager --verbose ~/HelloSDN/Simple_Controller.py
```
### b. Run a simple Mininet network
Do the following in a seprate termina:  
```shell
> sudo mn --topo single,3 --mac --controller remote --switch ovsk
```
Note that you could alternative method to set up your network. (for example python script)
# 2. Doing some Tests
### Do a pingall
```shell
mininet> pingall
```
You would see of PacketIn messages received on the Ryu terminal. </br>
Because the controller acts as a learning switch it should not fail any of the pings. 
```
mininet> pingall
*** Ping: testing ping reachability
h1 -> h2 h3 
h2 -> h1 h3 
h3 -> h1 h2
