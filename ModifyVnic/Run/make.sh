# For PC
ifconfig enp0s31f6 up
ethtool -K enp0s31f6 rx off
ethtool -K enp0s31f6 tx off
ethtool -K enp0s31f6 tso off
ethtool -K enp0s31f6 gro off

make

#cd ../Supervisor_adhoc
#./unload
#make
#./load ${1} ${2}
#cd ../adhoc_bridge
