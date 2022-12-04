import client
import config
import server

server.main()
client.init_call(config.BROADCAST_IP_ADDRESS, config.PORT)





### This is an example of how communication between 2 computers can be started. This line of code creates a connection between 'device_ip' and this device
### This makes 'device_ip' connect to a TCP server created by the server file. What is done at this point can be chosen by the user

device_ip = '127.0.0.1'
client.start_convo(device_ip)
