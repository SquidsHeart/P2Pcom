import client
import config
import server

server.main()
client.init_call(config.BROADCAST_IP_ADDRESS, config.PORT)

print(client.start_convo("10.4.97.8"))