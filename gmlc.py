##This requires PySCTP from https://github.com/P1sec/pysctp


import socket                                                                                   
import sctp                                                                                     
from   sctp import *                                                                            
import threading     
diameter = diameter.Diameter('hss.localdomain', 'localdomain', 'PyHSS')                                                                           
                                                                     
sctp_socket = sctpsocket_tcp(socket.AF_INET)                                                  
sctp_port   = 1234                                                                              

# Here are a couple of parameters for the server                                                
server_ip     = "0.0.0.0"                                                                       
backlog_conns = 3                                                                               

# Let's set up a connection:                                                                    
sctp_socket.events.clear()                                                                    
sctp_socket.bind((server_ip, sctp_port))                                                    
sctp_socket.listen(backlog_conns)                                                             

# Here's a method for handling a connection:                                                    
def handle_client(client_socket):                                                               
  #client_socket.send("Howdy! What's your name?\n")                                              
  name = client_socket.recv(1024) # This might be a problem for someone with a reaaallly long name.
  #name = name.strip()    
  print(name)                                                                       

  client_socket.send("Thanks for calling, {0}. Bye, now.".format(name))                         
  client_socket.close()                                                                         

# Now, let's handle an actual connection:                                                       
while True:                                                                                     
    client, addr   = my_tcp_socket.accept()                                                     
    print("Call from {0}:{1}".format(addr[0], addr[1]))

    client_handler = threading.Thread(target = handle_client,                                   
                                      args   = (client,))                                       
    client_handler.start() 