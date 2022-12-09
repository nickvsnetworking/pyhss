# Create Process

Before we can start service keepalives with Monit, we need to create a service.

For this we'll create a new file in ``/usr/bin`` called ``pyhss``

```
#!/bin/bash

PIDFILE=/var/run/pyhss.pid

case $1 in
   start)
       # Launch your program as a detached process
       cd /home/nick/Documents/pyhss/ && python3 hss.py >> /var/log/pyhss.log &
       # Get its PID and store it
       echo $! > ${PIDFILE} 
   ;;
   stop)
      kill `cat ${PIDFILE}`
      # Now that it's killed, don't forget to remove the PID file
      rm ${PIDFILE}
      pkill -9 -f hss.py
   ;;
   *)
      echo "usage: pyhss {start|stop}" ;;
esac
exit 0

```

You'll obviously need to adjust the path ``cd`` statement to point to the directory where you have PyHSS.

Next we'll need to make this service executable and give it the correct permissions:
```
root@oldfaithful:/home/nick# sudo chmod +x /usr/bin/pyhss 
root@oldfaithful:/home/nick# sudo chmod 777 /usr/bin/pyhs
```

Next up we can ensure the service starts as expected, by running:
```
root@oldfaithful:/home/nick# pyhss start
```

And you can stop the service with 

```
root@oldfaithful:/home/nick# pyhss stop
```


# Managing with Monit
Monit is a tool for moniting the status of services, it makes sure that services that should be running are, and will restart them if they crash.

We can use Monit to ensure the PyHSS service restarts if it stops running.

You can install Monit using your standard package manager, config is explained in the Monit docs, but an example following on from the service we saw before would be a ``monitrc`` file that contains:

```
#Enable Web Service
 set httpd port 2812 and
     use address localhost  # only accept connection from localhost (drop if you use M/Monit)
     allow localhost        # allow localhost to connect to the server and
     allow admin:monit      # require user 'admin' with password 'monit'



check process pyhss with pidfile /var/run/pyhss.pid
   start = "/usr/bin/pyhss start"
   stop = "/usr/bin/pyhss stop"
```

There are other settings to do with how often Monit checks the status (more frequent means a shorter period of potential downtime), and email when a crash happens, which is important to actually know when a crash happens.

### A note on Crashing and Detecting problems
Monit restarts services when they stop running (crash), but services *should not crash*. Monit is a safety net, but hopefully one you don't need.

PyHSS should only stop if critcal database queries (``DB.Get_Subscriber``) fail. This is typically due to a loss of connection to the database used.