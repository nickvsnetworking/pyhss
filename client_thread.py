from threading import Thread
import time

class MyThread(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.start()

    def run(self):
        while (True):
            self.foo()
            time.sleep(0.1)

    def foo(self):
        print("foo !")

my = None

while True:
    user_input = input("What do I do ? ")

    if user_input == "start thread":
        #Will start a threat that prints foo every second.
        if my == None: 
            print("Starting thread...")
            my = MyThread()
        else:
            print("Thread is already started.")

    elif user_input == "hello":
        print("Hello !")

    else:
        print("This is not a correct command.")
