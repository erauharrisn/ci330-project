# Setup Instructions
Download both the .c and the .h files to your local Linux machine. We recommend using Kali Linux, which was the distribution we used while testing these instructions. 

Run the command: 
apt-get install libssl-dev 

This will be needed for dependencies in our code. Next, ensure that the C and header files are both in the same directory. You can compile the code with GCC: 

gcc password_manager.h -lssl -lcrypto

This concludes the set up. 
