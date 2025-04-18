# Setup Instructions
Download both the .c and the .h files to your local Linux machine. We recommend using Kali Linux, which was the distribution we used while testing these instructions. 

Install required dependencies for the code: 
**apt-get install libssl-dev**

Make sure that the C and header files are both in the same directory. Now compile the code with GCC: 
**gcc password_manager.c -lssl -lcrypto**

This concludes the set up. 
