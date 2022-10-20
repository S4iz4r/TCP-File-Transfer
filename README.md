# TCP-File-Transfer


This is a simple file transfer ( download/upload ) based on python TCP socket connection.
You can list, upload, download or delete files from devices on the same local network

Available commands:

* pwd, cd: Show the current directory
* list, ls, dir, -l: List all the files from the server
* upload, -u <path>: Upload a file to the server  
* download, get, -d <file to download>: Download file from the server  
      - You can use '*' to download all the files: get *  
* cat, type: to read he content of the file (if its readable)  
* delete, rm, del  <filename>: Delete a file from the server  
* logout, quit, q, exit: Disconnect from the server  
* help, -h: List all the commands
  
  
The uploaded files are stored in the "sever_data" directory which is located or generated in the same path as the "server.py" script.
The downloaded files are stored in the "downloaded" directory which is located or generated in the same path as the "client.py" script.
  
# Usage:
  
- Install required modules:
      pip install -r requirements.txt
- Run "server.py" on your host server ( put the files you want to share on "server_data" directroy):
- Run "client.py" on the devices yo want to recive the files on.
  
  
To do:
  Add a functionality so that uploading and deleting files can only be done by providing a password.