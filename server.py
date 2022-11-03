import os
import socket
import threading
import tqdm
import platform
import shutil
from threading import Thread
from hashlib import sha256


class CustomThread(Thread):
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs={}, Verbose=None):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None

    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)

    def join(self, *args):
        Thread.join(self, *args)
        return self._return


platform = platform.system()

delete_file = 'rm' if platform != 'Windows' else 'del /f /q'
slash = '/' if platform != 'Windows' else '\\'
disable_stdout = '1>/dev/null' if platform != 'Windows' else '1> nul'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
IP = s.getsockname()[0]
s.close()
PORT = 4456
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"

if os.path.isdir(SERVER_DATA_PATH) == False:
    os.mkdir(SERVER_DATA_PATH)

pwd = os.path.dirname(os.path.relpath(__name__)) + slash + SERVER_DATA_PATH

help_text = """\n\npwd, cd: Show the current directory
list, ls, dir, -l: List all the files from the server.
upload, -u <path>: Upload a file to the server.
To upload a directory, client.py creates a .zip file automatically (be careful with the size).
download, get, -d <file to download>: Download file from the server.
You can use '*' to download all the files: get *
cat, type: to read he content of the file (if its readable)
delete, rm, del  <filename>: Delete a file from the server.
logout, quit, q, exit: Disconnect from the server.
help, -h: List all the commands.\n"""


def send_file(fname, ip, port, server_data_path=SERVER_DATA_PATH):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ip, int(port) + 1))
        file = open(f"{server_data_path}{slash}{fname}", 'rb')
        file_size = os.path.getsize(f"{server_data_path}{slash}{fname}")
        file_hash = sha256(
            open(f"{server_data_path}{slash}{fname}", 'rb').read()).hexdigest()
        client.send(fname.split(slash)[-1].encode())
        client.recv(1024).decode()
        client.send(str(file_size).encode())
        client.recv(1024).decode()
        client.send(str(file_hash).encode())
        client.recv(1024).decode()
        data = file.read()
        client.sendall(data)
        client.send(b'<END>')
        file.close()
        client.close()
        print("File transferred successfully")
    except Exception as e:
        print(e)


def recive_file(ip, port, server_data_path=SERVER_DATA_PATH):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((ip, int(port) + 1))
        server.listen()
        server.settimeout(2)
        client, addr = server.accept()
        file_name = client.recv(1024).decode()
        client.send('ok'.encode())
        file_size = client.recv(1024).decode()
        client.send('ok'.encode())
        file_hash = client.recv(1024).decode()
        client.send('ok'.encode())
        print(
            f'Reciving file: {file_name}  Size: {file_size}\nsha256: {file_hash}\n')
        file = open(f'{server_data_path}{slash}' + file_name, 'wb')
        file_bytes = b''
        done = False
        progress = tqdm.tqdm(unit='B', unit_scale=True,
                             unit_divisor=1000, total=int(file_size))
        while not done:
            # 1048576, 1024, 8196, 65536, 1024000...
            data = client.recv(int(1024000))
            if file_bytes[-5:] == b'<END>':
                done = True
            else:
                file_bytes += data
            progress.update(len(data))
        last_index = file_bytes.rfind(b'>')
        replaced_last = file_bytes[:last_index-4] + \
            b'' + file_bytes[last_index+1:]
        file.write(replaced_last)
        file.close()
        client.close()
        server.close()
        return file_name, file_hash
    except Exception as e:
        print(e)


def handle_client(conn, addr):
    client_platform = conn.recv(SIZE).decode()
    print(f"[NEW CONNECTION] {addr} connected [PLATFORM] {client_platform}")
    conn.send(("OK@Welcome to the File Server:" + help_text).encode())

    while True:
        try:
            data = conn.recv(SIZE).decode()
            data = data.split("@")
            cmd = data[0]
        except:
            break
        if cmd == "list" or cmd == "-l" or cmd == "ls" or cmd == 'dir':
            all_files = os.listdir(SERVER_DATA_PATH)
            files = []
            for f in all_files:
                if not os.path.isdir(os.path.join(SERVER_DATA_PATH, f)):
                    files.append(f)
                else:
                    shutil.make_archive(
                        SERVER_DATA_PATH+slash+f, 'zip', SERVER_DATA_PATH+slash+f)
                    files.append(f'{f}.zip')
                    os.system(
                        f'rmdir /q "{SERVER_DATA_PATH}{slash}{f}" 1> nul')
            send_data = "OK@"
            if len(all_files) == 0:
                send_data += "The server directory is empty"
            else:
                send_data += "\n" + "\n".join(f for f in files) + "\n"
            conn.send(send_data.encode())
        elif cmd == 'OK':
            send_data = "OK@"
            conn.send(send_data.encode())
        elif cmd == 'pwd' or cmd == 'cd':
            send_data = 'OK@'
            conn.send(f'{send_data}{pwd}'.encode())
        elif cmd == "upload" or cmd == "-u":
            port = data[2]
            print(f"\n{'*' * 72}")
            print(f"{addr} has requested a file upload through port: {int(port) + 1}")
            t = CustomThread(target=recive_file, args=(IP, port))
            t.start()
            try:
                fname, file_hash = t.join()
                files = os.listdir(SERVER_DATA_PATH)
                if fname in files:
                    print("Checking integrity...")
                    file_sha256 = sha256(open(
                        SERVER_DATA_PATH+slash+fname, 'rb').read()).hexdigest()
                    if str(file_sha256) == file_hash:
                        print("OK")
                        print(f"sha256: {file_sha256}")
                        conn.send(
                            f"OK@< {fname} >  uploaded successfully.".encode())
                    else:
                        conn.send(
                            "OK@Uploaded file seems to be corrupted".encode())
                        print("Integrity check failed!")
                        os.system(
                            f'{delete_file} "{SERVER_DATA_PATH}{slash}{fname}" {disable_stdout}')
            except:
                conn.send("OK@Could not upload file!".encode())
            print(f"{'*' * 72}\n")
        elif cmd == 'download' or cmd == '-d' or cmd == 'get':
            files = os.listdir(SERVER_DATA_PATH)
            send_data = "OK@"
            try:
                fname = data[1].split(slash)[-1]
                port = data[2]
            except:
                continue
            if not os.path.isdir(SERVER_DATA_PATH + slash + fname):
                print(
                    f"{addr} has requested a to file dowload: {fname} through port: {int(port) + 1}")
                if len(files) == 0:
                    send_data += "The server directory is empty"
                else:
                    try:
                        if fname in files and not os.path.isdir(fname):
                            try:
                                threading.Thread(target=send_file,
                                                 args=(fname, addr[0], port)).start()
                            except Exception as e:
                                print(f"ERROR: {e}")
                                send_data += "File could not be downloaded!"
                        else:
                            send_data += "File not found."
                    except:
                        continue
            else:
                send_data += "You must specify a file to download."
            conn.send(send_data.encode())
        elif cmd == "delete" or cmd == "rm" or cmd == "del":
            files = os.listdir(SERVER_DATA_PATH)
            send_data = "OK@"
            try:
                filename = data[1].split(slash)[-1]
                print(f"{addr} has requested the deletion of the file: {filename}")
            except:
                filename = ''
                send_data += "You must specify the file to delete."
            if len(files) == 0:
                send_data += "The server directory is empty"
            else:
                if filename in files or filename != '':
                    os.system(
                        f'{delete_file} "{SERVER_DATA_PATH}{slash}{filename}" {disable_stdout}')
                    files = os.listdir(SERVER_DATA_PATH)
                    if filename not in files:
                        send_data += "File deleted successfully."
                        print(f"{filename} deleted successfully")
                    else:
                        send_data += "File could not be deleted!"
                elif filename != '':
                    send_data += "File not found."
            conn.send(send_data.encode())
        elif cmd == "cat" or cmd == "type":
            files = os.listdir(SERVER_DATA_PATH)
            send_data = 'OK@'
            try:
                filename = data[1].split(slash)[-1]
                print(f"{addr} has requested the reading of the file: {filename}")
            except:
                filename = ''
                send_data += "You must specify the file to read."
            if len(files) == 0:
                send_data += "The server directory is empty"
            else:
                if filename in files:
                    try:
                        f = open(filename, 'r')
                        content = ('#' * 79) + '\n' + ('-' * (15 + len(filename))) + '\n| File name: ' + filename + ' |\n' + ('-' * (15 + len(filename))) + '\n\n' + \
                            ''.join(f.readlines()) + '\n' + ('#' * 79)
                        send_data += content
                    except Exception as e:
                        send_data += "File could not be read!"
                elif filename != '':
                    send_data += "File not found."
            conn.send(send_data.encode())
        elif cmd == "logout" or cmd == "exit" or cmd == "quit" or cmd == "q":
            break
        elif cmd == "help" or cmd == '-h':
            data = "OK@"
            data += help_text
            conn.send(data.encode())
        elif cmd == 'ok':
            conn.send('OK@'.encode())
        else:
            data = "OK@You have to chose one available command:"
            data += help_text
            conn.send(data.encode())
    print(f"[DISCONNECTED] {addr} disconnected")
    conn.close()


def main():
    print(f"\n[STARTING] Server is starting... [PLATFORM] {platform}\n")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    print(f"[LISTENING] Server is listening on {IP}:{PORT}.")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


if __name__ == "__main__":
    main()
