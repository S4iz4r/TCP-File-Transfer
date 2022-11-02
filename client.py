import socket
import tqdm
import os
import time
import threading
import platform
import re
import shutil
from threading import Thread
from hashlib import sha256

PORT = 4456
IP = '127.0.0.1'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
SELF_IP = s.getsockname()[0]
s.close()
FORMAT = "utf-8"
SIZE = 8192  # 1024
CLIENT_DATA_PATH = 'downloaded'

platform = platform.system()
re_ip = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

delete_file = 'rm'if platform != 'Windows' else 'del'
slash = '/'if platform != 'Windows' else '\\'


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


def upload_file(fname, ip, port):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ip, port + 1))
        file = open(fname, 'rb')
        file_size = os.path.getsize(fname)
        file_hash = sha256(open(fname, 'rb').read()).hexdigest()
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
        return True
    except Exception as e:
        print(e)


def recive_file(ip, port, client_data_path=CLIENT_DATA_PATH):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((ip, port + 1))
        server.listen()
        client, addr = server.accept()
        file_name = client.recv(1024).decode()
        client.send('ok'.encode())
        file_size = client.recv(1024).decode()
        client.send('ok'.encode())
        file_hash = client.recv(1024).decode()
        client.send('ok'.encode())
        print(
            f'Reciving file: {file_name}  Size: {file_size}\nsha256: {file_hash}\n')
        if os.path.isdir(client_data_path) == False:
            os.mkdir(client_data_path)
        file = open(f'{client_data_path}{slash}' + file_name, 'wb')
        file_bytes = b''
        done = False
        progress = tqdm.tqdm(unit='B', unit_scale=True,
                             unit_divisor=1000, total=int(file_size))
        while not done:
            # 1048576, 1024, 8196, 65536, 1024000...
            data = client.recv(1024000)
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


def main(IP):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if IP != '':
        try:
            client.connect((IP, PORT))
            client.send(platform.encode())
        except ConnectionRefusedError:
            print(f"Failed to connect to {IP} through port {PORT}...")
            exit()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        IP = s.getsockname()[0]
        s.close()
        try:
            client.connect((IP, PORT))
            client.send(platform.encode())
        except ConnectionRefusedError:
            print(f"Failed to connect to {IP} through port {PORT}...")
            exit()
    print(f"Connecting to [{IP}:{PORT}]")
    while True:
        data = client.recv(SIZE).decode()
        try:
            cmd, msg = data.split("@", 1)
        except Exception as e:
            print(e)
        if cmd == "DISCONNECTED":
            print(f"[SERVER]: {msg}")
            break
        elif cmd == "OK":
            if not msg.startswith("OK@"):
                print(f"{msg}")
        data = ''
        while data == '':
            try:
                data = input("> ")
            except:
                print('incorrect command!')
        data = data.split(" ")
        cmd = data[0].lower()
        payload = " ".join(data[1:])
        if cmd == "help" or cmd == "-h":
            client.send(cmd.encode())
        elif cmd == "pwd" or cmd == 'cd':
            client.send(cmd.encode())
        elif cmd == "logout" or cmd == "exit" or cmd == "quit" or cmd == "q":
            client.send(cmd.encode())
            break
        elif cmd == "list" or cmd == "-l" or cmd == "ls" or cmd == "dir":
            client.send(cmd.encode())
        elif cmd == "delete" or cmd == "rm" or cmd == "del":
            try:
                client.send(f"{cmd}@{payload}".encode())
            except:
                client.send(cmd.encode())
        elif cmd == 'cat' or cmd == "type":
            try:
                client.send(f"{cmd}@{payload}".encode())
            except:
                client.send(cmd.encode())
        elif cmd == "upload" or cmd == "-U" or cmd == "-u":
            multiple = False
            port = PORT
            multi = len(payload.split(', '))
            for file in payload.split(", "):
                if multi > 1:
                    multiple = True
                else:
                    multiple = False
                if os.path.isdir(file):
                    print(f"{file} is a directory, converting to .zip file...")
                    shutil.make_archive(file, 'zip', file)
                    file = zip_file = file + ".zip"
                if os.path.isfile(file):
                    try:
                        client.send(f'{cmd}@{file}@{port}'.encode())
                        t = CustomThread(target=upload_file,
                                         args=(file, IP, port,))
                        t.start()
                        ok = t.join()
                        if multiple:
                            data = client.recv(1024).decode()
                            print(data.split('@')[1])
                        if zip_file and ok:
                            print("Deleting converted .zip file...")
                            os.system(
                                f'{delete_file} /f /q "{zip_file}" 1> nul')
                            zip_file = None
                    except:
                        client.send('ok@'.encode())
                else:
                    print('File not found')
                    client.send('ok@'.encode())
                multi -= 1
                port += 1
        elif cmd == 'download' or cmd == '-d' or cmd == 'get':
            name = payload
            if name == '*':
                client.send('ls'.encode())
                data = client.recv(1024).decode()
                rcmd, msg = data.split("@")
                print("Downloading all files.")
                port = PORT
                for i in msg[1:-1].split('\n'):
                    print(f"\n{'*' * 72}")
                    t = CustomThread(target=recive_file,
                                     args=(SELF_IP, port))
                    t.start()
                    client.send(f"{cmd}@{i}@{port}".encode())
                    try:
                        fname, file_hash = t.join()
                        files = os.listdir(CLIENT_DATA_PATH)
                        if fname in files:
                            print("Checking integrity...")
                            file_sha256 = sha256(open(
                                CLIENT_DATA_PATH+slash+fname, 'rb').read()).hexdigest()
                            if str(file_sha256) == file_hash:
                                print("OK")
                                print(
                                    f"sha256: {file_sha256}")
                                print("File downloaded successfully.")
                                print(f"{'*' * 72}\n")
                            else:
                                print("Downloaded file seems to be corrupted.")
                                print(f"{'*' * 72}\n")
                        else:
                            print("Could not download file!")
                            print(f"{'*' * 72}\n")
                    except:
                        pass
                    port += 1
            else:
                print(f"\n{'*' * 72}")
                t = CustomThread(target=recive_file,
                                 args=(SELF_IP, PORT))
                t.start()
                client.send(f"{cmd}@{name}@{PORT}".encode())
                try:
                    fname, file_hash = t.join()
                    files = os.listdir(CLIENT_DATA_PATH)
                    if fname in files:
                        file_sha256 = sha256(open(
                            CLIENT_DATA_PATH+slash+fname, 'rb').read()).hexdigest()
                        if str(file_sha256) == file_hash:
                            print(f"sha256: {file_sha256}")
                            print("File downloaded successfully.")
                            print(f"{'*' * 72}\n")
                        else:
                            print("Downloaded file seems to be corrupted.")
                            print(f"{'*' * 72}\n")
                    else:
                        print("Could not download file!")
                        print(f"{'*' * 72}\n")
                except:
                    continue
        else:
            client.send(cmd.encode())

    print("Disconnected from the server.")
    client.close()


if __name__ == "__main__":
    while True:
        ip = input("Enter <IP> to connect: ")
        if re_ip.match(ip):
            IP = ip
            break
        elif ip == '':
            print("No ip address provided, using localhost by default")
            ip = IP
            break
    main(IP)
