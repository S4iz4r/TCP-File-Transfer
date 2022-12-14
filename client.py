import socket
import tqdm
import os
import platform
import re
import time
import shutil
from getpass import getpass
from threading import Thread
from hashlib import sha256

PORT = 4456
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
SELF_IP = s.getsockname()[0]
IP = ''
s.close()
CLIENT_DATA_PATH = 'downloaded'

platform = platform.system()
re_ip = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

delete_file = 'rm' if platform != 'Windows' else 'del /f /q'
slash = '/' if platform != 'Windows' else '\\'
disable_stdout = '1>/dev/null' if platform != 'Windows' else '1> nul'


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
        if os.path.isdir(client_data_path) == False:
            os.mkdir(client_data_path)
        file = open(f'{client_data_path}{slash}' + file_name, 'wb')
        file_bytes = b''
        done = False
        progress = tqdm.tqdm(unit='B', unit_scale=True,
                             unit_divisor=1000, total=int(file_size))
        while not done:
            if int(file_size) > 1024:
                data = client.recv(round(int(file_size) / 10))
            else:
                data = client.recv(1024)
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
            time.sleep(2)
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
        data = client.recv(1024).decode()
        try:
            cmd, msg = data.split("@", 1)
        except Exception as e:
            print(e)
        if cmd == "OK":
            if not msg.startswith("OK@") and not msg.startswith(" "):
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
            password = ''
            while password == '' or len(password) < 3:
                password = getpass("Insert password > ")
            password = sha256(password.encode()).hexdigest()
            try:
                client.send(f"{cmd}@{payload}@{password}".encode())
            except:
                client.send(cmd.encode())
        elif cmd == 'cat' or cmd == "type":
            try:
                client.send(f"{cmd}@{payload}".encode())
            except:
                client.send(cmd.encode())
        elif cmd == "upload" or cmd == "-U" or cmd == "-u":
            password = ''
            while password == '' or len(password) < 3:
                password = getpass("Insert password > ")
            password = sha256(password.encode()).hexdigest()
            multiple = True
            port = PORT
            multi = len(payload.split(', '))
            for file in payload.split(", "):
                zip_file = None
                if multi == 1:
                    multiple = False
                if os.path.isdir(file):
                    print(f"{file} is a directory, converting to .zip file...")
                    shutil.make_archive(file, 'zip', file)
                    file = zip_file = file + ".zip"
                if os.path.isfile(file):
                    try:
                        client.send(f'{cmd}@{file}@{port}@{password}'.encode())
                        response = client.recv(1024).decode()
                        if not response.split("@")[1].startswith("Wrong"):
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
                                    f'{delete_file} "{zip_file}" {disable_stdout}')
                                zip_file = None
                                print("OK")
                        else:
                            print(response.split("@")[1])
                            client.send("ok@".encode())
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
                                print(
                                    "Integrity check failed!\nCleaning corrupted file...")
                                os.system(
                                    f'{delete_file} "{CLIENT_DATA_PATH}{slash}{fname}" {disable_stdout}')
                                print(f"{'*' * 72}\n")
                        else:
                            print("Could not download file!")
                            print(f"{'*' * 72}\n")
                    except:
                        pass
                    port += 1
            else:
                multiple = True
                port = PORT
                multi = len(payload.split(', '))
                for f in name.split(', '):
                    if multi == 1:
                        multiple = False
                    print(f"\n{'*' * 72}")
                    t = CustomThread(target=recive_file,
                                     args=(SELF_IP, port))
                    t.start()
                    client.send(f"{cmd}@{f}@{port}".encode())
                    try:
                        fname, file_hash = t.join()
                        if multiple:
                            data = client.recv(1024).decode()
                            print(data.split('@')[1])
                        files = os.listdir(CLIENT_DATA_PATH)
                        if fname in files:
                            print("Checking integrity...")
                            file_sha256 = sha256(open(
                                CLIENT_DATA_PATH+slash+fname, 'rb').read()).hexdigest()
                            if str(file_sha256) == file_hash:
                                print("OK")
                                print(f"sha256: {file_sha256}")
                                print("File downloaded successfully.")
                                print(f"{'*' * 72}\n")
                            else:
                                print(
                                    "Integrity check failed!\nCleaning corrupted file...")
                                os.system(
                                    f'{delete_file} "{CLIENT_DATA_PATH}{slash}{fname}" {disable_stdout}')
                                print(f"{'*' * 72}\n")
                        else:
                            print("Could not download file!")
                            print(f"{'*' * 72}\n")
                    except:
                        continue
                    multi -= 1
                    port += 1
        else:
            client.send(cmd.encode())

    print("Disconnected from the server.")
    time.sleep(2)
    client.close()


if __name__ == "__main__":
    while True:
        ip = input("Enter <IP> to connect: ")
        if re_ip.match(ip):
            IP = ip
            break
        elif ip == '':
            print("No ip address provided, using localhost by default")
            IP = SELF_IP
            break
    main(IP)
