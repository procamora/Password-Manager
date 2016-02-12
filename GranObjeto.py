# -*- coding: utf-8 -*-
import os
from pprint import pprint
#http://www.saltycrane.com/blog/2011/10/python-gnupg-gpg-example/

import gnupg
from easygui import enterbox, passwordbox, codebox, msgbox

class Objetito:
    def __init__(self, passwd, email=None, fich=None):
        self.gpg = gnupg.GPG(gnupghome='Z:/ProgramasPropios/python/password-manager/tmp/', verbose=False)
        #self.gpg.encoding = 'utf-8'
        self.SecretFich = 'secret.pub'
        self.password = passwd
        self.mail = email
        self.fichero = fich
        self.ErrorDecrypted = 'Fail decrypted'
        self.ErrorEncrypted = 'Fail encrypted'


    def init(self, passwd=None):
        if passwd != None:
            self.password = passwd
        print(self.password)

        a = self._CompruebaPasswd()
        if a == self.ErrorDecrypted:
            return self.ErrorDecrypted

        elif a != 'No hay fichero':
            #print 'asd'
            return self._ProcesosComunes()

        else:
            return 'error'


    def _ProcesosComunes(self):

        if os.path.exists(self.SecretFich) and os.path.exists(self.fichero):
            datos = self.DecryptString(encrypted=open(self.SecretFich, 'r').read()).split('\n')
            #self.password = datos[0]
            self.mail = datos[1]
            self.fichero = datos[2]
        else:
            self.key = self.GenerateKeys()
            self.CreaFicheroPasswd()
            self.ExportKeys()
        return None

    def _CompruebaPasswd(self):
        if os.path.exists(self.SecretFich):
            datos = self.DecryptString(encrypted=open(self.SecretFich, 'r').read())
            #print datos
            if datos != self.ErrorDecrypted:
                return datos.split('\n')
            else:
                return self.ErrorDecrypted
        return 'No hay fichero'

    def GenerateKeys(self):
        input_data = self.gpg.gen_key_input(key_type="RSA", key_length=2048, name_real='test', name_email=self.mail, passphrase=self.password)
        self.key = self.gpg.gen_key(input_data)
        return self.key


    def ExportKeys(self):
        ascii_armored_public_keys = self.gpg.export_keys(self.key).replace("\r", "").strip()
        ascii_armored_private_keys = self.gpg.export_keys(self.key, True).replace("\r", "").strip()
        with open(self.fichero, 'w') as f:
            f.write(ascii_armored_public_keys)
            f.write('\n\n')
            f.write(ascii_armored_private_keys)
        f.close()


    def ImportKeys(self, Debug=False):
    #def ImportKeys(self, fichero=None, Debug=False):
        key_data = open(self.fichero).read()
        import_result = self.gpg.import_keys(key_data)
        #print import_result
        if Debug == True:
            print(import_result.summary())
            pprint(import_result.results)


    def EncryptString(self, unencrypted, Debug=False):
        #encrypted_data = gpg.encrypt(unencrypted_string, gpg.list_keys()[0]['keyid'], always_trust=True)        # always_trust=True evita el "here is no assurance this key belongs to the named user"
        encrypted_data = self.gpg.encrypt(unencrypted, self.mail, always_trust=True)        # always_trust=True evita el "here is no assurance this key belongs to the named user"
        self.encrypted_string = str(encrypted_data)
        if Debug == True:
            print('encrypt')
            print('ok: ', self.encrypted_data.ok)
            print('status: ', self.encrypted_data.status)
            print('stderr: ', self.encrypted_data.stderr)
            print('unencrypted_string: ', unencrypted)
            print('encrypted_string: ', self.encrypted_string)

        if encrypted_data.ok == False:
            return self.ErrorEncrypted
        else:
            return self.encrypted_string


    def DecryptString(self, encrypted, Debug=False):
        self.decrypted_data = self.gpg.decrypt(encrypted, passphrase=self.password, always_trust=True)
        #print self.gpg.list_keys()[0]
        if Debug == True:
            print('Decrypt')
            print('ok: ', self.decrypted_data.ok)
            print('status: ', self.decrypted_data.status)
            try:
                print('stderr: ', self.decrypted_data.stderr)  # da error por codificacion
            except:
                pass
            print('decrypted string: ', self.decrypted_data.data)

        if self.decrypted_data.ok == False:
            return self.ErrorDecrypted
        else:
            return self.decrypted_data.data


    def DeletingKeys(self, Debug=False):
        #pprint(gpg.list_keys())
        for i in self.gpg.list_keys():
            if Debug == True:
                print(i['fingerprint'])
            self.gpg.delete_keys(i['fingerprint'], True)
            self.gpg.delete_keys(i['fingerprint'])

    def ListKeys(self):
        for i in self.gpg.list_keys():
            print(i['fingerprint'])

    def CreaFicheroPasswd(self):
        '''crea fichero con la pass encriptada, se usara para desdencriptarlo y conformar que tenemos la pass correcta'''
        f = open(self.SecretFich, 'w')
        texto = self.EncryptString('%s\n%s\n%s'%(self.password, self.mail, self.fichero)).replace("\r", "").strip()
        f.write(texto)
        f.close()



def main():

    passwd ='123456789A1'
    email = 'prueba@gmail.com'
    fich = 'clave.pub'
    texto = 'Who are you? How did you get in my house?'

    hola = Objetito(passwd, email, fich)
    while hola.init(passwd) == 'Fail decrypted':
        print('repetir pass')
        passwd = '123456789A'

    print('Encriptar')
    enc = hola.EncryptString(texto)
    print(enc)

    print('Desencriptar')
    des = hola.DecryptString(enc)
    print(des)

    #hola.ImportKeys()
    #hola.ListKeys()
    #hola.DeletingKeys()

if __name__ == '__main__':
    main()

