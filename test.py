# -*- coding: utf-8 -*-
import gnupg
from pprint import pprint

#http://www.saltycrane.com/blog/2011/10/python-gnupg-gpg-example/

gpg = gnupg.GPG(gnupghome='Z:/ProgramasPropios/python/password-manager/tmp/', verbose=False)
#gpg.encoding = 'utf-8'

#hacer un objeto
def GenerateKeys(password=None, mail=None):
	input_data = gpg.gen_key_input(key_type="RSA", key_length=2048, name_real='test', name_email=mail, passphrase=password)
	key = gpg.gen_key(input_data)
	return key


def ExportKeys(key, fichero):
	ascii_armored_public_keys = gpg.export_keys(key).replace("\r", "").strip()
	ascii_armored_private_keys = gpg.export_keys(key, True).replace("\r", "").strip()
	with open(fichero, 'w') as f:
		f.write(ascii_armored_public_keys)
		f.write('\n\n')
		f.write(ascii_armored_private_keys)
	f.close()


def ImportKeys(fichero=None, Debug=False):
	key_data = open(fichero).read()
	import_result = gpg.import_keys(key_data)
	if Debug == True:
		print import_result.summary()
		pprint(import_result.results)


def EncryptString(unencrypted_string=None, mail=None, Debug=False):
	#encrypted_data = gpg.encrypt(unencrypted_string, gpg.list_keys()[0]['keyid'], always_trust=True)        # always_trust=True evita el "here is no assurance this key belongs to the named user"
	encrypted_data = gpg.encrypt(unencrypted_string, mail, always_trust=True)        # always_trust=True evita el "here is no assurance this key belongs to the named user"
	encrypted_string = str(encrypted_data)
	if Debug == True:
		print 'encrypt'
		print 'ok: ', encrypted_data.ok
		print 'status: ', encrypted_data.status
		print 'stderr: ', encrypted_data.stderr
		print 'unencrypted_string: ', unencrypted_string
		print 'encrypted_string: ', encrypted_string

	if encrypted_data.ok == False:
		return 'Fail encrypted'
	else:
		return encrypted_string


def DecryptString(encrypted_string=None, password=None, Debug=False):
	decrypted_data = gpg.decrypt(encrypted_string, passphrase=password)
	if Debug == True:
		print 'Decrypt'
		print 'ok: ', decrypted_data.ok
		print 'status: ', decrypted_data.status
		try:
			print 'stderr: ', decrypted_data.stderr  # da error por codificacion
		except:
			pass
		print 'decrypted string: ', decrypted_data.data

	if decrypted_data.ok == False:
		return 'Fail decrypted'
	else:
		return decrypted_data.data


def DeletingKeys(Debug=False):
	#pprint(gpg.list_keys())
	for i in gpg.list_keys():
		if Debug == True:
			print i['fingerprint']
		gpg.delete_keys(i['fingerprint'], True)
		gpg.delete_keys(i['fingerprint'])

def CreaFicheroPasswd(password, email, fichero='secret.pub'):
	f = open(fichero, 'w')
	f.write(EncryptString(unencrypted_string=password).replace("\r", "", mail=email).strip())  # ESTO NO PYEDE FUNCIONAR BIEN, REVISAR LOS PARENTESIS
	f.close()


def PrimeraVez(password, email, fichero, texto):
	key = GenerateKeys(password=password, email=email)
	CreaFicheroPasswd(password)
	ExportKeys(key, fichero)
	print DecryptString(encrypted_string=EncryptString(unencrypted_string=texto, mail=email), password=password)
	DeletingKeys()


def InicioSegundaVez(password, email, fichero):
	ImportKeys(fichero)
	key = gpg.list_keys()[0]
	passwd = DecryptString(encrypted_string=open('secret.pub', 'r').read(), password=password)
	DeletingKeys()
	return passwd


def SegundaVez(password, email, fichero, texto):
	ImportKeys(fichero)
	key = gpg.list_keys()[0]
	print  gpg.list_keys()
	print DecryptString(encrypted_string=EncryptString(unencrypted_string=texto, mail=email), password=password)
	DeletingKeys()



def main():
	passwd ='123456789A'
	email = 'prueba@gmail.com'
	fich = 'clave.pub'
	texto = 'Who are you? How did you get in my house?'

	#PrimeraVez(passwd, email, fich, texto)

	print InicioSegundaVez(passwd, email, fich)

	SegundaVez(password=InicioSegundaVez(passwd, email, fich), email=email, fichero=fich, texto=texto)

main()

