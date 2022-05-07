#!/usr/bin/env python3

import base64
import datetime
import getpass
import hashlib
import json
import os
import pathspec
import random
import signal
import sys
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from git import Repo
from pathlib import Path


class encryptAGit:

    def __init__(self):
        self.key = b''
        self.salt = b''
        self.decoded_json = {}
        self.do_not_ecrypt = ['.gitignore',
                              'encryptAGit.py',
                              'encrypted_git.json'
                              ]

    def remove_git_history(self):
        pass

    def walk_repo(self):
        '''
        return a list of file paths that are not in .gitignore
        ignore encryptAgit files
        '''
        list_of_files = []
        posix_paths = []
        files_in_path = Path().glob('**/*')

        if Path(".gitignore").exists():
            ignores = Path(".gitignore").read_text().splitlines()
            spec_output = pathspec.PathSpec.from_lines("gitwildmatch", ignores)
            posix_paths = [
                afile for afile in files_in_path if not spec_output.match_file(str(afile))
            ]
        else:
            posix_paths = [
                afile for afile in files_in_path
            ]
        for afile in posix_paths:
            if '.git/' in afile.as_posix():
                continue
            if afile.is_file():
                list_of_files.append(afile.as_posix())

        for no_go in self.do_not_ecrypt:
            try:
                # don't encrypt theses
                list_of_files.remove(no_go)
            except Exception as e:
                pass

        return list_of_files

    def verify_file_salts(self):

        files_to_update = []
        list_of_files = self.walk_repo()
        for afile in list_of_files:
            if afile in self.decoded_json:
                if self.hash_file(afile) == self.decoded_json[afile]['filehash']:
                    continue
                else:
                    print(f'[*] Updating {afile} in encrypted store.')
                    files_to_update.append(afile)
            else:
                print(f'[*] Updating {afile} in encrypted store')
                files_to_update.append(afile)

        return files_to_update

    def remove_deleted_files(self):
        to_remove = []
        list_of_files = self.walk_repo()
        # if the filepath in decode_json files 
        # is not on the file system, it should be removed.

        for afile in self.decoded_json.keys():
            if afile in list_of_files:
                continue
            else:
                to_remove.append(afile)

        for afile in to_remove:
            print(f"[*] Removing deleted {afile} from encrypted_git.json.")
            self.decoded_json.pop(afile)

        if to_remove:
            with open('encrypted_git.json', 'w') as f:
                print('[*] Writing encrypted_git.json after removing file.')
                to_write = json.dumps(self.decoded_json)
                f.write(to_write)

    def verify_single_file_salt(self, file_path):
        '''
        Return False if hashes are different
        '''
        try:
            if self.hash_file(file_path) != self.decoded_json[file_path]['filehash']:
                print(f'[!] {file_path} has changed since last encryption')
                return False
        except Exception as e:
            print(f'Exception {e}')
            return False

        return True

    def hash_file(self, file_path):
        return hashlib.sha512(self.salt + open(file_path, 'rb').read()).hexdigest()

    def encrypt_file_path(self, file_path):
        try:
            f = Fernet(self.key)
            encrypted_file = f.encrypt(file_path)
            return encrypted_path

        except Exception as e:
            print(f'Exception: {e}')
            return False

    def encrypt_file(self, file_path):
        '''
        Use the existing encryption key to encrypt a file
        return encrypted file
        '''
        try:
            f = Fernet(self.key)
            encrypted_file = f.encrypt(open(file_path, 'rb').read()).decode("utf-8")
            return encrypted_file

        except Exception as e:
            print(f'Exception: {e}')
            return False

    def decrypt_file(self, encrypted_file):
        '''
        Use existing encryption key to decrypt file
        '''
        try:
            f = Fernet(self.key)
            decrypted_file = f.decrypt(bytes(encrypted_file, 'utf-8'))
            return decrypted_file

        except Exception as e:
            print('Invalid key! try again!')
            sys.exit(-1)

    def encryption_key(self, user_salt, password):
        try:
            random.seed(user_salt)
            # The salt must be consistent and it is secret.
            # Not md5!
            self.salt = random.randbytes(16)

            kdf = Scrypt(
                salt=self.salt,
                length=32,
                n=2**15,
                r=13,
                p=3,
            )

            start = time.time()
            self.key = base64.urlsafe_b64encode(kdf.derive(bytes(password, 'iso-8859-1')))
            end = time.time()
            print(f"[*] It took {end - start} seconds to make the key.")
            return True

        except Exception as e:
            print(f'[!!] Check your salt and or password: {e}')
            return False

    def write_file(self, file_path):
        '''
        got to handle cloned repos
        '''
        if os.path.dirname(file_path):
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

        return open(file_path, 'wb')

    def unload_json(self):
        '''
        Return True if files were updates since last save
        '''
        updates = False

        for afile, values in self.decoded_json.items():
            # check if file on disk
            # if not on disk, decrypt it
            if not os.path.isfile(afile):
                decrypted_file = self.decrypt_file(values['token'])
                if decrypted_file:
                    print(f'[*] Writing decrypted {afile} to disk.')
                    with self.write_file(afile) as f:
                        f.write(decrypted_file)
            # else if the hash doesn't check out, update it.
            elif not self.verify_single_file_salt(afile):
                answer = ''
                while answer.lower() not in ['y', 'n']:
                    answer = input('[!!] Seems the file on disk has changed from the encrypted file, overwrite it from the encrypted version? (y/n):')
                    if answer.lower() == 'n':
                        updates = True
                    else:
                        decrypted_file = self.decrypt_file(values['token'])
                        if decrypted_file:
                            print(f'[*] Writing decrypted {afile} to disk.')
                            with self.write_file(afile) as f:
                                f.write(decrypted_file)

        return updates

    def git_commit(self):
        '''
        This will attempt to commit and push encrypted_git.json... that's it
        '''
        try:
            repo = Repo()
            changed_files = [item.a_path for item in repo.index.diff(None)]
            if 'encrypted_git.json' in changed_files:
                repo.git.add('encrypted_git.json')
                repo.index.commit(datetime.datetime.now().isoformat())
                origin = repo.remote(name='origin')
                origin.push()
                print('[*] Push of encrypted_git.json complete!')
        except Exception as e:
            print(f'[!!] Do you have a valid .git directory here?')

    def update_json(self):
        '''
        Walk file system while checking gitirgnores and update
        self.decoded_json
        '''

        files_to_update = []
        files_to_update = self.verify_file_salts()

        if files_to_update:
            for afile in files_to_update:
                file_hash = self.hash_file(afile)
                encrypted_file = self.encrypt_file(afile)

                self.decoded_json[afile] = {'token': encrypted_file,
                                            'filehash': file_hash,
                                           }

            with open('encrypted_git.json', 'w') as f:
                print('[*] Writing updated encrypted_git.json')
                to_write = json.dumps(self.decoded_json)
                f.write(to_write)

    def check_json(self):
        '''
        Some checks to ensure proper formatted json
        '''
        try:
            encrypted_json = open('encrypted_git.json', 'r').read()
        except Exception as e:
            print('😄 No encrypted_git.json file, seems like first use!')
            return False

        try:
            self.decoded_json = json.loads(encrypted_json)
            for key0, values in self.decoded_json.items():
                for key1, value in values.items():
                    if key1 not in ['token', 'filehash']:
                        print(f'😖 Malformed encrypted_git.json @ file: {key0}')
                        self.decoded_json = {}
                        return False

        except Exception as e:
            print(f'[!] Exception: {e}')
            self.decoded_json = {}
            return False

        return True

    def clean_up(self):
        print('👋 Removing unencrypted files not in .gitignore')
        list_of_files = self.walk_repo()
        for afile in list_of_files:
            os.remove(afile)
        self.key = b''
        self.salt = b''

    def set_keying_material(self):
        user_salt = getpass.getpass(prompt='🧂Enter your salt:',
                            stream=None)
        password = getpass.getpass(prompt='🕵️ Enter your password:',
                           stream=None)

        if not self.encryption_key(user_salt, password):
            print('🤔 hmmm, exiting...')
            sys.exit(-1)
        password = ''
        user_salt = ''

    def run(self):
        '''
        1. Check for encrypted_git.json, if not make one
        2. If one exists, decrypt it
        3. Loop adding and removing files as hey are saved or deleted.
        4. Commit changes
        4. Ask for password change on exit.
        5. Remove files not in .gitignore

        '''

        if not self.check_json():
            print("🤗 Welcome to encryptAGit! Let's encrypt your repo!")
            print("🤓 Use a passphrase for both salt and password. Remember what you enter!")
            self.set_keying_material()
            self.update_json()
            # create encrypted_git.json

        else:
            print("😊 Welcome Back to encryptAGit! Let's decrypt your repo!")
            self.set_keying_material()
            files_to_update = self.unload_json()
            if files_to_update:
                self.update_json()

        try:
            while True:
                self.update_json()
                time.sleep(1)
                self.remove_deleted_files()
                self.git_commit()

        except KeyboardInterrupt:
            answer = ''
            while answer.lower() not in ['y','n']:
                answer = input('\n💭 Do you want to change your salt and password? (y/n):')

            if answer.lower() == 'y':
                self.set_keying_material()
                os.remove('encrypted_git.json')

            print('\n[*] Exiting')
            self.update_json()
            self.clean_up()
            self.git_commit()
            sys.exit(0)


def main():
    run = encryptAGit()
    run.run()


if __name__ == "__main__":
    run = encryptAGit()
    run.run()