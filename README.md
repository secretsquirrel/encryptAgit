# EncryptAGit
Encrypt Your Git Repos

## Authors

- [@secretsquirrel](https://github.com/secretsquirrel)

## Installation

```
pip install encryptAgit
```

## Requirements

* GitPython
* pathlib
* cryptography
* pathspec

## Why??

OK.  I'm already paying for github. It stores files. And has versioning.

I wanted to see how hard it would be to write something from scratch with reasonable security...

..That I wouldn't mind using.

## Threat model

My threat model does not include [Mossad](https://www.usenix.org/system/files/1401_08-12_mickens.pdf).

If someone is on your computer capturing keystrokes, this won't help you.

If someone comes across your gitrepo of encrypted notes and they want to decrypt it,
it's not going to be easy (depends on your password/salt combos - read more...).

## Security

I'm using [fernet](https://cryptography.io/en/latest/fernet/#).

As this is a store of secrets, I can't use a random salt. The user provides it.

To produce the encryption/decryption key, I'm using [Scrypt](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.scrypt.Scrypt) with the user provided salt to make the Key Derivation Function and then the user password is provided to derive the key.

It takes over 1 sec to compute the key on a late model macBook pro (not an M1).

```

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

```

I consider the salt and password to be secrets. Maybe share one of each between friends so only the two of you can open a git repo. I don't know.
Either way, keep them secure.

Encrypted files (tokens - fernet speak) are stored in `encrypted_git.json`.

`encrypted_git.json` format:

```
{
    {
  "full_file_path": {
    "token": "gAAAAAABidd63NQSVrcIRrq9f_g68o4KV13w3SiSXSPI5fxOJNnhlyUUU0eTnzlzkBf_mdRsvZeeh8Sq8YO7yV2GaqB56qNai7t_kkbgJ34OiDLl_N-bXviELx5MSyblp-EbKciUsYH67qIpbnTsbw9KZcQg5uzp9RIlWT9aYaEOruJbEjLSM7_KoWWLKtajFaZ87t9ZY_3nJ7AdSdvOx645Th9VXWxrxV3PQtXaLUYCUYIpfKV3w_9uHCRoA=",
    "filehash": "ee7d78b32d112e88d69fa0739e3217c0d44b193ccbb7579909e1b72e7839f7b5922b5ca80d5f88b3e60aa67dd1ee379b8f74f9dc824b2c6c509471a11d406789"
  },

}

```

`filehash` is the sha512 of the user provided salt + the file contents.


```

    def hash_file(self, file_path):
        return hashlib.sha512(self.salt + open(file_path, 'rb').read()).hexdigest()
```

This helps to prevent searching for a file by hash. 

No keying material is logged or written to disk.

Yes, you can see the repo_path + file name in the encrypted_git.json file. Make sure it is not sensitive info. Reason this is not encrypted is it allows for speed and minimizes decryption cycles to check if a file has been modified. One might say, you could encrypt the full_file_path, like so...


```
{
    1: {"fullPath": "CBAAAAABidd63NQSVrcIRrdsas63635181faske82",
    "token": "gAAAAAABidd63NQSVrcIRrq9f_g68o4KV13w3SiSXSPI5fxOJNnhlyUUU0eTnzlzkBf_mdRsvZeeh8Sq8YO7yV2GaqB56qNai7t_kkbgJ34OiDLl_N-bXviELx5MSyblp-EbKciUsYH67qIpbnTsbw9KZcQg5uzp9RIlWT9aYaEOruJbEjLSM7_KoWWLKtajFaZ87t9ZY_3nJ7AdSdvOx645Th9VXWxrxV3PQtXaLUYCUYIpfKV3w_9uHCRoA=",
    "filehash": "ee7d78b32d112e88d69fa0739e3217c0d44b193ccbb7579909e1b72e7839f7b5922b5ca80d5f88b3e60aa67dd1ee379b8f74f9dc824b2c6c509471a11d406789"
    },

}

```

Whereas, the fullPath is kept decrypted in a python _dict_ pointing to the current filehash. However, the fullPath will allways be different when encrypted and great care will be required to ensure I'm not writing to the encrypted_git.json file multiple times for the same file. To properly find the file to change/update/remove, I'd have to decrypt each fullPath to ensure I had an exact match - then update or drop the file from the json blob. 

Hmm... I'll pass for now.

Keep your filenames non-sensitive!

And use a passphrase for your salt and passwords.

Isn't this like chef [data-bags](https://sec.okta.com/articles/2017/09/hey-chef-whats-the-length-of-your-encrypted-password)?

Not really. [Fernet](https://github.com/fernet/spec/blob/master/Spec.md) is AES-CBC. It's authenticated. The difference is I'm using Scrypt to derive a password vs [pkcs5_keyivgen](https://github.com/chef/chef/blob/61a11902ab814aad3625eb4da7e3345d63ee7c09/lib/chef/encrypted_data_bag_item/decryptor.rb#L110), which is [depreciated](https://www.rubydoc.info/stdlib/openssl/OpenSSL%2FCipher:pkcs5_keyivgen) and is not using a salt. I'm requiring it.


## Usage

This works best in a *fresh git repo*. I haven't implemented git history squashing yet. So any old files will be in your git history.

Maybe I'll implement git history squashing/deletion in a new release. 

1. git clone your notes repo
2. Change directory to it.
3. Execute `encryptAgit.py`

```
encryptAGit
😄 No encrypted_git.json file, seems like first use!
🤗 Welcome to encryptAGit! Let's encrypt your repo!
🤓 Use a passphrase for both salt and password. Remember what you enter!
🧂Enter your salt:
🕵️ Enter your password:
[*] It took 1.185420036315918 seconds to make the key.
[*] Updating moo.txt in encrypted store
[*] Updating hello.txt in encrypted store
[*] Updating pictures/kailua_beach.png in encrypted store
[*] Updating pictures/washington_monument.png in encrypted store
[*] Updating notes/unencryped.txt in encrypted store
[*] Updating notes/testing.txt in encrypted store
[*] Updating notes/1/more.txt in encrypted store
[*] Writing updated encrypted_git.json
[*] Push of encrypted_git.json complete!
```

Now any SAVED changes to files in your git repo will be automatically encrypted and pushed to your git repo.

Here I saved a file in a new directory called `newdir` called `newfile.txt`:
```
[*] Updating newdir/newfile.txt in encrypted store
[*] Writing updated encrypted_git.json
[*] Push of encrypted_git.json complete!
```

Use .gitignore:

```
 cat .gitignore 
*.swp
.DS_Store
README.md
```

Any files you put in .gitignore will not be encrypted, deleted, or saved. You have to git add, commit, and push those yourself.


### Ending the process and changing password

Hit CTRL+C and you will be asked if you want to rotate your salt/password.

Type `n` if you don't, `y` if you do.

```
encryptAgit
😊 Welcome Back to encryptAGit! Let's decrypt your repo!
🧂Enter your salt:
🕵️ Enter your password:
[*] It took 1.0983080863952637 seconds to make the key.
[*] Writing decrypted moo.txt to disk.
[*] Writing decrypted hello.txt to disk.
[*] Writing decrypted pictures/kailua_beach.png to disk.
[*] Writing decrypted pictures/washington_monument.png to disk.
[*] Writing decrypted newdir/newfile.txt to disk.
[*] Writing decrypted notes/unencryped.txt to disk.
[*] Writing decrypted notes/testing.txt to disk.
[*] Writing decrypted notes/1/more.txt to disk.
^C
💭 Do you want to change your salt and password? (y/n):
```
If you want to backout completely without erasing your UNENCRYPTED files type CTRL+C twice in a row.

```
encryptAgit
😊 Welcome Back to encryptAGit! Let's decrypt your repo!
🧂Enter your salt:
🕵️ Enter your password:
[*] It took 1.0983080863952637 seconds to make the key.
[*] Writing decrypted moo.txt to disk.
[*] Writing decrypted hello.txt to disk.
[*] Writing decrypted pictures/kailua_beach.png to disk.
[*] Writing decrypted pictures/washington_monument.png to disk.
[*] Writing decrypted newdir/newfile.txt to disk.
[*] Writing decrypted notes/unencryped.txt to disk.
[*] Writing decrypted notes/testing.txt to disk.
[*] Writing decrypted notes/1/more.txt to disk.
^C
💭 Do you want to change your salt and password? (y/n):^CTraceback (most recent call last):
  File "/Users/pioneer/homebrew/lib/python3.9/site-packages/encryptAgit.py", line 339, in run
    time.sleep(1)
KeyboardInterrupt

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/Users/pioneer/homebrew/bin/encryptAgit", line 8, in <module>
    sys.exit(main())
  File "/Users/pioneer/homebrew/lib/python3.9/site-packages/encryptAgit.py", line 361, in main
    run.run()
  File "/Users/pioneer/homebrew/lib/python3.9/site-packages/encryptAgit.py", line 346, in run
    answer = input('\n💭 Do you want to change your salt and password? (y/n):')
KeyboardInterrupt

```

### Editing files offline

Let's say to do a double CTRL+C and want to edit files offline - feel free to do so! 
Then later start encryptAgit again, if there were no edits to the decrypted files you won't get a warning:

```
encryptAgit
😊 Welcome Back to encryptAGit! Let's decrypt your repo!
🧂Enter your salt:
🕵️ Enter your password:
[*] It took 1.073664903640747 seconds to make the key.
^C  
💭 Do you want to change your salt and password? (y/n):n

[*] Exiting
👋 Removing unencrypted files not in .gitignore
```

If you edit the files without encryptAgit running you'll be asked to overwrite the newer file or not after running encryptAgit again:

```
➜  git-notes git:(main) ✗ vim moo.txt
➜  git-notes git:(main) ✗ encryptAgit              
😊 Welcome Back to encryptAGit! Let's decrypt your repo!
🧂Enter your salt:
🕵️ Enter your password:
[*] It took 1.0608000755310059 seconds to make the key.
[!] moo.txt has changed since last encryption
[!!] Seems the file on disk has changed from the encrypted file, overwrite it from the encrypted version? (y/n):n
[*] Updating moo.txt in encrypted store.
[*] Writing updated encrypted_git.json
[*] Push of encrypted_git.json complete!
```

## Enjoy

Please submit any bug reports to the github repo...


## Considerations 

GitHub repo and file size [limits](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github).


## TODO

* Add git history squashing option on user password change.
* Video on example usage
* Inspection of encrypted files before overwrite of new file or not
