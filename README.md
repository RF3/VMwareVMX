## VMwareVMX

VMware VMX Crypto Module for Python

VMware VMX configuration files are encrypted when the virtual machine
is encrypted, too. Making specific changes by hand to these files was
not possible until the user fully decrypted the virtual machine (including
all virtual disks) and, after the modification was done, re-encrypted the
whole virtual machine again. Until this little module was written, which
implements the methods to decrypt and encrypt the configuration data.

### Prerequisites:

The pycryptodome Module is used, so it must be installed like this:

    pip install pycryptodome

### Installation:

Currently there's no installation procedure. All you have to do is to import
the class VMwareVMX with a line like this:

    from vmwarevmx import VMwareVMX

### Available Modules, Commands and Tools

`vmwarevmx.py` implements the VMwareVMX class with methods decrypt and encrypt.

`main.py` is a command line interface to decrypt/encrypt VMware VMX
configuration files and to add and/or remove lines. It also serves as an
example on how to use the VMwareVMX class.

### Examples:

#### List all options (usage):

`./main.py -h`

    Usage:  main.py [-cdefgGhinv] [-a file] [-D name] [-p password] [-r file] [-x value] in_file [out_file]
      -a, --add          decrypt, add line(s) from file and encrypt in_file
      -c, --change       change password
      -d, --decrypt      decrypt in_file (default)
      -D, --displayname  set the displayname for encrypted configuration
      -e, --encrypt      encrypt in_file
      -f, --force        force overwriting out_file
      -g, --guestos      set the guestOS parameter
      -G, --guestinfo    set the guestInfo parameter
      -h, --help         display this message
      -i, --ignore       ignore some errors preventing decryption of a corrupted in_file
      -n, --new          after decrypt, use new parameters for encrypt
      -p, --password     set the password (default: ask for it)
      -r, --remove       decrypt, remove line(s) found in file and encrypt in_file
      -v, --version      print the version string and exit
      -x, --hashrounds   used for the number of hash rounds of the encryption key (default: 10,000)
      -1, --aes          encrypt with old AES-256 algorithm
      -2, --xts          encrypt with new XTS-AES-256 algorithm


#### Decrypt an encrypted VMX config file:

`./main.py old.vmx`

Will ask for the password, decrypts the VMX file old.vmx and writes the
result directly to stdout.

#### Encrypt a regular VMX config file:

`./main.py -e -D "Windows 10" -p test1234 old.vmx new.vmx`

Encrypts the VMX file old.vmx with password `test1234`, adds the display
name "Windows 10" to the config file and writes the result to new.vmx. If
new.vmx already exists, it's not overwritten. Add -f or --force to do so.

#### Decrypt a VMX config file, remove some lines, add lines and encrypt it:

`./main.py -a add.txt -r remove.txt old.vmx new.vmx`

Will ask for the password, decrypts the VMX file old.vmx, removes all the
lines that can be found in remove.txt from the configuration, adds new lines
from add.txt, encrypts the result and writes the configuration to new.vmx,
overwriting an already existing new.vmx file. The keys and parameters used for
encryption are identical to those used in the encrypted file old.vmx, which
means that the encryption.keySafe line is the same in old.vmx and new.vmx. To
use completely new keys and encryption parameters, add -n or --new to the
options.

#### Change the password of a VMX config file:

`./main.py -c old.vmx new.vmx`

This asks for the old password if not already given with the -p option and
then asks twice for the new password. If the new passwords match, the new
password is used for new.vmx.

### Changes

1.0.8:
 - Several strings were transfered into raw strings to avoid 'invalid
   escape sequence' warnings with Python 3.12+. Thanks to clouetb for the
   pull request to fix this.
 - Converting a XTS-AES-256 key into AES-256 is now supported by reusing
   the first 256 bits of the key.
 - Converting an AES-256 key into XTS-AES-256 reuses the existing key by
   adding 256 random bits for the longer 512 bit HMAC key.
 - First release of VMXEditor which is a simple text editor using the
   VMwareVMX module. Now you can open a VMX file, decrypt it, modify it,
   encrypt it again with the same password (or a different one) and save
   it. It even comes with undo/redo and a simple search function, but no
   search-and-replace. Cut, copy and paste is supported, so if you need
   to replace some text, just use a normal editor for that. The whole
   editor should be pretty self-explanatory, I hope, and it should run on
   any operating system supporting python.

1.0.7:
 - Fixed password bug in main.py (-p option didn't work anymore) which was
   introduced with 1.0.6. Thanks to RomanKrylov for noticing me.
 - Added two new options (-1, --aes and -2, --xts) for selecting the
   encryption algorithm. This allows both upgrading and downgrading.
 - Fixed an issue with the VMwareVMX class which forgot to reset the config
   key used to encrypt the configuration when the encryption algorithm was
   changed

1.0.6:
 - Added support for new XTS-AES-256 algorithm introduced with VMware
   Workstation 17.5 and VMware Fusion 13.5 (which is in fact not the real
   XTS-AES algorithm). Thanks to mroi for most of the work.
 - Python 2 support has been removed

1.0.5:
 - New option -G (or --guestinfo) defines the guestInfo parameter.
 - Added public attribute "hash_rounds" with the number of hash rounds used
   for the PBKDF2-HMAC-SHA-1 hashing algorithm.

1.0.4:
 - Fix: Added UTF-8 encoding on file encryption (thanks Knoxberg)
 - Added password change and guestos options:
   - New option -c (or --change) allows one to change the password of a VMX
     file without shutting down and restarting the client machine.
   - New option -g (or --guestos) defines the guestOS parameter.
 - Wrong password during decryption now results in a correct error message.

1.0.3:
 - Fix: Do not add "None" to output file if guestOSdetaileddata is empty
   (thanks jbl42)

1.0.2:
 - Added -i (--ignore) option to be able to open a corrupted .vmx file by
   ignoring some errors happening during decryption. Due to the nature of
   the AES encryption, this only works up to the point where the file got
   corrupted. If it's in the beginning, not much of it will be recovered.
 - Replaced pad() function with Crypto.Util.Padding.pad() and fixed the error
   of padding before encoding. Thanks to mroi.

### Author

Written 2018-2024 by Robert Federle <r.federle3@gmx.de>