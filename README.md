## VMwareVMX

VMware VMX Crypto Module for Python 2 and 3

VMware VMX configuration files are encrypted when the virtual machine
is encrypted, too. Making specific changes by hand to these files was
not possible until the user fully decrypted the virtual machine (including
all virtual disks) and, after the modification was done, re-encrypted the
whole virtual machine again. Until this little module was written, which
implements the methods to decrypt and encrypt the configuration data.

### Prerequisites:

The pycrypto Module is used, so it must be installed like this:

    pip install pycrypto

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

You can replace `python` with `python3` in the following examples if you want.
Both the module and the command line interface were tested with python 2 and 3.

#### List all options (usage):

`python main.py -h`

    Usage:  main.py [-defhnv] [-a file] [-D name] [-p password] [-r file] in_file [out_file]
      -a, --add          decrypt, add line(s) and encrypt in_file
      -d, --decrypt      decrypt in_file (default)
      -D, --displayname  set the displayname for encrypted configuration
      -e, --encrypt      encrypt in_file
      -f, --force        force overwriting out_file
      -h, --help         display this message
      -n, --new          after decrypt, use new parameters for encrypt
      -p, --password     set the password (default: ask for it)
      -r, --remove       decrypt, remove line(s) and encrypt in_file
      -v, --version      print the version string and exit

#### Decrypt an encrypted VMX config file:

`python main.py old.vmx`

Will ask for the password, decrypts the VMX file old.vmx and writes the
result directly to stdout.

#### Encrypt a regular VMX config file:

`python main.py -e -D "Windows 10" -p test1234 old.vmx new.vmx`

Encrypts the VMX file old.vmx with password `test1234`, adds the display
name "Windows 10" to the config file and writes the result to new.vmx. If
new.vmx already exists, it's not overwritten. Add -f or --force to do so.

#### Decrypt a VMX config file, remove some lines, add lines and encrypt it:

`python main.py -a add.txt -r remove.txt old.vmx > new.vmx`

Will ask for the password, decrypts the VMX file old.vmx, removes all the
lines that can be found in remove.txt from the configuration, adds new lines
from add.txt, encrypts the result and writes the configuration to new.vmx,
overwriting an already existing new.vmx file. The keys and parameters used for
encryption are identical to those used in the encrypted file old.vmx, which
means that the encryption.keySafe line is the same in old.vmx and new.vmx. To
use completely new keys and encryption parameters, add -n or --new to the
options.

### Author

Written 2018 by Robert Federle <r.federle3@gmx.de>
