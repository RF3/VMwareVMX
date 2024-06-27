#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  main.py
#

version = '1.0.7'

import getopt
from getpass import getpass
import os
import re
import sys
from vmwarevmx import VMwareVMX

def getpassword(text):
    try:
        while True:
            password = getpass(text)
            if password != '':
                return password
            sys.stderr.write('Error: Empty password is not allowed. Try again.\n')
    except (EOFError, KeyboardInterrupt):
        sys.exit('\nError: Need a password')

def initgetopt(name, options, files=''):
    maxlen     =       max(len(long)
                           for (short, long, arg, text) in options)
    optlong    =      list(long + '=' if arg else long
                           for (short, long, arg, text) in options)
    optshort   =   ''.join(short + ':' if arg else short
                           for (short, long, arg, text) in options)
    withoutarg =   ''.join(short
                           for (short, long, arg, text) in options if not arg)
    witharg    =   ''.join('[-{s} {a}] '.format(s=short, a=arg)
                           for (short, long, arg, text) in options if arg)
    usage      = '\n'.join('  -{s}, --{l:{len}s}  {t}' \
                           .format(s=short, l=long, t=text, len=maxlen)
                           for (short, long, arg, text) in options)
    usage      = 'Usage:  {n} [-{wo}] {w}{f}\n{u}' \
                 .format(n=name, wo=withoutarg, w=witharg, f=files, u=usage)
    return optshort, optlong, usage

def main(argv):
    addfilename = None
    changepassword = False
    cipher = None
    decrypt = False
    displayname = None
    encrypt = False
    force = False
    guestOSdetaileddata = None
    guestInfodetaileddata = None
    hash_rounds = None
    ignore = False
    new = False
    outfilename = None
    password = None
    removefilename = None
    options = [
               ('a', 'add',         'file',
                'add line(s) from file'),
               ('c', 'change',      '',
                'change password'),
               ('d', 'decrypt',     '',
                'decrypt in_file (default)'),
               ('D', 'displayname', 'name',
                'set the displayname parameter'),
               ('e', 'encrypt',     '',
                'encrypt in_file'),
               ('f', 'force',       '',
                'force overwriting out_file'),
               ('g', 'guestos',     '',
                'set the guestOS parameter'),
               ('G', 'guestinfo',   '',
                'set the guestInfo parameter'),
               ('h', 'help',        '',
                'display this message'),
               ('i', 'ignore',      '',
                'ignore some errors preventing decryption of a corrupted in_file'),
               ('n', 'new',         '',
                'after decrypt, use new parameters for encryption'),
               ('p', 'password',    'password',
                'set the password (default: ask for it)'),
               ('r', 'remove',      'file',
                'remove line(s) found in file'),
               ('v', 'version',     '',
                'print the version string and exit'),
               ('x', 'hashrounds',  'value',
                'used for the number of hash rounds of the password (default: 10,000)'),
               ('1', 'aes',         '',
                'encrypt with old AES-256 algorithm'),
               ('2', 'xts',         '',
                'encrypt with new XTS-AES-256 algorithm'),
              ]

    (optshort, optlong, usage) = initgetopt(os.path.basename(argv[0]),
                                            options,
                                            'in_file [out_file]')
    try:
        (opts, args) = getopt.getopt(argv[1:], optshort, optlong)
    except getopt.GetoptError as err:
        sys.stderr.write('Error: ' + str(err) + '\n')
        sys.exit(usage)

    for (opt, arg) in opts:
        if opt in ('-a', '--add'):
            addfilename = arg
        elif opt in ('-c', '--change'):
            changepassword, decrypt, encrypt = True, True, True
        elif opt in ('-d', '--decrypt'):
            decrypt = True
        elif opt in ('-D', '--displayname'):
            displayname = arg
        elif opt in ('-e', '--encrypt'):
            encrypt = True
        elif opt in ('-f', '--force'):
            force = True
        elif opt in ('-g', '--guestos'):
            guestOSdetaileddata = arg
        elif opt in ('-G', '--guestinfo'):
            guestInfodetaileddata = arg
        elif opt in ('-h', '--help'):
            sys.stderr.write(usage + '\n')
            sys.exit(0)
        elif opt in ('-i', '--ignore'):
            ignore = True
        elif opt in ('-n', '--new'):
            new = True
        elif opt in ('-p', '--password'):
            password = arg
        elif opt in ('-r', '--remove'):
            removefilename = arg
        elif opt in ('-v', '--version'):
            print('VMwareVMX Crypto Tool v{v}\n' \
                  'Copyright (C) 2018-2024 Robert Federle'.format(v=version))
            sys.exit(0)
        elif opt in ('-x', '--hashrounds'):
            try:
                hash_rounds = int(arg)
                if hash_rounds <= 0:
                    sys.exit('Error: hashrounds value must be a positive non-zero number')
            except ValueError:
                sys.exit('Error: hashrounds value must be a positive non-zero number')
        elif opt in ('-1', '--aes'):
            cipher = "AES-256"
        elif opt in ('-2', '--xts'):
            cipher = "XTS-AES-256"
        else:
            sys.exit(usage)

    if len(args) == 0:
        sys.exit('Error: No input file given')

    # Read the configuration file
    infilename = args[0]
    if len(args) == 2:
        outfilename = args[1]
        if os.path.abspath(infilename) == os.path.abspath(outfilename):
            sys.exit('Error: Input and output files are the same')
    elif len(args) > 2:
        sys.exit('Error: More arguments after filenames found')

    try:
        lines = open(infilename, "r").read().split('\n')
    except (OSError, IOError) as err:
        sys.exit('Error: Cannot read from file ' + infilename + ": " +  str(err))

    # Analyze the file and replace all header entries with the ones from the command-line
    encoding = 'utf-8'
    headerlist = []
    configlist = []
    keysafe, data = None, None
    counter = 0
    for line in lines:
        if line == '':
            continue
        match = re.match(r'^.encoding *= *"(.+)"$', line)
        if match:
            encoding = match.group(1).lower()
            headerlist.append(line)
            continue
        if re.match(r'^display[Nn]ame *= *"(.+)"$', line):
            if displayname:
                # Replace with new parameter
               line = 'displayName = "{}"'.format(displayname)
            headerlist.append(line)
            continue
        if re.match(r'^guestOS.detailed.data *= *"(.+)"$', line):
            if guestOSdetaileddata:
                # Replace with new parameter
                line = 'guestOS.detailed.data = "{}"'.format(guestOSdetaileddata)
            headerlist.append(line)
            continue
        if re.match(r'^guestInfo.detailed.data *= *"(.+)"$', line):
            if guestInfodetaileddata:
                # Replace with new parameter
                line = 'guestInfo.detailed.data = "{}"'.format(guestInfodetaileddata)
            headerlist.append(line)
            continue
        if re.match(r'^encryption.keySafe *= *"vmware:key/list/\(pair/\(phrase/(.+)pass2key(.+)\)\)"$', line):
            keysafe = line
            continue
        if re.match(r'^encryption.data *= *"(.+)"$', line):
            data = line
            continue
        configlist.append(line)

    # If the file is encrypted, enforce decryption, otherwise nothing useful can be done
    if (decrypt == False) and (keysafe and data):
        decrypt = True
        # If we add or remove lines from an encrypted file or a specific cipher is selected,
        # make sure the result is also encrypted
        if addfilename or removefilename or cipher:
            encrypt = True

    # Create VMwareVMX object
    vmx = VMwareVMX.new()

    # Decrypt the configuration
    if decrypt:
        if keysafe is None or data is None:
            sys.exit('Error: File ' + infilename + ' is not a valid VMX file or already decrypted')

        if password is None:
            password = getpassword('Password:')

        try:
            config = vmx.decrypt(password, keysafe, data, encoding, ignore)
        except ValueError as err:
            sys.exit('Error: ' + str(err))

        if config is None:
            sys.exit('Error: Password is invalid')
        else:
            keysafe, data = None, None
            configlist = config.split('\n')

    # Remove lines from the configuration
    if removefilename:
        try:
            removelist = open(removefilename, "r", encoding=encoding).read().split('\n')
        except (OSError, IOError) as err:
            sys.exit('Error: Cannot read from file ' + removefilename + ": " +  str(err))
        configlist = [x for x in configlist if x not in removelist]

    # Add lines to the configuration
    if addfilename:
        try:
            addlist = open(addfilename, "r", encoding=encoding).read().split('\n')
        except (OSError, IOError) as err:
            sys.exit('Error: Cannot read from file ' + addfilename + ": " +  str(err))
        configlist.extend(addlist)

    # Use new parameters (hash_rounds, identifier, salt, AES IV, AES keys) for encryption?
    if new:
        vmx.reinit()

    # Encrypt the configuration
    if encrypt:
        if keysafe and data:
            sys.exit('Error: VMX file is already encrypted')

        # If no password is given and password should be changed, ask for password
        if changepassword or password is None:
            password = getpassword('New Password:')
            password2 = getpassword('New Password (again):')
            if password != password2:
                sys.exit("Error: Passwords don't match")

        # Change the cipher algorithm if requested
        if cipher:
            vmx.cipher = cipher

        # Create configuration for encryption
        config = '\n'.join(configlist)

        try:
            (keysafe, data) = vmx.encrypt(password, config, hash_rounds)
        except ValueError as err:
            sys.exit('Error: '+ str(err))

    # Create configuration
    config = '\n'.join(headerlist) + '\n'
    if keysafe and data:
        config = config + keysafe + '\n' + data + '\n'
    else:
        config = config + '\n'.join(configlist) + '\n'

    # Write to the configuration file or to stdout
    if outfilename is None or outfilename == '-':
        sys.stdout.write(config)
    else:
        if force is False and os.path.isfile(outfilename):
            sys.exit('Error: File ' + outfilename + ' exists; ' \
                     'use --force to overwrite')
        try:
            open(outfilename, "w", encoding=encoding).write(config)
        except (OSError, IOError) as err:
            sys.exit('Error: Cannot write to file ' + outfilename + ": " +  str(err))

    sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)

# vim:set ts=4 sw=4 sts=4 expandtab:
