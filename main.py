#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  main.py
#

version = '1.0.5'

import getopt
from getpass import getpass
import os
import re
import sys
from vmwarevmx import VMwareVMX

def getpassword(text):
    try:
        password = getpass(text)
    except (EOFError, KeyboardInterrupt):
        sys.exit('\nError: Need a password')
    return password

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
    add = False
    addfilename = None
    changepassword = False
    config = None
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
    remove = False
    removefilename = None
    options = [
               ('a', 'add',         'file',
                'decrypt, add line(s) from file and encrypt in_file'),
               ('c', 'change',      '',
                'change password'),
               ('d', 'decrypt',     '',
                'decrypt in_file (default)'),
               ('D', 'displayname', 'name',
                'set the displayname for encrypted configuration'),
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
                'after decrypt, use new parameters for encrypt'),
               ('p', 'password',    'password',
                'set the password (default: ask for it)'),
               ('r', 'remove',      'file',
                'decrypt, remove line(s) found in file and encrypt in_file'),
               ('v', 'version',     '',
                'print the version string and exit'),
               ('x', 'hashrounds',  'value',
                'used for the number of hash rounds of the encryption key (default: 10,000)'),
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
            add, decrypt, encrypt = True, True, True
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
            remove, decrypt, encrypt = True, True, True
        elif opt in ('-v', '--version'):
            print('VMwareVMX Crypto Tool v{v}\n' \
                  'Copyright (C) 2018-2023 Robert Federle'.format(v=version))
            sys.exit(0)
        elif opt in ('-x', '--hashrounds'):
            try:
                hash_rounds = int(arg)
                if hash_rounds <= 0:
                    sys.exit('Error: hashrounds value must be a positive non-zero number')
            except ValueError:
                sys.exit('Error: hashrounds value must be a positive non-zero number')
        else:
            sys.exit(usage)

    if len(args) == 0:
        sys.exit('Error: No input file given')

    if decrypt is False and encrypt is False:
        decrypt = True

    # Read the configuration file
    infilename = args[0]
    if len(args) == 2:
        outfilename = args[1]
        if os.path.abspath(infilename) == os.path.abspath(outfilename):
            sys.exit('Error: Input and output files are the same')
    elif len(args) > 2:
        sys.exit('Error: More arguments after filenames found')

    if password is None:
        password = getpassword('Password:')

    if password == '':
        sys.exit('Error: Empty password not allowed')

    try:
        with open(infilename, "r") as infile:
            lines = infile.readlines()
    except (OSError, IOError) as err:
        sys.exit('Error: Cannot read from file ' + infilename + ": " +  str(err))

    VMX = VMwareVMX.new()

    # Decrypt the configuration
    if decrypt:
        keysafe = None
        data = None

        for line in lines:
            if displayname is None:
                match = re.match('display[Nn]ame *= *"(.+)"\n', line)
                if match:
                    displayname = match.group(1)
            if guestOSdetaileddata is None:
                match = re.match('guestOS.detailed.data *= *"(.+)"\n', line)
                if match:
                    guestOSdetaileddata = match.group(1)
            if guestInfodetaileddata is None:
                match = re.match('guestInfo.detailed.data *= *"(.+)"\n', line)
                if match:
                    guestInfodetaileddata = match.group(1)
            if 'encryption.keySafe' in line:
                keysafe = line
            if 'encryption.data' in line:
                data = line
            elif '.encoding' in line:
                match = re.match('.encoding *= *"(.+)"\n', line)
                if match:
                    encoding = match.group(1).lower()

        if displayname is None or keysafe is None or data is None:
            sys.exit('Error: File ' + infilename + ' is not a valid VMX file')

        try:
            config = VMX.decrypt(password, keysafe, data, encoding, ignore)
        except ValueError as err:
            sys.exit('Error: ' + str(err))

        if config is None:
            sys.exit('Error: Password is invalid')

    # Remove lines from the configuration
    if remove:
        try:
            removelist = open(removefilename, "r").read().split('\n')
        except (OSError, IOError) as err:
            sys.exit('Error: Cannot read from file ' + removefilename + ": " +  str(err))

        lines = config.split('\n')
        config = '\n'.join([x for x in lines if x not in removelist]) + '\n'

    # Add lines to the configuration
    if add:
        try:
            addconfig = open(addfilename, "r", encoding="utf8").read()
        except (OSError, IOError) as err:
            sys.exit('Error: Cannot read from file ' + addfilename + ": " +  str(err))

        config += addconfig

    # Use new parameters (hash_rounds, identifier, salt, AES IV, AES keys) for encryption?
    if new:
        VMX.reinit()

    # Encrypt the configuration
    if encrypt:
        if displayname is None:
            sys.exit('Error: Displayname is missing')

        if guestOSdetaileddata is None:
            guestOSdetaileddata = ""
        else:
            guestOSdetaileddata = 'guestOS.detailed.data = "{g}"\n' \
                                  .format(g=guestOSdetaileddata)

        if guestInfodetaileddata is None:
            guestInfodetaileddata = ""
        else:
            guestInfodetaileddata = 'guestInfo.detailed.data = "{i}"\n' \
                                    .format(i=guestInfodetaileddata)

        if changepassword:
            password = getpassword('New Password:')
            if password == '':
                sys.exit('Error: Empty password is not allowed')
            password2 = getpassword('New Password (again):')
            if password != password2:
                sys.exit("Error: Passwords don't match")

        if config is None:
            config = ''.join(lines)

        # Reuse old value for hash_rounds if not overriden 
        if hash_rounds is None:
            hash_rounds = VMX.hash_rounds

        try:
            (keysafe, data) = VMX.encrypt(password, config, hash_rounds)
        except ValueError as err:
            sys.exit('Error: '+ str(err))

        config = '.encoding = "UTF-8"\ndisplayName = "{n}"\n{g}{i}{k}\n{d}\n' \
                 .format(n=displayname, g=guestOSdetaileddata, i=guestInfodetaileddata, k=keysafe, d=data)

    # Write to the configuration file or to stdout
    if outfilename is None or outfilename == '-':
        sys.stdout.write(config)
    else:
        if force is False and os.path.isfile(outfilename):
            sys.exit('Error: File ' + outfilename + ' exists; ' \
                     'use --force to overwrite')
        try:
            open(outfilename, "w").write(config)
        except (OSError, IOError) as err:
            sys.exit('Error: Cannot write to file ' + outfilename + ": " +  str(err))

    sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)

# vim:set ts=4 sw=4 sts=4 expandtab:
