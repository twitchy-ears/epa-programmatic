# epa-programmatic
Querying Emacs epa / EasyPG Assistant GnuPG library of keys programmatically

This was made because I was messing around with epa/EasyPG
Assistant for encrypting some config files and I wanted some easy
ways to lookup the GPG keys on that machine to make my config a
little more portable between my machines, so I wanted something
that would let me put in a name, or an email address or some other
criteria, get those keys, and then use those key-ids with plstore
and similar.

I initially parsed the epa buffered output (those functions are
commented out later down the file) but dug into them a little
afterwards and switched to querying the epg library directly

For example very very simply and probably dangerously: 

```
(use-package epa-programmatic)

;; Ensure that plstore is encrypted to yourself
(use-package plstore
  :after epa-programmatic
  :config 
  (let ((ukeys (epa-programmatic-ultimate-trusted-keyids)))
    (if (length> ukeys 0)
        (dolist (curr ukeys)
          (add-to-list 'plstore-encrypt-to curr)))))
```

If you wanted to look for all keys related to `@foo.com` emails (yes,
beware regexps) with both ultimate or full trust, and retrieve the
key-id, user-id-string (usually "Firstname Surname
<email@domain.tld>"), and the trust character (u(ltimate), f(ull), o
(unknown), q (undefined), n(ever), m(arginal), - (none)) then
something like this:


```
(epa-programmatic-get-data-filtered
           '((:user-id-string "@foo.com")
             (:trust-char "[uf]"))
           nil
           '(:key-id :user-id-string :trust-char))"
```

What functions are available?

* `epa-programmatic-get-data`: Retrieves all the data from either public or secret keyrings, has some basic filtering from the functions it calls.
* `epa-programmatic-get-data-filtered`: Retrieves flexible fields from keys based on flexible filtering
* `epa-programmatic-ultimate-trusted-keyids`: Retrieves a list of key-ids of all keys with ultimate trust and validity from the secret keyring.
* `epa-programmatic-buffer-get-keys`: Parses the epa output buffer to get its data, deprecated.
* `epa-programmatic-buffer-get-keys-filtered`: Allows some filtering of data and results from epa buffers, deprecated.

# BUGS

Almost certainly

# Is there a better way of doing this?

Almost certainly, take a look inside `epa-programmatic-get-data` and you'll see what we're parsing, you can probably build something more specific from the guts of `epg-*`