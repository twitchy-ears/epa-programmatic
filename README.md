# epa-programmatic
Querying Emacs epa / EasyPG Assistant GnuPG library of keys programmatically

This was made because I was messing around with epa/EasyPG
Assistant for encrypting some config files and I wanted some easy
ways to lookup the GPG keys on that machine to make my config a
little more portable between my machines, so I wanted something
that would let me put in a name, or an email address or some other
criteria, get those keys, and then use those key-ids with plstore
and similar.

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

If you wanted to get the key-id and user data from every key (not just secret keys) that had @foo.com in its user data (be that in an email or a name, beware regexps, etc.etc.) then something like this:

```
;; Filter on data field 2 (user-data), for the regexp given,
;; don't limit ourselves to secret keys, and return fields 1 and 2
;; (keyid, user-data) 
(epa-programmatic-get-keys-filtered 2 ".*@foo\.com.*" nil '(1 2))
```

# BUGS

Almost certainly

# Is there a better way of doing this?

Almost certainly but messing around inside epa feels like more work than a quick buffer parser.