;;; epa-programmatic.el --- Querying Emacs epg / epa / EasyPG Assistant GnuPG library of keys programmatically -*- lexical-binding: t -*-

;; Copyright 2025 - Twitchy Ears

;; Author: Twitchy Ears https://github.com/twitchy-ears/
;; URL: https://github.com/twitchy-ears/epa-programmatic
;; Version: 0.1
;; Package-Requires ((emacs "30.1"))
;; Keywords: PGP, GnuPG

;; This file is not part of GNU Emacs.

;; This program is free software; you can redistribute it and/or
;; modify it under the terms of the GNU General Public License as
;; published by the Free Software Foundation; either version 3, or
;; (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;; General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License
;; along with this program; see the file COPYING.  If not, write to
;; the Free Software Foundation, Inc., 51 Franklin Street, Fifth
;; Floor, Boston, MA 02110-1301, USA.

;;; History
;;
;; 2025-05-13 - initial version
;; 2025-05-14 - changed functions around, now a thin shim over EPG

;;; Commentary:

;; This was made because I was messing around with epa/EasyPG
;; Assistant for encrypting some config files and I wanted some easy
;; ways to lookup the GPG keys on that machine to make my config a
;; little more portable between my machines, so I wanted something
;; that would let me put in a name, or an email address or some other
;; criteria, get those keys, and then use those key-ids with plstore
;; and similar.
;;
;; I initially parsed the epa buffered output (those functions are
;; commented out later down the file) but dug into them a little
;; afterwards and switched to querying the epg library directly.
;;
;; The original epa buffer querying functions are still available if wanted.
;; 
;; (use-package epa-programmatic)
;; 
;; ;; Ensure that plstore is encrypted to yourself
;; (use-package plstore
;;   :after epa-programmatic
;;   :config 
;;   (let ((ukeys (epa-programmatic-ultimate-trusted-keyids)))
;;     (if (length> ukeys 0)
;;         (dolist (curr ukeys)
;;           (add-to-list 'plstore-encrypt-to curr)))))
;;
;; Example, getting all keys related to @foo.com with ultimate or full
;; trust in the keyring, and retrieving a list of key-id,
;; user-id-string, and the trust character (u, f, m, o, q, -, etc)
;;
;; (epa-programmatic-get-data-filtered
;;           '((:user-id-string "@foo.com")
;;             (:trust-char "[uf]"))
;;           nil
;;           '(:key-id :user-id-string :trust-char))"

(require 'epa)
(require 'epg)

(defun epa-programmatic-get-data (&optional filter secret)
  "Processes through the GnuPG/epa/epg data directly, returns a list of
alists in the form of: 

( ( (:validity-string . validity-string)
    (:validity-char . validity-char)
    (:user-id-string . user-id-string)
    (:owner-trust . owner-trust)
    (:trust-char . trust-char)
    (:key-id . key-id) )

  ( (:validity-string . validity-string)
    (:validity-char . validity-char)
    (:user-id-string . user-id-string)
    (:owner-trust . owner-trust)
    (:trust-char . trust-char)
    (:key-id . key-id) )

  ... )

These values can then be accessed with something like:

(dolist (entry (epa-programmatic-get-data))
  (message \"key-id '%s'\" (alist-get :key-id entry)))

Where validity-string and validity-char are both drawn from
`epg-key-validity-alist' (but are given as strings rather than a
(char . symbol) pairing for ease of looking at later)

The user-id-string is from the key and is often
\"Firstname Surname <email@domain.tld>\" formatted

The owner-trust string is a description of how trusted the key is as per
GnuPG standards so should be one of: ultimate, full, unknown, undefined,
never, marginal.

The trust-char is owner-trust looked up from epg-key-validity-alist but as
a string, likely to be u(ltimate), f(ull), o (unknown), q (undefined),
n(ever), m(arginal), - (none).

The key-id is the long ID of the subkey that has the 'sign and 'certify
qualities and is hence likely the public key you're interested in.

If there is a filter then only keys matching it (I think in user-id-string)
will be returned, if secret is t then only the secret keyring will be searched"

  (interactive)
  (let* ((context (epg-make-context epa-protocol))
         (data (epg-list-keys context filter secret))
         (acc '()))
    
    ;; Run through all the keys found
    (dolist (dat data)
      ;; (message "DAT '%s'" dat)
      (let* ((uid-list (epg-key-user-id-list dat))
             (validity (epg-user-id-validity (car uid-list)))
             (subkey-list (epg-key-sub-key-list dat))
             (ret '()))
        
        ;; Process through the associated UIDs
        ;; (dolist (uid uid-list)
        ;; (message "uid validity '%s' user '%s'"
        ;;          (epg-user-id-validity uid)
        ;;          (epg-user-id-string uid))
        ;; (push (epg-user-id-validity uid) ret)
        ;; (push (epg-user-id-string uid) ret))

        ;; Just grab the first identity
        (push (cons :validity (symbol-name validity)) ret)
        (push (cons :validity-char
                    (char-to-string
                     (car (rassq validity
                                 epg-key-validity-alist))))
              ret)
        (push (cons :user-id-string (epg-user-id-string (car uid-list))) ret)
        
        ;; Owner trust
        ;; (message "owner-trust '%s'" (epg-key-owner-trust dat))
        (push (cons :owner-trust (symbol-name (epg-key-owner-trust dat))) ret)
        (push (cons :trust-char
                    (char-to-string
                     (car (rassq (epg-key-owner-trust dat)
                                 epg-key-validity-alist))))
              ret)
        
        ;; Pick the most interesting subkey
        (dolist (skey subkey-list)
          ;; (message "sub-key-id '%s' -> '%s'" (epg-sub-key-capability skey) (epg-sub-key-id skey))
          (if (and (member 'sign (epg-sub-key-capability skey))
                   (member 'certify (epg-sub-key-capability skey)))
              (push (cons :key-id (epg-sub-key-id skey)) ret)))
        
        (push (reverse ret) acc)))

    (when (called-interactively-p 'any)
      (message "%s" acc))
    
    acc))




(defun epa-programmatic-get-data-filtered (filter &optional secret return-fields)

  "Uses the `epa-programmatic-get-data' function but allows ease of filtering
its output for specific values, and also filtering what values are returned.

The `filter' is a list of lists, the car of which should be a :keyword
and the cdr of which should be a regexp to test against this.  If all
of these match then the key is returned.  If a single one fails then the
whole entry is rejected.

`field' should be a :keyword from the data structure of
epa-programmatic-get-data and `filter' is a regex that will be tested
against this field.  If both are nil then all results will be returned.

The optional argument `secret' should be nil for all keys on the keyring
 and t for just the secret keys.

The `return-fields' should be a list of :keyword entries from the data
structure of epa-programmatic-get-data, if nil it defaults to '(:key-id)

For example: If you wanted to search for all keys with \@foo.com in the
user ID with ultimate or full trust, and get the key-id, user-id-string,
and trust level then you'd want something like:

(epa-programmatic-get-data-filtered
           '((:user-id-string \"@foo.com\")
             (:trust-char \"[uf]\"))
           nil
           '(:key-id :user-id-string :trust-char))"
  
  (interactive)

  (if (not return-fields)
      (setq return-fields '(:key-id)))

  ;; Get unfiltered data because we do more complex checking later
  (let ((data (epa-programmatic-get-data nil secret))
        (return '()))
    
    (dolist (entry data)
      (let ((matched nil)
            (result '()))

        ;; Work out if we're returning this entry or not
        (if filter
            
            ;; Actually filter, if any test fails then don't return the data
            (let ((failed nil))
              
              (dolist (filt filter)
                ;; (message "Processing filter '%s' '%s' '%s'" filt (car filt) (nth 1 filt))
                (let* ((field (car filt))
                       (filter-regexp (nth 1 filt))
                       (field-data (alist-get field entry)))
                  
                  (if (not (string-match-p filter-regexp field-data))
                      (setq failed t))))
              
              (if (not failed)
                  (setq matched t)))

          ;; No filter?  Just return
          (setq matched t))

        ;; Extract the wanted fields
        (when matched
          (dolist (key return-fields)
            (let ((val (alist-get key entry)))
              (push val result)))
          
          ;; Accumulate onto returnable results, reversing the order
          ;; because everything was pushed above
          (push (reverse result) return))))

    ;; (reverse return)
    (when (called-interactively-p 'any)
      (message "%s" return))

    return))
        
                


(defun epa-programmatic-ultimate-trusted-keyids ()
  "Returns a list of strings, each of which is the keyid of a GPG key with
ultimate trust and validity from the GnuPG keyring.

Returns an empty list if there are none."
  (interactive)
  (let ((raw (epa-programmatic-get-data-filtered
              '((:validity "^ultimate$")
                (:owner-trust "^ultimate$"))
              t
              '(:key-id)))
        (results '()))

    ;; Extract the keyids from the list above as each will be on a
    ;; results sublist
    (dolist (curr raw)
      (push (car curr) results))

    ;; Reverse because we were pushing
    (setq results (reverse results))
    
    (when (called-interactively-p 'any)
      (message "%s" results))
    results))



;; Some old code that parses the epa buffers instead of querying epg directly.


(defun epa-programmatic-buffer-get-keys (&optional secret)
  "Returns a list of lists of all the keys that epa knows about.
Each list is three strings, with the first being qualities known by EPA
(see `epa-list-keys' for examples of these but e is expired, u is ultimate
trust, etc), the second is the key-id, and the third is the associated data
(name and email address).

If the `secret' argument is given checks the data from epa-list-secret-keys"
  
  (interactive)
  (save-excursion
    ;; Setup our config to not do a popup buffer of the data
    ;; See https://github.com/daviwil/emacs-from-scratch/blob/master/show-notes/Emacs-Tips-DisplayBuffer-1.org for how this works
    (let ((display-buffer-overriding-action '(display-buffer-no-window . ((allow-no-window . t))))
          (epa-keys-buffer (generate-new-buffer "*temporary-epa-keys*"))
          (found-keys '()))

      ;; Either the secret keys or all the keys
      (if secret
          (epa-list-secret-keys)
        (epa-list-keys))
      
      (switch-to-buffer epa-keys-buffer)
      (goto-char 0)

      ;; Run through and regex extract everything, then kill the buffer.
      (while (not (eobp))
        (let* ((eol (save-excursion
                      (end-of-line)
                      (point)))
               (line (buffer-substring-no-properties (point) eol)))
          (if (string-match "^[[:space:]]*\\([a-z]\\)[[:space:]]+\\([[:alnum:]]+\\)[[:space:]]+\\(.*\\)$" line)
              (push (list (match-string 1 line)
                          (match-string 2 line)
                          (match-string 3 line))
                    found-keys))
          (forward-line)))
      (kill-buffer epa-keys-buffer)

      ;; Return
      (when (called-interactively-p 'any)
        (message "%s" found-keys))
      found-keys)))



(defun epa-programmatic-buffer-get-keys-filtered (field filter &optional secret return-fields)

  "Filters the keys known to epa (EasyPG Assistant) and returns keyids based on
the criteria given.  Retrieves data with `epa-programmatic-buffer-get-keys'
which gives a list of all keys known in the format

'( (descriptive-character key-id user-details) ...)

This function take a `field' to check (0 being descriptive character, 1
being key-id, and 2 being user-details).

If that field matches the regex in `filter' it will construct a list of the
values from `return-fields' to give back to you, by default it returns all
fields.

The return-fields can either be a list of values (0 to 2) or a single integer.
Returns an empty list if there are none."
  (interactive)

  ;; Default to everything
  (if (not return-fields)
      (setq return-fields '(0 1 2)))
  
  (let ((epa-data (epa-programmatic-buffer-get-keys secret))
        (found-keydata '()))
    
    (dolist (curr epa-data)
      ;; If field is an int then check the field against the filter,
      ;; if its just true in some way then check it against every
      ;; field
      (let ((matcher nil))
        (cond
         ;; Check specific field
         ((integerp field)
             (if (string-match-p filter (nth field curr))
                 (setq matcher t)))

         ;; Check everything
         (field
          (dolist (dat curr)
            (if (string-match-p filter dat)
                (setq matcher t)))))

        ;; If we got a match then extract the desired fields
        (if matcher
            (let ((res '()))

              ;; Extract single value or multiple values
              (cond ((integerp return-fields)
                     (push (nth return-fields curr) res))
                    
                    ((listp return-fields)
                     (dolist (item return-fields)
                       (push (nth item curr) res))))

              ;; Values are pushed, so reverse the list
              (push (reverse res) found-keydata)))))
              
    (when (called-interactively-p 'any)
      (message "%s" found-keydata))
    found-keydata))







(provide 'epa-programmatic)
