;;; epa-programmatic.el --- Querying Emacs epa / EasyPG Assistant GnuPG library of keys programmatically -*- lexical-binding: t -*-

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

;;; Commentary:

;; This was made because I was messing around with epa/EasyPG
;; Assistant for encrypting some config files and I wanted some easy
;; ways to lookup the GPG keys on that machine to make my config a
;; little more portable between my machines, so I wanted something
;; that would let me put in a name, or an email address or some other
;; criteria, get those keys, and then use those key-ids with plstore
;; and similar.
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

(require 'epa)

(defun epa-programmatic-get-keys (&optional secret)
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

(defun epa-programmatic-get-keys-filtered (field filter &optional secret return-fields)

  "Filters the keys known to epa (EasyPG Assistant) and returns keyids based on
the criteria given.  Retrieves data with `epa-programmatic-get-keys' which
gives a list of all keys known in the format

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
  
  (let ((epa-data (epa-programmatic-get-keys secret))
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

(defun epa-programmatic-ultimate-trusted-keyids ()
  "Returns a list of strings, each of which is the keyid of a GPG key with ultimate trust
via epa/EasyPG Assistant.  Returns an empty list if there are none."
  (interactive)
  (let ((raw (epa-programmatic-get-keys-filtered 0 "^u$" t 1))
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


(provide 'epa-programmatic)
