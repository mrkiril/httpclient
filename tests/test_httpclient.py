import sys
import datetime
import time
import re
import socket
import base64
import json
import mimetypes
import os.path
import logging
import random
import string
import math
import hashlib


sys.path.append(os.path.abspath(os.path.join(
    os.path.abspath(os.path.dirname(__file__)), os.pardir)))

from httpclient import HttpClient
import unittest


class Test_urllib(unittest.TestCase):

    def setUp(self):
        self.file_path = os.path.abspath(os.path.dirname(__file__))

        my_headers = [('User-Agent', 'Mozilla/4.0'), ('X-From', 'UA')]
        my_user_pass = ('kiril', 'supersecret')

        self.client = HttpClient(
            load_cookie='cookie.txt',   # load cookie from file before query
            save_cookie='cookie.txt',   # save cookie to file after query
            connect_timeout=10,         # socket timeout on connect
            transfer_timeout=30,        # socket timeout on send/recv
            # follow Location: header on 3xx response
            max_redirects=10,
            # set Referer: header when follow location
            set_referer=True,
            keep_alive=3,               # Keep-alive socket up to N requests
            headers=my_headers,         # send custom headers
            http_version="1.1",         # use custom http/version
            auth=my_user_pass,          # http auth
            # try again on socket or http/5xx errors
            retry=5,
            retry_delay=10)             # wait betweet tries

    def tearDown(self):
        pass

    def test_get(self):

        res = self.client.get('http://www.google.com/intl/uk/about/',
                              referrer='http://www.google.com/',
                              output=os.path.join(self.file_path,
                                                  "socket_page.html"))
        # перевірка на успішність запиту
        self.assertEqual(res.status_code, "200")
        # перевірка на наявність тега <html>
        self.assertRegex(res.body, "<html")
        self.assertRegex(res.body, "</html>")

        lists = ["Barak Obama", "Vladimir Putin",
                 "fransua cluzet", "Alan Rickman",
                 "Taylor Momsen", "kurt cobain", "johnny depp"]

        for i in lists:
            res = self.client.get('http://www.google.com.ua/search?',
                                  params={'q': i, 'start': '10'},
                                  output=os.path.join(self.file_path,
                                                      "socket_page.html"))
            # перевірка на успішність запиту
            self.assertEqual(res.status_code, "200")
            # перевірка на наявність тега <html>
            self.assertRegex(res.body, "<html")
            self.assertRegex(res.body, "</html>")

        res = self.client.get('http://zakon5.rada.gov.ua/laws/show/254%D0%BA/'
                              '96-%D0%B2%D1%80/print1453311319237518',
                              max_size=150000,
                              output=os.path.join(self.file_path,
                                                  "socket_page.html"))
        # перевірка на успішність запиту
        self.assertEqual(res.status_code, "200")
        # перевірка на наявність тега <html>
        self.assertRegex(res.body, "<html>")
        self.assertRegex(res.body, "</html>")

        res = self.client.get('http://zakon5.rada.gov.ua/laws/show/254%D0%BA/'
                              '96-%D0%B2%D1%80/print1453311319237518',
                              max_size=50000,
                              output=os.path.join(self.file_path,
                                                  "socket_page.html"))
        # перевірка на успішність запиту
        self.assertEqual(res.status_code, "200")
        # перевірка на наявність тега <html>
        self.assertRegex(res.body, "<html")
        self.assertEqual(os.path.getsize(os.path.join(
            self.file_path, "socket_page.html")), 50000)

    def test_post(self):
        res = self.client.post('http://451f.tk/kiril.kuchelny/',
                               data={'k1': 'value', 'k2': 'eulav'},
                               output=os.path.join(self.file_path,
                                                   "socket_page.html"))
        # перевірка на успішність запиту
        self.assertEqual(res.status_code, "200")
        self.assertRegex(res.body, "eulav")
        self.assertRegex(res.body, "value")

        res = self.client.get(
            'http://i.ytimg.com/vi/7AFUch5JZaQ/maxresdefault.jpg',
            output=os.path.join(self.file_path,
                                "minion.jpg"))
        # перевірка на успішність запиту
        self.assertEqual(res.status_code, "200")

        res = self.client.post('http://451f.tk/kiril.kuchelny/',
                               files={'f1': open(os.path.join(
                                   self.file_path, "minion.jpg"), 'rb')},
                               auth=None,
                               output=os.path.join(self.file_path,
                                                   "socket_page.html"))

        # перевірка на успішність запиту
        with open(os.path.join(self.file_path, "minion.jpg"), 'rb') as fp:
            file_ = base64.standard_b64encode(fp.read())

        fp.close()
        m = hashlib.md5()
        m.update(file_)
        self.assertEqual(res.status_code, "200")
        self.assertRegex(res.body, m.hexdigest())

    def test_delete(self):
        res = self.client.delete('http://451f.tk/kiril.kuchelny/?123',
                                 retry=0,
                                 raise_on_error=True,
                                 output=os.path.join(self.file_path,
                                                     "socket_page.html"))
        # перевірка на успішність запиту
        self.assertEqual(res.status_code, "200")


if __name__ == '__main__':
    unittest.main()
