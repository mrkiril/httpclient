#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import os
import os.path
import hashlib
import subprocess
import multiprocessing
from httpclient import HttpClient
import unittest
from time import sleep
import logging
import logging.config
import sys
import configparser
import signal
import time
import json


class Test_urllib(unittest.TestCase):

    def setUp(self):
        print("Wait for a moment server is started ...")
        self.file_path = os.path.abspath(os.path.dirname(__file__))
        logging.config.fileConfig(
            os.path.join(os.getcwd(), "logging.conf"),
            disable_existing_loggers=True)

        my_headers = [('User-Agent', 'Mozilla/4.0'), ('X-From', 'UA')]
        my_user_pass = ('kiril', 'supersecret')
        self.client = HttpClient(
            connect_timeout=10,         # socket timeout on connect
            transfer_timeout=3,        # socket timeout on send/recv
            max_redirects=10,
            set_referer=True,
            keep_alive=3,               # Keep-alive socket up to N requests
            headers=my_headers,         # send custom headers
            http_version="1.1",         # use custom http/version
            auth=my_user_pass,          # http auth
            retry=5,
            retry_delay=10)             # wait betweet tries

        #
        # Enter the path to the cookies file in setting file
        #
        dictionary = self.client.configure_from_file(
            os.path.join(self.file_path, "setting.ini"))

        os.chdir("../../../../..")
        self.children = multiprocessing.Value('i', 0)
        self.p = multiprocessing.Process(target=self.process,
                                         args=(self.children, ),
                                         daemon=True)
        self.p.start()
        self.pid = self.p.pid
        sleep(2)
        config = configparser.ConfigParser()
        config.read(os.path.join(os.getcwd(), "setting", "setting.ini"))
        self.ip = config['DEFAULT']["ip"]
        self.port = config['DEFAULT']["port"]
        self.sock = self.ip + ":" + self.port
        os.chdir(self.file_path)

    def process(self, child_pid):
        children = subprocess.Popen(["python3", "search_serv.py"],
                                    shell=False)
        child_pid.value = children.pid

    def setting_sys(self, path):
        config = configparser.ConfigParser()
        config.read(path)
        if "SETTINGS" in config:
            dict1 = {}
            options = config.options("SETTINGS")
            for option in options:
                try:
                    dict1[option] = config.get("SETTINGS", option)
                    if dict1[option] == -1:
                        DebugPrint("skip: %s" % option)
                except:
                    print("exception on %s!" % option)
                    dict1[option] = None
            return dict1

    def tearDown(self):
        print("tearDown")
        print("slave >> " + str(self.pid))
        print("head  >> " + str(os.getpid()))
        print("child >> " + str(self.children.value))

        os.kill(self.children.value, signal.SIGINT)
        print("IS_ALIVE >> ", self.p.is_alive())
        self.p.terminate()

        try:
            os.kill(self.children.value, signal.SIGINT)
        except Exception as e:
            print("try to kill child", self.children.value, " but Exception")
            print(e.args)
        try:
            os.kill(self.pid, signal.SIGINT)
        except Exception as e:
            print("try to kill ", self.pid, " but Exception")
            print(e.args)

    def test_test(self):
        print("GET")
        # звичайтий запит перевірка статус кода
        # запис до файла
        # та багато запитів на гугл, перевірка відправки параметрів запиту
        res = self.client.get('http://www.google.com/intl/uk/about/',
                              referrer='http://www.google.com/',
                              output=os.path.join(self.file_path,
                                                  "socket_page.html"))

        self.assertEqual(res.status_code, "200")
        self.assertRegex(res.body, "<html")
        self.assertRegex(res.body, "</html>")

        lists = ["Barak+Obama", "Vladimir+Putin",
                 "fransua+cluzet", "Alan+Rickman",
                 "Taylor+Momsen", "kurt+cobain", "johnny+depp"]

        for i in lists:
            res = self.client.get('http://www.google.com.ua/search?',
                                  params={'q': i, 'start': '10'},
                                  output=os.path.join(self.file_path,
                                                      "socket_page.html"))

            self.assertEqual(res.status_code, "200")
            self.assertRegex(res.body, "<html")
            self.assertRegex(res.body, "</html>")

        # перевірка роботи max_size
        # якщо max_size більше ніж розмір сторінки
        #
        res = self.client.get('http://lurkmore.to/%D0%9F%D0%B5%D1%80%D0%B2'
                              '%D0%B0%D1%8F_%D0%BC%D0%B8%D1%80%D0%BE%D0%B2'
                              '%D0%B0%D1%8F_%D0%B2%D0%BE%D0%B9%D0%BD%D0%B0',
                              max_size=1500000,
                              output=os.path.join(self.file_path,
                                                  "socket_page.html"))

        self.assertEqual(res.status_code, "200")
        self.assertRegex(res.body, "</html>")

        # обмеження скачування через параметр max_size
        # з урахуванням того що розмір сторінки більше ніж max_size
        #
        res = self.client.get('http://lurkmore.to/%D0%9F%D0%B5%D1%80%D0%B2'
                              '%D0%B0%D1%8F_%D0%BC%D0%B8%D1%80%D0%BE%D0%B2'
                              '%D0%B0%D1%8F_%D0%B2%D0%BE%D0%B9%D0%BD%D0%B0',
                              max_size=150000,
                              output=os.path.join(self.file_path,
                                                  "socket_page.html"))

        self.assertEqual(res.status_code, "200")
        self.assertRegex(res.body, "html")
        self.assertEqual(
            os.path.getsize(
                os.path.join(
                    self.file_path, "socket_page.html")), 150000)

        # кукі, хедери, аутентифікація
        # та історія переходів
        #
        res = self.client.get('http://451f.tk/kiril.kuchelny/',
                              cookie={"key": "value"},
                              headers={"X-From": "UAUA"})

        self.assertRegex(res.body, "COOKIE: key=value")
        self.assertRegex(res.body, "X_FROM: UAUA")
        self.assertRegex(res.body, "Username: kiril")
        self.assertRegex(res.body, "Password: supersecret")

        # кукі, хедери, аутентифікація
        # та історія переходів
        #
        res = self.client.get('http://451f.tk/kiril.kuchelny/',
                              cookie={"key": "value"},
                              headers={"X-From": "UAUA"},
                              auth=("user", "ololo"),
                              history_body=True)

        self.assertRegex(res.body, "COOKIE: key=value")
        self.assertRegex(res.body, "X_FROM: UAUA")
        self.assertRegex(res.body, "Username: user")
        self.assertRegex(res.body, "Password: ololo")
        self.assertIsNotNone(res.history)

        # проксі
        # з аутентифікацією
        # та ВІА
        res = self.client.get('http://451f.tk/kiril.kuchelny?lalala=ololo',
                              proxy=('77.120.99.41', 8080),
                              proxy_auth=('kiril', 'kuchelny'),
                              set_via=True,
                              output=os.path.join(self.file_path,
                                                  "socket_page.html"))

        self.assertEqual(res.status_code, "200")
        self.assertRegex(res.body, "lalala=ololo")

        # перевірка обмеження редіректів
        # через редірект з головного дзеркала на сайт
        #
        res = self.client.get('http://www.lurkmore.to/',
                              max_redirects=1)
        self.assertEqual(res.status_code, "301")

        # функція програс бара  в якосі аргумента
        # для чекання прогреса скачування
        #
        def on_progress(i, all_len):
            sys.stdout.write('\r')
            sys.stdout.write("[%-20s] %d%%" %
                             ('=' * round(20 * i / all_len),
                              100 * i / all_len))
            sys.stdout.flush()
            return True

        res = self.client.get(
            'http://i.ytimg.com/vi/7AFUch5JZaQ/maxresdefault.jpg',
            output=os.path.join(self.file_path, "minion.jpg"),
            on_progress=on_progress)
        self.assertEqual(res.status_code, "200")

        # перевірка таймауту
        # екземпляр класа None
        # ібо нічого не прийшло
        res = self.client.get('http://' + self.sock + "/test_timeout")
        self.assertIsNotNone(res)
        self.assertEqual(res.status_code, "")

        # переврка виставлення обмежження повтору запитів
        # при 5хх помилках
        # на виклика помилки
        res = self.client.get('http://' + self.sock + "/test_505",
                              retry=1,
                              raise_on_error=True)
        self.assertEqual(res.status_code, "505")

        res = self.client.get('http://' + self.sock + "/test_505", retry=1)
        self.assertEqual(res.status_code, "505")
        self.assertEqual(res.retry_index, 1)

        print("POST")
        # перевірка відправки дата
        # та виводу сторінки в файл
        #
        res = self.client.post('http://451f.tk/kiril.kuchelny/',
                               data={'k1': 'value', 'k2': 'eulav'},
                               output=os.path.join(self.file_path,
                                                   "socket_page.html"))
        self.assertEqual(res.status_code, "200")
        self.assertRegex(res.body, "eulav")
        self.assertRegex(res.body, "value")

        # перевірка відправки файла через контрольну суму MD5
        # та виводу сторінки в файл
        # з відміною стандартної аутентифікації
        res = self.client.get(
            'http://i.imgur.com/HK9d09p.jpg',
            output=os.path.join(self.file_path, "minion.jpg"))
        self.assertEqual(res.status_code, "200")

        res = self.client.post('http://451f.tk/kiril.kuchelny/',
                               files={'f1': open(os.path.join(
                                   self.file_path, "minion.jpg"), 'rb')},
                               auth=None,
                               output=os.path.join(self.file_path,
                                                   "socket_page.html"))

        # print(res.body)

        with open(os.path.join(self.file_path, "minion.jpg"), 'rb') as fp:
            file_ = base64.standard_b64encode(fp.read())
        fp.close()
        m = hashlib.md5()
        m.update(file_)
        self.assertEqual(res.status_code, "200")
        self.assertRegex(res.body, m.hexdigest())

        with open(os.path.join(self.file_path,
                               "socket_page.html"), "r") as fp:
            data = fp.read()

        self.assertNotRegex(res.body, "Username: kiril")
        self.assertNotRegex(res.body, "Password:  supersecret")
        self.assertNotRegex(data, "Username: kiril")
        self.assertNotRegex(data, "Password: supersecret")

        # перевірка відправки данних
        # виставлення кукі та хедерів разом з аутентифікацією
        # та наявність хісторі
        res = self.client.post('http://451f.tk/kiril.kuchelny/',
                               data={'k1': 'value', 'k2': 'eulav'},
                               cookie={"key": "value"},
                               headers={"X-From": "UAUA"},
                               auth=("user", "ololo"),
                               history_body=True)

        self.assertRegex(res.body, "COOKIE: key=value")
        self.assertRegex(res.body, "X_FROM: UAUA")
        self.assertRegex(res.body, "Username: user")
        self.assertRegex(res.body, "Password: ololo")
        self.assertIsNotNone(res.history)

        # перевірка відправки данних
        # та виставлення реферерера
        # з хісторі боді
        res = self.client.post("http://httpbin.org/post",
                               data={'k1': 'value', 'k2': 'eulav'},
                               referrer='http://httpbin.org/',
                               history_body=True)
        self.assertEqual(res.status_code, "200")
        self.assertRegex(res.body, '"k1": "value"')
        self.assertRegex(res.body, '"k2": "eulav"')
        self.assertRegex(res.body, '"Referrer": "http://httpbin.org/"')
        self.assertIsNotNone(res.history)

        # обмеження кількості редіректів
        #
        res = self.client.post('http://' + self.sock + "/test_301",
                               data={'k1': 'value', 'k2': 'eulav'},
                               max_redirects=1)
        self.assertEqual(res.status_code, "301")
        self.assertEqual(res.redirect_counter, 1)
        self.assertEqual(res.headers["Location"], "http://google.com.ua")

        # max_size for POST
        # перевірна на файлі
        # а також на розмірі месседж боді екземпляра класа
        res = self.client.get("http://httpbin.org/html",
                              max_size=400,
                              output=os.path.join(self.file_path,
                                                  "socket_page.html"))
        self.assertEqual(res.status_code, "200")
        self.assertRegex(res.body, "html")
        self.assertEqual(len(res.body), 400)
        self.assertEqual(
            os.path.getsize(
                os.path.join(
                    self.file_path, "socket_page.html")), 400)

        # timeout  POST
        #
        #
        res = self.client.post('http://' + self.sock + "/test_timeout",
                               data={'k1': 'value', 'k2': 'eulav'})
        self.assertEqual(res.status_code, "")
        self.assertEqual(res.body, "")

        # переврка виставлення обмежження повтору запитів
        # при 5хх помилках
        # на виклика помилки
        res = self.client.post('http://' + self.sock + "/test_505",
                               data={'k1': 'value', 'k2': 'eulav'},
                               retry=1,
                               raise_on_error=True)
        self.assertEqual(res.status_code, "505")

        res = self.client.post('http://' + self.sock + "/test_505",
                               data={'k1': 'value', 'k2': 'eulav'},
                               retry=1)

        self.assertIsNotNone(res)
        self.assertEqual(res.status_code, "505")
        self.assertEqual(res.retry_index, 1)

        print("DELETE")
        res = self.client.delete(
            'http://httpbin.org/delete?mama=papa&alala=ololo')
        self.assertRegex(res.body, '"mama": "papa"')
        self.assertEqual(res.status_code, "200")

        print("PUT")
        res = self.client.put('http://httpbin.org/put',
                              data={'k1': 'value', 'k2': 'eulav'})
        self.assertRegex(res.body, '"k1": "value"')
        self.assertRegex(res.body, '"k2": "eulav"')
        self.assertEqual(res.status_code, "200")

        print("HEAD")
        res = self.client.head('http://451f.tk/kiril.kuchelny/')
        self.assertEqual(res.status_code, "200")

        start_time = time.time()
        print(start_time)
        # Неблокуючий режим для GET
        # З кукі, та хедерами
        # та набором параметрів
        payload = {'q': "Trump", 'start': '10'}
        res1 = self.client.get("http://httpbin.org/get",
                               params=payload,
                               cookie={"key": "value"},
                               headers={"X-From": "UAUA"},
                               nonblocking=True)
        res2 = self.client.get("http://httpbin.org/get",
                               params=payload,
                               cookie={"key": "value"},
                               headers={"X-From": "UAUA"},
                               nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break
        for res in arr_obj:
            self.assertRegex(res.body, '"q": "Trump"')
            self.assertRegex(res.body, '"start": "10"')
            self.assertRegex(res.body, '"key=value"')
            self.assertRegex(res.body, '"X-From": "UAUA"')
            self.assertEqual(res.status_code, "200")

        print(time.time() - start_time)

        # Неблокуючий режим для GET
        # таймаут відправки данних
        payload = {'q': "Trump", 'start': '10'}
        res1 = self.client.get("http://httpbin.org/delay/5",
                               params=payload,
                               cookie={"key": "value"},
                               headers={"X-From": "UAUA"},
                               nonblocking=True)
        res2 = self.client.get("http://httpbin.org/delay/5",
                               params=payload,
                               cookie={"key": "value"},
                               headers={"X-From": "UAUA"},
                               nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            self.assertEqual(arr_obj[i].status_code, "")
            self.assertEqual(arr_obj[i].body, "")

        # Базова аутентифікація
        # та запису до файла
        #
        res1 = self.client.get("http://httpbin.org/basic-auth/user/ololo",
                               history_body=True,
                               auth=("user", "ololo"),
                               output=os.path.join(self.file_path,
                                                   "socket_page_1.html"),
                               nonblocking=True)
        res2 = self.client.get("http://httpbin.org/basic-auth/user/ololo",
                               history_body=True,
                               auth=("user", "ololo"),
                               output=os.path.join(self.file_path,
                                                   "socket_page_2.html"),
                               nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            self.assertEqual(arr_obj[i].status_code, "200")
            self.assertRegex(arr_obj[i].body, '"authenticated": true')
            self.assertIsNotNone(arr_obj[i].history)

        path = os.path.join(self.file_path, "socket_page_1.html")
        self.assertEqual(str(os.path.getsize(path)), arr_obj[
                         0].headers["Content-Length"])

        # проксі в неблокуючому режимі
        # з аутентифікацією
        # та ВІА
        res1 = self.client.get("http://httpbin.org/get",
                               params={"qwerty": "12345"},
                               proxy=('77.120.99.41', 8080),
                               proxy_auth=('kiril', 'kuchelny'),
                               set_via=True,
                               nonblocking=True)
        res2 = self.client.get("http://httpbin.org/get",
                               params={"qwerty": "12345"},
                               proxy=('77.120.99.41', 8080),
                               proxy_auth=('kiril', 'kuchelny'),
                               set_via=True,
                               nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            data = json.loads(arr_obj[i].body)
            self.assertEqual(arr_obj[i].status_code, "200")
            self.assertEqual(data["args"]["qwerty"], "12345")

        # Обмеження кількості повторних запитів
        # при 5хх помилкахсервера
        #
        res1 = self.client.get("http://httpbin.org/status/501",
                               retry=1,
                               nonblocking=True)
        res2 = self.client.get("http://httpbin.org/status/501",
                               retry=1,
                               nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            self.assertEqual(arr_obj[i].status_code, "501")
            self.assertEqual(arr_obj[i].retry_index, 1)

        # raise_on_error при 5хх помилках
        #
        #
        res1 = self.client.get("http://httpbin.org/status/501",
                               raise_on_error=True,
                               nonblocking=True)
        res2 = self.client.get("http://httpbin.org/status/501",
                               raise_on_error=True,
                               nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            self.assertEqual(arr_obj[i].status_code, "501")
            self.assertEqual(arr_obj[i].retry_index, 0)

        # Перевірка обмеження максимальноїдовжини сторінки
        # через max_size
        # тарозміру файла при завантаження
        size_size = 2999
        res1 = self.client.get("http://httpbin.org/html",
                               max_size=size_size,
                               output=os.path.join(self.file_path,
                                                   "socket_page_1.html"),
                               nonblocking=True)
        res2 = self.client.get("http://httpbin.org/html",
                               max_size=size_size,
                               output=os.path.join(self.file_path,
                                                   "socket_page_2.html"),
                               nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            self.assertEqual(arr_obj[i].status_code, "200")
            self.assertEqual(len(arr_obj[i].body), size_size)

        path = os.path.join(self.file_path, "socket_page_1.html")
        self.assertEqual(os.path.getsize(path), size_size)
        path = os.path.join(self.file_path, "socket_page_2.html")
        self.assertEqual(os.path.getsize(path), size_size)

        # перевірка обмеження max_redirects
        #
        #
        size_size = 2999
        res1 = self.client.get("http://httpbin.org/absolute-redirect/2",
                               max_redirects=1,
                               nonblocking=True)
        res2 = self.client.get("http://httpbin.org/absolute-redirect/2",
                               max_redirects=1,
                               nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            self.assertEqual(arr_obj[i].status_code, "302")
            self.assertEqual(arr_obj[i].redirect_counter, 1)

        # перевірка реферера
        #
        #
        size_size = 2999
        res1 = self.client.get("http://httpbin.org/get",
                               referrer='http://www.google.com/',
                               nonblocking=True)
        res2 = self.client.get("http://httpbin.org/get",
                               referrer='http://www.google.com/',
                               nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            # data = json.loads(arr_obj[i].body)
            self.assertEqual(arr_obj[i].status_code, "200")

        # ********** POST *********
        # перевірка відправки данних
        # реферера, кукі, хедерів
        # хісторі боді   та запис до файлу
        res1 = self.client.post("http://httpbin.org/post",
                                data={'k1': 'value', 'k2': 'eulav'},
                                referrer='http://www.google.com/',
                                cookie={"key": "value"},
                                headers={"X-From": "UAUA"},
                                history_body=True,
                                output=os.path.join(self.file_path,
                                                    "socket_page_1.html"),
                                nonblocking=True)
        res2 = self.client.post("http://httpbin.org/post",
                                referrer='http://www.google.com/',
                                data={'k1': 'value', 'k2': 'eulav'},
                                cookie={"key": "value"},
                                headers={"X-From": "UAUA"},
                                history_body=True,
                                output=os.path.join(self.file_path,
                                                    "socket_page_2.html"),
                                nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            data = json.loads(arr_obj[i].body)
            self.assertEqual(arr_obj[i].status_code, "200")
            self.assertEqual(data["form"]["k1"], "value")
            self.assertEqual(data["form"]["k2"], "eulav")
            self.assertEqual(data["headers"]["Cookie"], "key=value")
            self.assertEqual(data["headers"]["Referrer"],
                             "http://www.google.com/")
            self.assertEqual(data["headers"]["X-From"], "UAUA")
            self.assertIsNotNone(arr_obj[i].history)

        path = os.path.join(self.file_path, "socket_page_1.html")
        self.assertEqual(os.path.getsize(path), int(
            arr_obj[0].headers["Content-Length"]))
        path = os.path.join(self.file_path, "socket_page_2.html")
        self.assertEqual(os.path.getsize(path), int(
            arr_obj[1].headers["Content-Length"]))

        # перевірка відправки файла
        # та порівняння контрольних сум
        #
        res1 = self.client.post("http://451f.tk/kiril.kuchelny/",
                                auth=("user", "ololo"),
                                files={'f1': open(os.path.join(
                                    self.file_path, "minion.jpg"), 'rb')},
                                nonblocking=True)

        res2 = self.client.post("http://451f.tk/kiril.kuchelny/",
                                auth=("user", "ololo"),
                                files={'f1': open(os.path.join(
                                    self.file_path, "minion.jpg"), 'rb')},
                                nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 15.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        with open(os.path.join(self.file_path, "minion.jpg"), 'rb') as fp:
            file_ = base64.standard_b64encode(fp.read())
        fp.close()
        m = hashlib.md5()
        m.update(file_)
        control_sum = m.hexdigest()

        for i in range(len(arr_obj)):
            self.assertEqual(arr_obj[i].status_code, "200")
            self.assertRegex(arr_obj[i].body, str(control_sum))
            self.assertRegex(arr_obj[i].body, "Username: user")
            self.assertRegex(arr_obj[i].body, "Password: ololo")

        # перевірка обмеження кількості редіректів
        #
        #
        res1 = self.client.post("http://" + self.sock + "/test_301",
                                data={'k1': 'value', 'k2': 'eulav'},
                                max_redirects=1,
                                nonblocking=True)
        res2 = self.client.post("http://" + self.sock + "/test_301",
                                data={'k1': 'value', 'k2': 'eulav'},
                                max_redirects=1,
                                nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            self.assertEqual(arr_obj[i].status_code, "301")
            self.assertEqual(arr_obj[i].redirect_counter, 1)
            self.assertEqual(arr_obj[i].headers[
                             "Location"], "http://google.com.ua")

        # Обмеження кількості повторних запитів
        # при 5хх помилках сервера
        #
        res1 = self.client.post('http://' + self.sock + "/test_505",
                                data={'k1': 'value', 'k2': 'eulav'},
                                retry=1,
                                nonblocking=True)
        res2 = self.client.post('http://' + self.sock + "/test_505",
                                data={'k1': 'value', 'k2': 'eulav'},
                                retry=1,
                                nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            self.assertEqual(arr_obj[i].status_code, "505")
            self.assertEqual(arr_obj[i].retry_index, 1)

        # Обмеження кількості повторних запитів
        # при 5хх помилках сервера
        #
        res1 = self.client.post('http://' + self.sock + "/test_timeout",
                                data={'k1': 'value', 'k2': 'eulav'},
                                retry=1,
                                nonblocking=True)
        res2 = self.client.post('http://' + self.sock + "/test_timeout",
                                data={'k1': 'value', 'k2': 'eulav'},
                                retry=1,
                                nonblocking=True)
        arr_obj = [res1, res2]
        global_start_time = time.time()
        while True:
            arr_status = [ob.isready() for ob in arr_obj]
            if False in arr_status:
                sleep(0.05)
                if time.time() - global_start_time > 3.5:
                    break
                if time.time() - global_start_time > 0.9:
                    count = arr_status.count(True)
                    if count / len(arr_status) > 0.6:
                        break
                    else:
                        continue
                continue
            else:
                break

        for i in range(len(arr_obj)):
            self.assertEqual(arr_obj[i].status_code, "")
            self.assertEqual(arr_obj[i].body, "")


if __name__ == '__main__':
    unittest.main()
