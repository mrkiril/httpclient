#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import socket
import base64
import json
import mimetypes
import os.path
import logging
import random
import string
import errno
import os
import io
import sys
import time
import configparser


class HttpErrors(Exception):

    """Class HttpErrors
    Need to raise error is raise_on_error == True
    """

    def __init__(self, err_number):
        self.err_number = err_number

    def __str__(self):
        return repr("HTTP ERROR " + self.err_number +
                    " - " + HtCode.get_story(str(self.err_number)))


class HtCode(object):

    """
    Http Code class

    Input the number of http code. And method get_story
    retun an subscribe of it
    """
    http_codes = {
        "200": "OK",
        "301": "Moved Permanently",
        "302": "Moved Temporarily",
        "400": "Bad Request",
        "404": "Not Found",
        "405": "Method Not Allowed ",
        "408": "Request Timeout",
        "415": "Unsupported Media Type",
        "418": "I'm a teapot ",
        "423": "Locked",
        "500": "Internal Server Error",
        "501": "Not Implemented",
        "502": "Bad Gateway",
        "503": "Service Unavailable",
        "504": "Gateway Timeout",
        "505": "HTTP Version Not Supported"
    }

    @staticmethod
    def get_story(code):
        return HtCode.http_codes[str(code)]


class SocketFallError(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class HttpClient(object):

    """ Main class of this library.
        It contain GET, POST, PUT, DELETE, HEAD methods.

        Attributes:
            load_cookie: load cookie from file before query
            save_cookie: save cookie to file after query
            connect_timeout: socket timeout on connect
            transfer_timeout: socket timeout on send/recv
            max_redirects: follow Location: header on 3xx response
            set_referer: set Referer: header when follow location
            keep_alive: Keep-alive socket up to N requests

            And logger of library can call'd like self.logger
    """

    def __init__(self, **kwargs):
        # create logger
        self.logger = logging.getLogger(__name__)
        # self.logger.setLevel(logging.INFO)
        self.file_path = os.path.abspath(os.path.dirname(__file__))
        self.load_cookie = None
        self.save_cookie = None
        self.connect_timeout = 15
        self.transfer_timeout = 2
        self.max_redirects = 10
        self.set_referer = True
        self.keep_alive = 5
        # send custom headers
        self.headers_for_request = [
            ('User-Agent', 'Opera/9.80 (iPhone; Opera Mini/7.0.4/28.2555;'
             'U; fr) Presto/2.8.119 Version/11.10'), ('X-From', 'UA')]
        self.http_version = "1.1"
        self.auth = None
        self.retry = 5
        self.retry_delay = 1
        self.nonblocking = False
        self.nonblocking_stack = []
        self.send_stack_index = 0
        self.send_byte_index = 0
        self.redirect_counter = 0
        self.socket_fall_counter = 0
        if "load_cookie" in kwargs:
            self.load_cookie = kwargs["load_cookie"]
        if "save_cookie" in kwargs:
            self.save_cookie = kwargs["save_cookie"]
        if "connect_timeout" in kwargs:
            self.connect_timeout = kwargs["connect_timeout"]
        if "transfer_timeout" in kwargs:
            self.transfer_timeout = kwargs["transfer_timeout"]
        if "max_redirects" in kwargs:
            self.max_redirects = kwargs["max_redirects"]
        if "set_referer" in kwargs:
            self.set_referer = kwargs["set_referer"]
        if "keep_alive" in kwargs:
            self.keep_alive = kwargs["keep_alive"]
        if "headers" in kwargs:
            self.headers_for_request = kwargs["headers"]
        if "http_version" in kwargs:
            self.http_version = kwargs["http_version"]
        if "auth" in kwargs:
            self.auth = kwargs["auth"]
        if "retry" in kwargs:
            self.retry = kwargs["retry"]
        if "retry_delay" in kwargs:
            self.retry_delay = kwargs["retry_delay"]

        self.req_line = b""
        self.is_f_req = True
        self.cook_dick = {}
        # for nonblocking
        self.isgetipfromhost = False
        self.isconnect = False
        self.issend = False
        self.isrecv = False
        self.start_time = time.time()

        self.response_str = ""
        # self.soket_dic[Host] = { "socket": sock, "index" : index}
        self.soket_dic = {}
        self.page_status_list = []
        self.host_ip_dic = {}
        # start methods parametsr
        self.output = None
        self.host = None
        self.cookies = ""
        self.sock = None
        self.max_size = None
        self.proxy = None
        self.proxy_auth = None
        self.retry_index = 0
        # if True in history will be add message body
        self.history_body = None
        # end methods parametrs
        self.status_code = ""
        self.headers = {}
        self.encoding = ""
        self.body = b""
        self.history = []
        # for nonblocking
        self.page = b""
        self.firstin = True
        self.chunked_index = 0
        self.page_str = b""  # for chunked module nonblocking

    def __del__(self):
        # self.soket_dic[Host] = { "socket": sock, "index" : index, "key": key}
        for k, v in self.soket_dic.items():
            v["socket"].close()

    def configure_from_file(self, path):
        config = configparser.ConfigParser()
        config.read(path)
        if "SETTINGS" in config:
            dict1 = {}
            options = config.options("SETTINGS")
            for option in options:
                try:
                    dict1[option] = config.get("SETTINGS", option)
                except:
                    dict1[option] = None

            if "load_cookie" in dict1:
                self.load_cookie = dict1["load_cookie"]
            if "save_cookie" in dict1:
                self.save_cookie = dict1["save_cookie"]
            if "connect_timeout" in dict1:
                self.connect_timeout = int(dict1["connect_timeout"])
            if "transfer_timeout" in dict1:
                self.transfer_timeout = int(dict1["transfer_timeout"])
            if "max_redirects" in dict1:
                self.max_redirects = int(dict1["max_redirects"])
            if "set_referer" in dict1:
                self.set_referer = bool(dict1["set_referer"])
            if "keep_alive" in dict1:
                self.keep_alive = int(dict1["keep_alive"])
            if "http_version" in dict1:
                self.http_version = dict1["http_version"]
            if "retry" in dict1:
                self.retry = int(dict1["retry"])
            if "retry_delay" in dict1:
                self.retry_delay = int(dict1["retry_delay"])
            return dict1

    def ipfromhost(self, host):
        if host in self.host_ip_dic:
            return self.host_ip_dic[host]
        else:
            return None

    def size_base64(self, size_):
        z = (size_ // 3)
        if size_ % 3 != 0:
            z += 1
        return z * 4

    def boundary(self):
        a = string.ascii_lowercase + string.digits
        return ''.join([random.choice(a) for i in range(8)])

    def del_sock(self):
        # delete and close this socket
        key = None
        for k, v in self.soket_dic.items():
            if v["socket"] == self.sock:
                key = k
                break
        if key is not None:
            self.soket_dic.pop(key)
            self.sock.close()

        if self.host in self.soket_dic:
            self.soket_dic[self.host]["socket"].close()
            self.soket_dic.pop(self.host)

    def connect(self, url, kwargs, headers_all, url_previos,
                type_req, bytes_to_send, transfer_timeout):
        while True:
            try:
                if self.host in self.soket_dic and self.proxy is None:
                    self.logger.debug('socket exist')
                    self.sock = self.soket_dic[self.host]["socket"]
                    self.soket_dic[self.host]["index"] += 1
                    self.is_f_req = True

                if self.host not in self.soket_dic and self.proxy is None:
                    self.logger.debug('socket does not exist')
                    self.sock = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM)

                    if ":" in self.host:
                        n_host = self.host.split(":")
                        addr = (n_host[0], int(n_host[1]))
                    else:
                        ip = self.ipfromhost(self.host)
                        if ip is not None:
                            addr = (ip, 80)
                            self.logger.debug('Ip from list')
                        if ip is None:
                            addr = (self.host, 80)

                    if self.nonblocking:
                        self.sock.settimeout(0.0)
                        try:
                            self.sock.connect(addr)
                        except socket.error as err:
                            if err.errno != errno.EINPROGRESS:
                                raise

                    if not self.nonblocking:
                        self.sock.settimeout(self.connect_timeout)
                        self.sock.connect(addr)
                        self.sock.settimeout(None)
                        self.host_ip_dic[self.host] = self.sock.getpeername()[
                            0]

                    self.soket_dic[self.host] = {
                        "socket": self.sock, "index": 0}
                    self.is_f_req = True

                if self.proxy is not None:
                    is_proxy_exist = False
                    soket_key = None
                    for key, elem in self.soket_dic.items():
                        if self.proxy[0] == str(
                                elem["socket"].getpeername()[0]):
                            is_proxy_exist = True
                            self.sock = elem["socket"]
                            soket_key = key
                            break
                    if not is_proxy_exist:
                        self.logger.info('Proxy socket does not exist')
                        self.sock = socket.socket(socket.AF_INET,
                                                  socket.SOCK_STREAM)
                        addr = (self.proxy[0], self.proxy[1])
                        self.sock.settimeout(self.connect_timeout)
                        self.sock.connect(addr)
                        if self.nonblocking:
                            self.sock.settimeout(0)
                        if not self.nonblocking:
                            self.sock.settimeout(None)
                        self.soket_dic[self.proxy[0]] = (
                            {"socket": self.sock, "index": 0})
                        self.is_f_req = True
                        self.logger.info('Proxy socket is create')

                    if is_proxy_exist:
                        self.logger.info('Proxy socket exist')
                        self.sock = self.soket_dic[soket_key]["socket"]
                        self.soket_dic[soket_key]["index"] += 1
                        self.is_f_req = True

            except ConnectionError as e:
                self.logger.error('ConnectionError' + str(e.args))
                return(False, "", "")

            except FileNotFoundError as e:
                self.logger.error('FileNotFoundError' + str(e.args))
                self.del_sock()
                return (False, "", "")

            except socket.timeout as e:
                self.sock.close()
                self.logger.error('TimeoutError' + str(e.args))
                try:
                    self.soket_dic.pop(self.host)
                except KeyError as e:
                    pass
                return (False, "")

            except BlockingIOError as e:
                self.logger.error("Resource temporarily unavailable")
                return(False, "", "")

            except OSError as e:
                self.logger.error(
                    'OSError ' + str(e.errno) + " " + os.strerror(e.errno))
                self.del_sock()
                return(False, "", "")

            else:
                return (True, b"", "")

    def status_200_300(self,  host_url_and_query, cookie_arr):
        # Find cookies for next iteration
        m_location = re.search("(\w+://)?(([^/]+).*)", host_url_and_query)
        new_Host_url_and_query = m_location.group(2)
        new_Host = m_location.group(3)
        cookies = ""
        cook_part = []
        for key in self.cook_dick.keys():
            if key[0] == ".":
                m_key = re.search(key[1:] +
                                  self.cook_dick[key]["params"]["path"],
                                  new_Host_url_and_query)

            if key[0] != ".":
                m_key = re.match(key + self.cook_dick[key]["params"]["path"],
                                 new_Host_url_and_query)

            if m_key is not None:
                tmp_cook = self.cook_dick[key]["cookie"].copy()
                tmp_cook.update(cookie_arr)
                cook_part.append(
                    "; ".join([k + "=" + v for k, v in tmp_cook.items()]))

        cookies = "; ".join(cook_part)
        return (cookies, host_url_and_query, new_Host)

    def cookies_parsing_funk(self, cookies_list, start_host):
        for el_cookies_list in cookies_list:
            m_cook = re.split("; ?", el_cookies_list)
            temp_dick = {}
            for el in m_cook:
                parser_el = re.search("(.+?)=(.+)", el)
                if parser_el is not None:
                    el_key = parser_el.group(1).lower()
                    el_value = re.sub(";", "", parser_el.group(2))
                    temp_dick[el_key] = el_value

            params = {}
            # DOMAIN
            if "domain" not in temp_dick:
                domain = "." + start_host

            if "domain" in temp_dick:
                if "domain" in temp_dick:
                    domain = temp_dick.pop("domain")
                else:
                    domain = temp_dick.pop("Domain")
            # PATH
            if "path" not in temp_dick:
                params["path"] = "/"

            if "path" in temp_dick:
                if "path" in temp_dick:
                    params["path"] = temp_dick.pop("path")

            # EXPIRES
            if "expires" not in temp_dick:
                params["expires"] = None
            if "expires" in temp_dick:
                if "expires" in temp_dick:
                    params["expires"] = temp_dick.pop("expires")

            # DICK
            if domain not in self.cook_dick:
                self.cook_dick[domain] = (
                    {"cookie": temp_dick, "params": params})

            if domain in self.cook_dick:
                for key, value in temp_dick.items():
                    self.cook_dick[domain]["cookie"][key] = value

    def soket_funk(self, url, kwargs, headers_all, url_previos,
                   type_of_request, bytes_to_send):
        """
        Create request string and send in blockmode.
        Or push to the stack in nonblocking mode
        """
        self.nonblocking_stack = []
        bound = self.boundary().encode()
        CRLF = b"\r\n"
        q = (type_of_request.encode() + b" " + url.encode() +
             b" HTTP/" + self.http_version.encode() + CRLF)

        q += b"Host: " + self.host.encode() + CRLF
        if self.cookies:
            q += b"Cookie: " + self.cookies.encode() + CRLF

        if self.set_referer:
            if "referrer" in kwargs:
                q += b"Referrer: " + kwargs["referrer"].encode() + CRLF

            if url_previos != "":
                q += b"Referrer: " + url_previos.encode() + CRLF

        if self.auth is not None:
            q += b"Authorization: Basic " + base64.standard_b64encode(
                self.auth[0].encode() + b":" +
                self.auth[1].encode()) + CRLF

        q += b"Connection: Keep-Alive" + CRLF
        for k, v in headers_all.items():
            q += k.encode() + b": " + v.encode() + CRLF

        if "proxy" in kwargs and "proxy_auth" in kwargs:
            q += b"Proxy-Authorization: Basic " + base64.standard_b64encode(
                self.proxy_auth[0].encode() + b":" +
                self.proxy_auth[1].encode()) + CRLF

            q += b"Proxy-Connection: Keep-Alive" + CRLF
            if "set_via" in kwargs:
                if kwargs["set_via"]:
                    localhost = self.sock.getsockname()
                    lasthost = self.sock.getpeername()
                    via = ("Via: {0} {1}:{2}, 1.1 {3}:{4}, 1.1 {5}".format(
                        self.http_version, localhost[0], localhost[1],
                        lasthost[0], lasthost[1], self.host) +
                        CRLF.decode())

                    q += via.encode()

        if (type_of_request == "HEAD" or type_of_request == "DELETE" or
                type_of_request == "GET"):
            q += CRLF
            if not self.nonblocking:
                num = self.soket_send(q)
                return num
            if self.nonblocking:
                self.nonblocking_stack.append(q)
                return self.nonblocking_stack

        if type_of_request == "POST" or type_of_request == "PUT":
            if "data" in kwargs:
                q += b"Content-Type: application/x-www-form-urlencoded" + CRLF
            if "files" in kwargs:
                q += (b"Content-Type: multipart/form-data; "
                      b"boundary=" + bound + CRLF)

            # calculate byte lenght
            if "data" in kwargs:
                payload_el = "&".join([k + "=" + v for k, v in
                                           kwargs["data"].items()])
                byte_len = str(len(payload_el))
                q += b"Content-Length: " + byte_len.encode() + CRLF

            if "files" in kwargs:
                count_files = len(kwargs["files"])
                sum_of = 14 + count_files * 121
                for key, value in kwargs["files"].items():
                    path = os.path.abspath(value.name)
                    size_base64 = self.size_base64(os.path.getsize(path))
                    sum_of += len(os.path.basename(value.name).encode())
                    sum_of += len(key.encode())
                    sum_of += len(
                        mimetypes.guess_type(value.name,
                                             strict=False)[0].encode())
                    sum_of += size_base64

                byte_len = str(sum_of)
                # last CRLF before entity-body
                q += b"Content-Length: " + byte_len.encode() + CRLF

            q += CRLF
            if not self.nonblocking:
                self.soket_send(q)

            if self.nonblocking:
                self.nonblocking_stack.append(q)

            q = b""
            # constructing message body
            # to sending files
            boundary = b"--" + bound
            mimetypes.init()
            is_one_iter = False
            lap = b'"'
            if "files" in kwargs:
                for key, value in kwargs["files"].items():
                    bytes_to_send = b""
                    mime = mimetypes.guess_type(value.name, strict=False)
                    # create request string
                    bytes_to_send += boundary + CRLF
                    bytes_to_send += (b"Content-Disposition: " +
                                      b"form-data; name=" +
                                      lap +
                                      key.encode() + lap + b"; filename=" +
                                      lap +
                                      os.path.basename(value.name).encode() +
                                      lap + CRLF)

                    bytes_to_send += b"Content-Type: " + \
                        mime[0].encode() + CRLF
                    bytes_to_send += b"Content-Transfer-Encoding: base64" + \
                        CRLF
                    bytes_to_send += CRLF
                    if self.nonblocking:
                        self.nonblocking_stack.append(bytes_to_send)
                        self.nonblocking_stack.append(value)
                        is_one_iter = True

                    if not self.nonblocking:
                        self.soket_send(bytes_to_send)
                        while True:
                            try:
                                file_ = base64.standard_b64encode(
                                    value.read(65535))
                                if file_ == b"":
                                    break
                                self.soket_send(file_)

                            except FileNotFoundError as e:
                                # logger
                                self.logger.error(
                                    "Send file exception: File not found")
                                bytes_to_send = b""
                                break
                            else:
                                is_one_iter = True
                        value.close()

                    if self.nonblocking:
                        self.nonblocking_stack.append(CRLF)

                    if not self.nonblocking:
                        self.soket_send(CRLF)
                if is_one_iter:
                    last_boundary = boundary + b"--" + CRLF
                    if self.nonblocking:
                        self.nonblocking_stack.append(last_boundary)
                    if not self.nonblocking:
                        self.soket_send(last_boundary)

            if "data" in kwargs:
                payload_el = "&".join([k + "=" + v for k, v in
                                       kwargs["data"].items()])
                # self.soket_send(payload_el.encode())
                if self.nonblocking:
                    self.nonblocking_stack.append(payload_el.encode())

                if not self.nonblocking:
                    self.soket_send(payload_el.encode())

    def soket_recv(self, byte, transfer_timeout):
        self.sock.settimeout(self.transfer_timeout)
        response = self.sock.recv(byte)
        self.sock.settimeout(None)
        if response == b"" and not self.is_f_req:
            self.logger.warning("Socket return Zero")
            return (False, response)

        if response == b"" and self.is_f_req:
            self.logger.warning("Socket is fall down")
            raise SocketFallError("Socket is fall down")
            return (False, response)
        self.is_f_req = False
        return (True, response)

    def soket_send(self, q):
        num = self.sock.send(q)
        self.req_line += q
        return num

    def parslink(self, link):
        m_data_link = re.search("https?://([^/]+).*", link, re.DOTALL)
        if ":" in m_data_link.group(1):
            start_host = m_data_link.group(1)
            start_cook_pattern = m_data_link.group(1)

        if ":" not in m_data_link.group(1):
            pat = re.search("(www\.)?(.*)", m_data_link.group(1), re.DOTALL)
            start_host = pat.group()
            start_cook_pattern = pat.group(2)

        url = link
        return (url, start_host, start_cook_pattern)

    def search_headers(self,  all_headers):
        header = {}
        # get out first rows
        all_headers = all_headers[int(re.search(".+?\r\n",
                                                all_headers).span()[1]):]
        # Parsing headers
        summ = ""
        ind = 0
        cookies_list = []
        for i in range(len(all_headers[:-2])):
            summ += all_headers[i]

            if summ.endswith("\r\n"):
                for_dict = re.search("(.+?): (.+)", summ[:-2])
                if for_dict.group(1) == "Set-Cookie":
                    # array of all cookies in Set-Cookie
                    cookies_list.append(for_dict.group(2))
                else:
                    header[for_dict.group(1)] = for_dict.group(2)

                summ = ""
        header["Set-Cookie"] = cookies_list
        return (header, cookies_list)

    def content_length_nonblocking(self):
        self.logger.debug("Conent len mode")
        self.logger.debug("len is: " + str(self.headers["Content-Length"]))
        page_bytes = self.data[self.start_index:]
        if "on_progress" in self.kwargs:
            on_progress = self.kwargs["on_progress"]
            prog_status = on_progress(
                len(page_bytes), int(self.headers["Content-Length"]))
            if not prog_status:
                if (self.max_size is not None and
                        self.max_size < len(page_bytes)):
                    return(True, self.page[0:self.max_size])
                return (True, self.page)

        if int(self.headers["Content-Length"]) <= 0:
            return (True, self.page)

        if int(self.headers["Content-Length"]) > 0:
            if self.firstin:
                if "output" in self.kwargs:
                    with open(self.kwargs["output"], "wb") as fp:
                        if (self.max_size is not None and
                                self.max_size < len(page_bytes)):
                            fp.write(page_bytes[0:self.max_size])
                        else:
                            fp.write(page_bytes)
                self.firstin = False

            if self.max_size is not None and self.max_size < len(page_bytes):
                return(True, page_bytes[0:self.max_size])

            if len(page_bytes) < int(self.headers["Content-Length"]):
                response = self.sock.recv(65536)
                if "output" in self.kwargs:
                    with open(self.kwargs["output"], "ab") as fp:
                        curent_size = os.path.getsize(self.kwargs["output"])
                        if (self.max_size is not None and
                                self.max_size > curent_size):
                            for_file = page_bytes + response
                            fp.write(for_file[curent_size:self.max_size])

                        if self.max_size is None:
                            fp.write(page_bytes[curent_size:])

                self.data += response
                page_bytes = self.data[self.start_index:]
                self.logger.debug("Now is body data: " + str(len(page_bytes)))
                self.logger.debug("content-lenght:" +
                                  str(self.headers["Content-Length"]))

                if len(page_bytes) >= int(self.headers["Content-Length"]):
                    if "output" in self.kwargs:
                        # logger
                        self.logger.info("Download to file is complited.")
                    self.page += self.data[self.start_index:]
                    if (self.max_size is not None and
                            self.max_size < len(page_bytes)):
                        return(True, self.page[0:self.max_size])
                    return (True, self.page)
                return (False, b"")

            if len(page_bytes) >= int(self.headers["Content-Length"]):
                if "output" in self.kwargs:
                    self.logger.info("Download to file is complited.")
                self.page += self.data[self.start_index:]
                if (self.max_size is not None and
                        self.max_size < len(page_bytes)):
                    return(True, self.page[0:self.max_size])
                return (True, self.page)

    def content_length(self, page_bytes,
                       transfer_timeout, kwargs, max_size):
        if int(self.headers["Content-Length"]) > 0:
            if "output" in kwargs:
                with open(kwargs["output"], "wb") as fp:
                    if max_size is not None and max_size < len(page_bytes):
                        fp.write(page_bytes[0:max_size])
                    else:
                        fp.write(page_bytes)

            while True:
                if len(page_bytes) >= int(self.headers["Content-Length"]):
                    if "output" in kwargs:
                        self.logger.info("Download to file is complited.")
                    break

                response = self.soket_recv(65536, transfer_timeout)
                if "output" in kwargs:
                    with open(kwargs["output"], "ab") as fp:
                        curent_size = os.path.getsize(kwargs["output"])
                        if max_size is not None and max_size > curent_size:
                            for_file = page_bytes + response[1]
                            fp.write(for_file[curent_size:max_size])

                        if max_size is None:
                            fp.write(page_bytes[curent_size:])

                if not response[0]:
                    return (False, b"")

                if response[0]:
                    page_bytes += response[1]

                if max_size is not None and max_size < len(page_bytes):
                    self.del_sock()
                    return(True, page_bytes[0:max_size])

                if "on_progress" in kwargs:
                    on_progress = kwargs["on_progress"]
                    prog_status = on_progress(
                        len(page_bytes),
                        int(self.headers["Content-Length"]))
                    if not prog_status:
                        break
        return (True, page_bytes)

    def transfer_encodong_nonblocking(self):
        self.logger.debug("Chunked  mode")
        page_bytes = self.data[self.start_index:]
        self.logger.debug("In loop")
        page_bytes = self.data[self.start_index:]
        if "on_progress" in self.kwargs:
            on_progress = self.kwargs["on_progress"]
            prog_status = on_progress(len(self.page_str), None)
            if not prog_status:
                return (True, self.page_str)

        if len(page_bytes[self.chunked_index:]) < 7:
            response = self.sock.recv(2048)
            page_bytes = self.data[self.start_index:]
            self.data += response

        m_len = re.search(b"(\r\n)?(.+?)\r\n", page_bytes[self.chunked_index:])
        if m_len is None:
            response = self.sock.recv(2048)
            page_bytes = self.data[self.start_index:]
            self.data += response
            return(False, b"")

        self.logger.debug("m-len: " + str(m_len is not None))
        len_len = len(m_len.group())        # len() of LEN  +\r\n
        byte_len = int(m_len.group(2), 16)

        while len(page_bytes[self.chunked_index + len_len:]) < byte_len:
            response = self.sock.recv(byte_len)
            self.data += response
            page_bytes = self.data[self.start_index:]

        from_ = self.chunked_index + len_len
        to_ = self.chunked_index + len_len + byte_len
        this_page = page_bytes[from_: to_]
        self.page_str += this_page

        # Navigates to the next iteration
        self.chunked_index += len_len + byte_len
        if "output" in self.kwargs:
            if not self.firstin:
                if self.max_size is None:
                    with open(self.kwargs["output"], "ab") as fp:
                        fp.write(this_page)

                if self.max_size is not None:
                    path = self.kwargs["output"]
                    file_size = os.path.getsize(path)
                    with open(self.kwargs["output"], "ab") as fp:
                        if file_size + len(this_page) < self.max_size:
                            fp.write(this_page)

                        else:
                            part_this_page = self.max_size - file_size
                            fp.write(this_page[0:part_this_page])
                            byte_len = 0

            if self.firstin:
                if "output" in self.kwargs:
                    with open(self.kwargs["output"], "wb") as fp:
                        fp.write(page_bytes)
                self.firstin = False

        if self.max_size is not None:
            if len(self.page_str) > int(self.max_size):
                return (True, self.page_str[0: self.max_size])

        if byte_len == 0:
            return (True, self.page_str)

        if byte_len != 0:
            return (False, b"")

    def transfer_encodong(self, page_bytes,
                          transfer_timeout, kwargs, max_size):
        byte_len = 100
        start_page_index = 0
        page_str = b""
        page_bytes += self.soket_recv(2048, transfer_timeout)[1]
        pattern = re.search(b"(\w+?)\r\n", page_bytes).group(1)

        if "output" in kwargs:
            with open(kwargs["output"], "wb") as fp:
                fp.write(page_bytes)

        if pattern.decode() == "0":
            byte_len = 0
        while byte_len != 0:
            if "on_progress" in kwargs:
                on_progress = kwargs["on_progress"]
                prog_status = on_progress(len(page_str), None)
                if not prog_status:
                    return (True, page_str)

            if len(page_bytes[start_page_index:]) < 7:
                response = self.soket_recv(2048, transfer_timeout)
                if response[0]:
                    page_bytes += response[1]
                if not response[0]:
                    return (False, b"")

            m_len = re.search(b"(\r\n)?(.+?)\r\n",
                              page_bytes[start_page_index:])

            if m_len is None:
                response = self.soket_recv(2048, transfer_timeout)
                if response[0]:
                    page_bytes += response[1]
                if not response[0]:
                    return (False, b"")
                continue

            len_len = len(m_len.group())        # len() of LEN  +\r\n
            byte_len = int(m_len.group(2), 16)
            while len(page_bytes[start_page_index + len_len:]) < byte_len:
                response = self.soket_recv(byte_len, transfer_timeout)
                if response[0]:
                    page_bytes += response[1]
                if not response[0]:
                    return (False, b"")

            from_ = start_page_index + len_len
            to_ = start_page_index + len_len + byte_len
            this_page = page_bytes[from_: to_]
            page_str += this_page
            # Navigates to the next iteration
            start_page_index += len_len + byte_len
            if "output" in kwargs:
                if max_size is None:
                    with open(kwargs["output"], "ab") as fp:
                        fp.write(this_page)

                if max_size is not None:
                    path = kwargs["output"]
                    file_size = os.path.getsize(path)
                    with open(kwargs["output"], "ab") as fp:
                        if file_size + len(this_page) < max_size:
                            fp.write(this_page)

                        else:
                            part_this_page = max_size - file_size
                            fp.write(this_page[0:part_this_page])
                            break

            if max_size is not None:
                if len(page_str) >= max_size:
                    break

        if max_size is None:
            page = page_str

        if max_size is not None:
            new_page_str = page_str[0: max_size]
            page = new_page_str

        return (True, page)

    def connection_close_nonblocking(self):
        response = self.sock.recv(65536)
        self.data += response
        page_bytes = self.data[self.start_index:]
        if "on_progress" in self.kwargs:
            on_progress = self.kwargs["on_progress"]
            prog_status = on_progress(len(page_bytes), None)
            if not prog_status:
                self.page += self.data[self.start_index:]
            return (True, self.page)

        if not self.firstin:
            if "output" in self.kwargs:
                with open(self.kwargs["output"], "ab") as fp:
                    fp.write(response)

        if self.firstin:
            if "output" in self.kwargs:
                with open(self.kwargs["output"], "wb") as fp:
                    fp.write(page_bytes)
            self.firstin = False

        if self.max_size is not None:
            if len(page_bytes) <= self.max_size:
                return (True, page_bytes[:self.max_size])

        endof = re.search(b"</html>", page_bytes)
        if endof is not None:
            self.page += self.data[self.start_index:]
            return (True, self.page)
        else:
            return (False, b"")

    def connection_close(self, page_bytes,
                         transfer_timeout, kwargs, max_size):
        if "output" in kwargs:
            start_page_index = len(page_bytes)
            with open(kwargs["output"], "wb") as fp:
                fp.write(page_bytes)
        if "on_progress" in kwargs:
            on_progress = kwargs["on_progress"]
            prog_status = on_progress(len(page_bytes),
                                      int(self.headers["Content-Length"]))
            if not prog_status:
                if self.encoding is None:
                    return (True, b"")
                return (True, page_bytes)

        while True:
            if "on_progress" in kwargs:
                on_progress = kwargs["on_progress"]
                prog_status = on_progress(len(page_bytes),
                                          int(self.headers["Content-Length"]))
                if not prog_status:
                    return (True, page_bytes)

            response = self.soket_recv(65536, transfer_timeout)
            page_bytes += response[1]
            if "output" in kwargs:
                with open(kwargs["output"], "ab") as fp:
                    fp.write(page_bytes[start_page_index:])
                start_page_index = len(page_bytes)

            if max_size is not None:
                if len(page_bytes) <= max_size:
                    self.del_sock()
                    return (True, page_bytes[:max_size])

            endof = re.search(b"</html>", response[1])
            if endof is not None:
                return (True, page_bytes)

            if not response[0]:
                return (True, page_bytes)

    def load_cookies(self, directory):
        if self.load_cookie is not None:
            try:
                with open(directory, "r", encoding='utf-8') as fp:
                    file = fp.read()
            except FileNotFoundError as e:
                self.logger.info("Coockie's file not found")
                return {}
            else:
                return json.loads(file)
        else:
            return {}

    def write_cookies(self, cook_dick, directory):
        if self.save_cookie is not None:
            cookies_json = json.dumps(cook_dick, separators=(',', ':'))
            with open(directory, "w", encoding='utf-8') as fp:
                fp.write(cookies_json)

    def cookies_constr(self, cook_arr, link, start_cook_pattern):
        for small_dick in self.cook_dick.keys():
            in_cook_dick = re.search(start_cook_pattern + "$", small_dick)
            if in_cook_dick is not None:
                cookies_url = self.status_200_300(link, cook_arr)
                return cookies_url[0]
                break
        return "; ".join([k + "=" + v for k, v in cook_arr.items()])

    def sendnonblock(self):
        try:
            if type(self.nonblocking_stack[self.send_stack_index]) is bytes:
                num = self.soket_send(
                    self.nonblocking_stack[
                        self.send_stack_index][self.send_byte_index:])
                self.send_byte_index += num
                if self.send_byte_index == len(
                        self.nonblocking_stack[self.send_stack_index]):
                    self.send_stack_index += 1
                    self.send_byte_index = 0
                    self.nonblocking_stack[self.send_stack_index]
                    return False
                else:
                    return False

            elif (type(self.nonblocking_stack[self.send_stack_index])
                  is io.TextIOWrapper or
                  type(self.nonblocking_stack[self.send_stack_index])
                  is io.BufferedReader):

                try:
                    if self.file_lock:
                        self.send_byte_index = 0
                        self.file_ = base64.standard_b64encode(
                            self.nonblocking_stack[self.send_stack_index].read(
                                65535))
                        self.file_lock = False

                    num = self.soket_send(self.file_[self.send_byte_index:])
                    self.send_byte_index += num
                except FileNotFoundError as e:
                    self.logger.error("Send file exception: File not found")
                    return False

                else:
                    if self.file_ == b"":
                        self.nonblocking_stack[self.send_stack_index].close()
                        self.send_stack_index += 1
                        self.send_byte_index = 0
                        self.file_ = b""

                    if len(self.file_) == self.send_byte_index:
                        self.file_lock = True
                    return False

        except IndexError as e:
            self.logger.debug("all data send")
            if self.proxy is None:
                self.host_ip_dic[self.host] = self.sock.getpeername()[0]
            return True

    def zeroing(self, status):
        self.isgetipfromhost = False
        self.isconnect = False
        self.issend = False
        self.isrecv = False
        self.isheaders = False
        self.firstin = True
        self.send_stack_index = 0
        self.send_byte_index = 0
        self.data = b""
        if self.status_code[0] == "3":
            cookies_url = self.status_200_300(self.headers["Location"], {})
            self.url_previos = self.url    # url for Referrer
            self.url = cookies_url[1]    # URL for next step
            # COOKIE for next step
            self.cookies = cookies_url[0]
            self.host = cookies_url[2]  # Host for next step
        return status

    def recvnonblock(self):
        try:
            if not self.isheaders:
                self.data += self.sock.recv(65536)
                self.logger.debug("recv 65536")
                status = re.search(b"HTTP.*? (\d+) ", self.data[:16])
                if status is None:
                    self.logger.error("Critical ERROR: No status code!")
                    if self.raise_on_error:
                        raise HttpErrors(400)
                    return "error"
                self.status_code = status.group(1).decode()
                self.logger.debug("status code: " + str(self.status_code))
                m_headers = re.search(b".+?\r\n\r\n", self.data, re.DOTALL)
                if m_headers is None:
                    if len(self.data) > 16:
                        if self.raise_on_error:
                            raise HttpErrors(400)
                        return "error"
                    else:
                        return "continue"

                if m_headers is not None:
                    all_headers = m_headers.group().decode("ascii")
                    headers_and_startindex = self.search_headers(
                        all_headers)
                    # start index of message body
                    self.start_index = m_headers.span()[1]
                    cookies_list = headers_and_startindex[1]
                    self.headers = headers_and_startindex[0]

                self.encoding = None
                if "Content-Type" in self.headers:
                    charset = re.search("charset=(.*);?",
                                        self.headers["Content-Type"])

                    if charset is not None:
                        self.encoding = charset.group(1)
                # cookies_list string with cookies (not parsing).
                self.cookies_parsing_funk(cookies_list, self.host)

                if "on_headers" in self.kwargs:
                    on_headers = self.kwargs["on_headers"](self.headers)
                    if not on_headers:
                        self.logger.info("on_headers is drop download ...")
                        return "ok"

                if status is not None:
                    if self.status_code[0] == "5":
                        self.del_sock()
                        self.logger.error(
                            "You have 5-th ERROR of 5xx http response")
                        if self.raise_on_error:
                            raise HttpErrors(self.status_code)
                        self.retry_index += 1
                        if (self.retry_index >= self.retry):
                            return "ok"
                        time.sleep(self.retry_delay)
                        return self.zeroing("continue")

                    if self.status_code[0] == "4":
                        self.logger.error(
                            "You have 4-th ERROR of 4xx http response")
                        self.logger.info("Enter correct informations")
                        if self.raise_on_error:
                            raise HttpErrors(self.status_code)
                        return "error"

                    if (self.type_req == "DELETE" and
                            self.status_code[0] == "3"):
                        self.logger.error(
                            "You have 3-th ERROR of 3xx http response")
                        self.logger.info(
                            "for DELETE method Enter correct informations")
                        if self.raise_on_error:
                            raise HttpErrors(400)
                        return "error"

                    if self.status_code[0] == "3":
                        if "Location" in self.headers:
                            if self.raise_on_error:
                                raise HttpErrors(self.status_code)
                            self.isgetipfromhost = False
                            self.isconnect = False
                            self.issend = False
                            self.isrecv = False
                            self.isheaders = False
                            self.firstin = True
                            self.send_stack_index = 0
                            self.send_byte_index = 0
                            self.data = b""

                            cookies_url = self.status_200_300(
                                self.headers["Location"], {})
                            self.url_previos = self.url    # url for Referrer
                            self.url = cookies_url[1]    # URL for next step
                            # COOKIE for next step
                            self.cookies = cookies_url[0]
                            self.host = cookies_url[2]  # Host for next step
                            self.redirect_counter += 1
                            if self.status_code != "307":
                                self.type_req = "GET"
                            if self.redirect_counter >= self.max_redir:
                                return "ok"
                            return self.zeroing("error")
                        else:
                            self.logger.error("Bad Request: 400")
                            if self.raise_on_error:
                                raise HttpErrors(400)
                            return "error"
                    self.isheaders = True

            if self.isheaders and not self.isbody:
                if self.type_req == "HEAD":
                    self.isbody = True

                if not self.type_req == "HEAD":
                    if "Content-Length" in self.headers:
                        self.logger.debug("Type of download: Content-Length")
                        response, self.body = self.content_length_nonblocking()
                        if response:
                            self.logger.debug("Content Len: OK")
                            self.isbody = True
                            return "ok"

                        if not response:
                            self.logger.debug(
                                "Content Len: we need more iter...")
                            return "continue"

                    if "Transfer-Encoding" in self.headers:
                        self.logger.debug(
                            "Type of download: Transfer-Encoding")
                        try:
                            answer = self.transfer_encodong_nonblocking()
                            response, self.body = answer
                        except BlockingIOError as e:
                            self.logger.debug("Transfer-Encoding ERROR")
                            raise e

                        else:
                            if response:
                                self.logger.debug("Transfer-Encoding: OK")
                                self.isbody = True
                                return "ok"

                            if not response:
                                self.logger.debug(
                                    "Transfer-Encoding: we need more iter...")
                                return "continue"

                    if ("Transfer-Encoding" not in self.headers and
                            "Content-Length" not in self.headers):
                        self.logger.debug("Type of download: Connection_close")
                        answer = self.connection_close_nonblocking()
                        response, self.body = answer
                        if response:
                            self.logger.debug("Conection close: OK")
                            self.isbody = True
                            return "ok"

                        if not response:
                            self.logger.debug(
                                "Conection close: we need more iter...")
                            return "continue"
            if self.isbody:
                return "ok"

        except BlockingIOError as e:
            raise e

        else:
            if self.isbody:
                return "ok"
            else:
                self.logger.debug("continue ...")
                return "continue"

    def isready(self):
        """
        For nonblocking mode
        need to check the status of preparedness request
        """
        try:
            if not self.isgetipfromhost and not self.isrecv:
                if ":" in self.host:
                    n_host = self.host.split(":")
                    self.host_ip_dic[str(self.host)] = n_host[1]
                    self.isgetipfromhost = True

                elif str(self.host) not in self.host_ip_dic:
                    self.logger.info("Take ip from host  " + str(self.host))
                    ip = None
                    ip = socket.gethostbyname(str(self.host))
                    if ip:
                        self.host_ip_dic[str(self.host)] = ip
                        self.isgetipfromhost = True
                    else:
                        self.logger.critical("Connection to dns: ERROR")
                        self.isgetipfromhost = False
                else:
                    self.isgetipfromhost = True

            if (self.isgetipfromhost and not
                    self.isconnect and not self.isrecv):

                self.logger.debug("Connect mode " + str(self.host))
                response = self.connect(
                    url=self.url,
                    kwargs=self.kwargs,
                    headers_all=self.headers_all,
                    url_previos=self.url_previos,
                    type_req=self.type_req,
                    bytes_to_send=self.bytes_to_send,
                    transfer_timeout=self.transfer_timeout)

                # Connection to socket is OK
                if response[0]:
                    self.logger.debug("Connection to socket is OK")
                    self.logger.info(
                        str(round(time.time() - self.start_time, 3)) +
                        "   time connection " + self.host)
                    result = response[1]
                    request_str = response[2]
                    self.isconnect = True
                    self.soket_funk(self.url, self.kwargs, self.headers_all,
                                    self.url_previos, self.type_req,
                                    self.bytes_to_send)

                # Connection to socket: ERROR
                if not response[0]:
                    self.logger.critical("Connection to socket: ERROR")
                    self.isconnect = False

            if (self.isgetipfromhost and
                    self.isconnect and not
                    self.issend and not self.isrecv):
                self.logger.debug("Send mode ...")
                issend = self.sendnonblock()
                if issend:
                    self.issend = True
                    self.isheaders = False
                    self.isbody = False
                    self.logger.debug("Issend True")
                else:
                    self.issend = False

            if (self.isgetipfromhost and self.isconnect and
                    self.issend and not self.isrecv):
                describe = self.recvnonblock()
                if describe in ["ok", "error"]:
                    self.logger.debug("isrecv: " + describe + " go to exit")
                    self.logger.info(
                        str(round(time.time() - self.start_time, 3)) +
                        "  time to recv " + self.host)
                    self.isrecv = True
                else:
                    self.isrecv = False

            if self.isrecv:
                return True
        except socket.timeout as e:
            err = e.args[0]
            if err == 'timed out':
                time.sleep(0.02)
                self.logger.info('recv timed out, retry later')
                return False

            else:
                self.logger.error(str(e))
                return False

        except socket.gaierror as e:
            # wrong link
            self.logger.info(self.url)
            self.logger.error("Gai error: " + str(e.errno))
            self.isrecv = True
            self.issend = True
            self.isconnect = True
            self.isgetipfromhost = True
            return True

        except BlockingIOError as e:
            # [Errno 11] Resource temporarily unavailable
            if self.isrecv:
                self.logger.info(self.url)
                self.logger.info("All data is here")
                return True
            else:
                # self.logger.info("BlockingIOError")
                return False

        except SocketFallError as e:
            self.logger.error('SocketFallError, reload socket ...')
            self.del_sock()
            self.socket_fall_counter += 1
            time.sleep(1)
            if self.socket_fall_counter > 5:
                self.logger.error(
                    'something wrong with internet connection. Try later')
                return True
            return False

        else:
            if self.isrecv:
                self.logger.info("isready() : Isrecv TRUE")
                return True
            else:
                return False

    def structure(self, url, kwargs, headers_all, url_previos, type_req,
                  bytes_to_send, transfer_timeout, redirect_counter,
                  max_redir, max_size, retry):
        # Start structure
        while True:
            try:
                self.status_code = ""
                self.headers = {}
                self.encoding = ""
                self.body = b""
                page = b""  # Variable which will be returnes(BYTES)
                start_index = None  # Startindex of message body
                response = self.connect(url, kwargs, headers_all, url_previos,
                                        type_req, bytes_to_send,
                                        transfer_timeout)
                if response[0]:
                    self.logger.info("Connection to socket is OK")
                    result = response[1]
                    request_str = response[2]

                if not response[0]:
                    self.logger.critical("Connection to socket: ERROR")
                    return self

                num = self.soket_funk(url, kwargs, headers_all,
                                      url_previos, type_req,
                                      bytes_to_send)

                result = self.soket_recv(16, transfer_timeout)
                first_str = result[1].decode("ascii")
                status = re.search("HTTP.*? (\d+) .*?", first_str)
                if status is None:
                    self.logger.error(first_str)
                    self.logger.error("Critical ERROR: No status code!")
                    if self.raise_on_error:
                        raise HttpErrors(400)
                    return self
                self.status_code = status.group(1)
                if status is not None:
                    this_stack_bytes = result[1]
                    while True:
                        response = self.soket_recv(4096, transfer_timeout)
                        if response[0]:
                            this_stack_bytes += response[1]
                        if not response[0]:
                            self.logger.error("ERROR: First 4096 byte error")
                            break
                        m_headers = re.search(b".+?\r\n\r\n",
                                              this_stack_bytes, re.DOTALL)

                        if m_headers is not None:
                            break
                    all_headers = m_headers.group().decode("ascii")
                    headers_and_startindex = self.search_headers(all_headers)
                    # start index of message body
                    start_index = m_headers.span()[1]
                    cookies_list = headers_and_startindex[1]
                    self.headers = headers_and_startindex[0]
                    self.encoding = None
                    if "Content-Type" in self.headers:
                        charset = re.search("charset=(.*);?",
                                            self.headers["Content-Type"])

                        if charset is not None:
                            self.encoding = charset.group(1)
                    # cookies_list string with cookies (not parsinf).
                    self.cookies_parsing_funk(cookies_list, self.host)
                    if "on_headers" in kwargs:
                        on_headers = kwargs["on_headers"](self.headers)
                        if not on_headers:
                            self.logger.info("on_headers is drop download ...")
                            return self

                    if self.status_code[0] == "5":
                        self.del_sock()
                        self.logger.error(
                            "You have 5-th ERROR of 5xx http response")
                        if self.raise_on_error:
                            raise HttpErrors(self.status_code)
                        self.retry_index += 1
                        if (self.retry_index >= retry):
                            return self
                        time.sleep(self.retry_delay)

                    if self.status_code[0] == "4":
                        self.del_sock()
                        self.logger.error("You have 4-th ERROR")
                        if self.raise_on_error:
                            raise HttpErrors(self.status_code)
                        return self

                    if self.status_code[0] in ["2", "3"]:
                        if type_req == "DELETE" and self.status_code[0] == "3":
                            self.logger.error(
                                "You have 3-th ERROR of 3xx http response")
                            self.logger.info(
                                "for DELETE method Enter correct informations")
                            break

                        if not type_req == "HEAD":
                            self.response_str = this_stack_bytes[:start_index]
                            # Content-Length
                            if "Content-Length" in self.headers:
                                self.logger.info(
                                    "Type of download: Content-Length")
                                response = self.content_length(
                                    page_bytes=this_stack_bytes[start_index:],
                                    transfer_timeout=transfer_timeout,
                                    kwargs=kwargs,
                                    max_size=max_size)

                                if response[0]:
                                    self.logger.info("Content Len: OK")
                                    page += response[1]
                                if not response[0]:
                                    self.logger.error("Content Len: ERROR")
                                    break
                                self.body = page

                            if "Transfer-Encoding" in self.headers:
                                self.logger.info(
                                    "Type of download: Transfer-Encoding")
                                response = self.transfer_encodong(
                                    page_bytes=this_stack_bytes[start_index:],
                                    transfer_timeout=transfer_timeout,
                                    kwargs=kwargs,
                                    max_size=max_size)

                                if response[0]:
                                    self.logger.info("Chanked: OK")
                                    page += response[1]
                                if not response[0]:
                                    self.logger.error("Chanked: ERROR")
                                    break
                                self.body = page

                            # Conection Closed
                            if ("Transfer-Encoding" not in self.headers and
                                    "Content-Length" not in self.headers):
                                # logger
                                self.logger.info(
                                    "Type of download: Connection_close")
                                response = self.connection_close(
                                    page_bytes=this_stack_bytes[start_index:],
                                    transfer_timeout=transfer_timeout,
                                    kwargs=kwargs,
                                    max_size=max_size)

                                if response[0]:
                                    self.logger.info("Conection close: OK")
                                    page += response[1]
                                    self.del_sock()
                                if not response[0]:
                                    self.logger.error("Conection close: ERROR")
                                    break
                                self.body = page

                        # With domain allocates part .example.xxx
                        # and correlate it to link transition.
                        # And extracts the cookie for this domain.
                        # In case nothing matches pond
                        if self.status_code == "2":
                            self.logger.info("Status code: 2xx")
                            self.logger.info("GO TO >>>>>>>>>>> EXIT")

                        if self.status_code[0] == "3":
                            if "Location" in self.headers:
                                self.logger.info("Status code: " +
                                                 str(self.status_code))
                                self.logger.info("REDIRECT TO >>>" +
                                                 str(self.headers["Location"]))

                                cookies_url = self.status_200_300(
                                    self.headers["Location"], {})
                                url_previos = url       # url for Referrer
                                url = cookies_url[1]    # URL for next step
                                # COOKIE for next step
                                self.cookies = cookies_url[0]
                                # Host for next step
                                self.host = cookies_url[2]
                                if self.status_code != "307":
                                    type_req = "GET"
                                self.del_sock()
                                if self.raise_on_error:
                                    raise HttpErrors(self.status_code)
                            else:
                                self.logger.info("Status code: 400")

                        self.page_status_list.append(self.status_code)
                        if self.history_body:
                            self.history.append({"headers": self.headers,
                                                 "body": self.page})
                        if (not self.history_body or
                                self.history_body is None):
                            self.history.append({"headers": self.headers,
                                                 "body": ""})

                # Delete and Close Soсket if index smaller that in settings
                for k, v in self.soket_dic.items():
                    if v["index"] > self.keep_alive:
                        v['socket'].close()

                self.soket_dic = ({key: value for key, value
                                   in self.soket_dic.items()
                                   if value["index"] <= self.keep_alive})

                # END
                if 1 <= len(self.page_status_list):
                    if self.page_status_list[-1] == "200":
                        self.write_cookies(self.cook_dick, self.save_cookie)
                        return self
                        break

                # Counter of redirext
                redirect_counter += 1
                self.redirect_counter = redirect_counter
                if redirect_counter >= max_redir:
                    return self

            except SocketFallError as e:
                self.logger.error('SocketFallError, reload socket ...')
                self.del_sock()
                self.socket_fall_counter += 1
                time.sleep(1)
                if self.socket_fall_counter > 5:
                    self.logger.error(
                        'something wrong with internet connection. Try later')
                    break
                continue

            except ConnectionError as e:
                self.logger.error('ConnectionError: ' + str(e.args))
                self.del_sock()
                return self

            except socket.timeout as e:
                self.sock.close()
                self.soket_dic.pop(self.host)
                self.logger.error('TimeoutError: ' + str(e.args[0]))
                return self

            except BlockingIOError as e:
                self.logger.error("Resource temporarily unavailable")
                return self

            except OSError as e:
                self.logger.error(
                    'OSError ' + str(e.errno) + " " + os.strerror(e.errno))
                self.del_sock()
                return self

    def get(self, link, **kwargs):
        """GET http request.

           Request for take data on some link.

           Args:
                1) headers; 2) cookies 3) max_redir 4)transfer_timeout
                5) max_size 6) auth 7) output 8) history_body
                9) proxy 10) proxy_auth 11) retry 12) on_progress

           Returns:
                status code: HTTP code of the request
                encoding: Represents a character encoding.
                headers: Dickt of reaponse headers
                body: message body
                history: list of redirect history

        """
        self.logger.debug("Try to connect: " + str(link))
        self.is_f_req = True
        bytes_to_send = None
        url_previos = ""
        redirect_counter = 0
        self.retry_index = 0
        self.raise_on_error = False
        payload_el = ""
        headers_all = dict(self.headers_for_request)
        if "params" in kwargs:
            payload_dick = {}
            for key, value in kwargs["params"].items():
                value = "+".join(re.split(" ", value))
                payload_dick[key] = value

            payload_el = "?" + "&".join(
                [k + "=" + v for k, v in payload_dick.items()])

        if "raise_on_error" in kwargs:
            self.raise_on_error = kwargs["raise_on_error"]

        if "headers" in kwargs:
            headers_all.update(kwargs["headers"])

        max_redir = self.max_redirects
        if "max_redirects" in kwargs:
            max_redir = kwargs["max_redirects"]

        transfer_timeout = self.transfer_timeout
        if "transfer_timeout" in kwargs:
            transfer_timeout = kwargs["transfer_timeout"]

        max_size = self.max_size
        if "max_size" in kwargs:
            max_size = kwargs["max_size"]

        if "auth" in kwargs:
            self.auth = kwargs["auth"]

        if "output" in kwargs:
            self.output = kwargs["output"]

        self.history_body = None
        if "history_body" in kwargs:
            self.history_body = kwargs["history_body"]

        self.proxy = None
        if "proxy" in kwargs:
            self.proxy = kwargs["proxy"]

        self.proxy_auth = None
        if "proxy_auth" in kwargs:
            self.proxy_auth = kwargs["proxy_auth"]

        retry = self.retry
        if "retry" in kwargs:
            retry = kwargs["retry"]

        if "nonblocking" in kwargs:
            self.nonblocking = kwargs["nonblocking"]

        # Take from link: Host, Cookies pattern
        link_el = self.parslink(link)
        url = link_el[0] + payload_el
        self.host = link_el[1]
        start_cook_pattern = link_el[2]

        # Fiend Cookies for Request
        self.cook_dick = self.load_cookies(self.load_cookie)
        cook_arr = {}
        if "cookie" in kwargs:
            cook_arr = kwargs["cookie"]
        self.cookies = self.cookies_constr(
            cook_arr=cook_arr,
            link=link,
            start_cook_pattern=start_cook_pattern)

        if self.nonblocking:
            class getHttpClient(HttpClient):

                def __init__(self):
                    super(getHttpClient, self).__init__()

            children = getHttpClient()
            children.host = self.host
            children.cook_dick = self.cook_dick
            children.cookies = self.cookies
            children.url = url

            children.kwargs = kwargs
            children.headers_all = headers_all
            children.url_previos = url_previos
            children.type_req = "GET"
            children.bytes_to_send = bytes_to_send
            children.transfer_timeout = transfer_timeout
            children.redirect_counter = redirect_counter
            children.max_redir = max_redir
            children.max_size = max_size
            children.retry = retry
            children.logger = self.logger
            children.auth = self.auth
            children.proxy = self.proxy
            children.proxy_auth = self.proxy_auth
            children.raise_on_error = self.raise_on_error
            children.file_ = b""

            children.data = b""
            children.nonblocking = True
            children.isconnect = False
            children.issend = False

            children.isheaders = False
            children.isbody = False
            children.isrecv = False
            children.host_ip_dic = self.host_ip_dic
            return children

        if not self.nonblocking:
            return self.structure(
                url=url,
                kwargs=kwargs,
                headers_all=headers_all,
                url_previos=url_previos,
                type_req="GET",
                bytes_to_send=bytes_to_send,
                transfer_timeout=transfer_timeout,
                redirect_counter=redirect_counter,
                max_redir=max_redir,
                max_size=max_size,
                retry=retry)

    def post(self, link, **kwargs):
        """POST http request.

           Request for take data on some link.

           Args:
                1) headers; 2) cookies 3) max_redir 4)transfer_timeout
                5) max_size 6) auth 7) output 8) history_body
                9) proxy 10) proxy_auth 11) retry 12) data or file

           Returns:
                status code: HTTP code of the request
                encoding: Represents a character encoding.
                headers: Dickt of reaponse headers
                body: message body
                history: list of redirect history
        """
        self.logger.info("Try to connect: " + str(link))
        self.is_f_req = True
        url_previos = ""
        redirect_counter = 0
        self.retry_index = 0
        self.raise_on_error = False
        self.cook_dick = self.load_cookies(self.load_cookie)
        headers_all = dict(self.headers_for_request)
        bytes_to_send = None

        if "headers" in kwargs:
            headers_all.update(kwargs["headers"])

        max_redir = self.max_redirects
        if "max_redirects" in kwargs:
            max_redir = kwargs["max_redirects"]

        transfer_timeout = self.transfer_timeout
        if "transfer_timeout" in kwargs:
            transfer_timeout = kwargs["transfer_timeout"]

        max_size = self.max_size
        if "max_size" in kwargs:
            max_size = kwargs["max_size"]

        if "output" in kwargs:
            self.output = kwargs["output"]

        self.history_body = None
        if "history_body" in kwargs:
            self.history_body = kwargs["history_body"]

        if "auth" in kwargs:
            self.auth = kwargs["auth"]

        self.proxy = None
        if "proxy" in kwargs:
            self.proxy = kwargs["proxy"]

        self.proxy_auth = None
        if "proxy_auth" in kwargs:
            self.proxy_auth = kwargs["proxy_auth"]

        retry = self.retry
        if "retry" in kwargs:
            retry = kwargs["retry"]

        if "nonblocking" in kwargs:
            self.nonblocking = kwargs["nonblocking"]

        # Take from link: Host, Cookies pattern
        link_el = self.parslink(link)
        url = link_el[0]
        self.host = link_el[1]
        start_cook_pattern = link_el[2]

        # Fiend Cookies for Request
        self.cook_dick = self.load_cookies(self.load_cookie)
        cook_arr = {}
        if "cookie" in kwargs:
            cook_arr = kwargs["cookie"]
        self.cookies = self.cookies_constr(
            cook_arr=cook_arr,
            link=link,
            start_cook_pattern=start_cook_pattern)

        if self.nonblocking:
            class getHttpClient(HttpClient):

                def __init__(self):
                    super(getHttpClient, self).__init__()

            children = getHttpClient()
            children.host = self.host
            children.cook_dick = self.cook_dick
            children.cookies = self.cookies
            children.url = url

            children.kwargs = kwargs
            children.headers_all = headers_all
            children.url_previos = url_previos
            children.type_req = "POST"
            children.bytes_to_send = bytes_to_send
            children.transfer_timeout = transfer_timeout
            children.redirect_counter = redirect_counter
            children.max_redir = max_redir
            children.max_size = max_size
            children.retry = retry
            children.logger = self.logger
            children.auth = self.auth
            children.proxy = self.proxy
            children.proxy_auth = self.proxy_auth
            children.raise_on_error = self.raise_on_error
            children.file_ = b""
            children.file_lock = True

            children.data = b""
            children.nonblocking = True
            children.isconnect = False
            children.issend = False

            children.isheaders = False
            children.isbody = False
            children.isrecv = False
            children.host_ip_dic = self.host_ip_dic
            return children

        if not self.nonblocking:
            return self.structure(
                url=url,
                kwargs=kwargs,
                headers_all=headers_all,
                url_previos=url_previos,
                type_req="POST",
                bytes_to_send=bytes_to_send,
                transfer_timeout=transfer_timeout,
                redirect_counter=redirect_counter,
                max_redir=max_redir,
                max_size=max_size,
                retry=retry)

    def put(self, link, **kwargs):
        """PUT http request.

           Request for take data on some link.

           Args:
                1) headers; 2) cookies 3) max_redir 4)transfer_timeout
                5) max_size 6) auth 7) output 8) history_body
                9) proxy 10) proxy_auth 11) retry 12) data or file

           Returns:
                status code: HTTP code of the request
                encoding: Represents a character encoding.
                headers: Dickt of reaponse headers
                body: message body
                history: list of redirect history
        """
        self.logger.info("Try to connect: " + str(link))
        self.is_f_req = True
        url_previos = ""
        redirect_counter = 0
        self.retry_index = 0
        self.raise_on_error = False
        self.cook_dick = self.load_cookies(self.load_cookie)
        headers_all = dict(self.headers_for_request)
        bytes_to_send = None
        CRLF = b"\r\n"
        if "headers" in kwargs:
            headers_all.update(kwargs["headers"])

        transfer_timeout = self.transfer_timeout
        if "transfer_timeout" in kwargs:
            transfer_timeout = kwargs["transfer_timeout"]

        max_size = self.max_size
        if "max_size" in kwargs:
            max_size = kwargs["max_size"]

        max_redir = self.max_redirects
        if "max_redirects" in kwargs:
            max_redir = kwargs["max_redirects"]

        if "output" in kwargs:
            self.output = kwargs["output"]

        self.history_body = None
        if "history_body" in kwargs:
            self.history_body = kwargs["history_body"]

        if "auth" in kwargs:
            self.auth = kwargs["auth"]

        self.proxy = None
        if "proxy" in kwargs:
            self.proxy = kwargs["proxy"]

        self.proxy_auth = None
        if "proxy_auth" in kwargs:
            self.proxy_auth = kwargs["proxy_auth"]

        retry = self.retry
        if "retry" in kwargs:
            retry = kwargs["retry"]

        # Take from link: Host, Cookies pattern
        link_el = self.parslink(link)
        url = link_el[0]
        self.host = link_el[1]
        start_cook_pattern = link_el[2]

        # Fiemd Cookies for Request
        self.cook_dick = self.load_cookies(self.load_cookie)
        cook_arr = {}
        if "cookie" in kwargs:
            cook_arr = kwargs["cookie"]
        self.cookies = self.cookies_constr(
            cook_arr=cook_arr,
            link=link,
            start_cook_pattern=start_cook_pattern)

        if self.nonblocking:
            class getHttpClient(HttpClient):

                def __init__(self):
                    super(getHttpClient, self).__init__()

            children = getHttpClient()
            children.host = self.host
            children.cook_dick = self.cook_dick
            children.cookies = self.cookies
            children.url = url

            children.kwargs = kwargs
            children.headers_all = headers_all
            children.url_previos = url_previos
            children.type_req = "PUT"
            children.bytes_to_send = bytes_to_send
            children.transfer_timeout = transfer_timeout
            children.redirect_counter = redirect_counter
            children.max_redir = max_redir
            children.max_size = max_size
            children.retry = retry
            children.logger = self.logger
            children.auth = self.auth
            children.proxy = self.proxy
            children.proxy_auth = self.proxy_auth
            children.raise_on_error = self.raise_on_error
            children.file_ = b""
            children.file_lock = True

            children.data = b""
            children.nonblocking = True
            children.isconnect = False
            children.issend = False

            children.isheaders = False
            children.isbody = False
            children.isrecv = False
            children.host_ip_dic = self.host_ip_dic
            return children

        if not self.nonblocking:
            return self.structure(
                url=url,
                kwargs=kwargs,
                headers_all=headers_all,
                url_previos=url_previos,
                type_req="PUT",
                bytes_to_send=bytes_to_send,
                transfer_timeout=transfer_timeout,
                redirect_counter=redirect_counter,
                max_redir=max_redir,
                max_size=max_size,
                retry=retry)

    def delete(self, link, **kwargs):
        """DELETE http request.

           Request for delete data on some link.

           Args:
                1) headers; 2) cookies 3) max_redir 4)transfer_timeout
                5) max_size 6) auth 7) output 8) history_body
                9) proxy 10) proxy_auth 11) retry

           Returns:
                status code: HTTP code of the request
                encoding: Represents a character encoding.
                headers: Dickt of reaponse headers
                body: message body
                history: list of redirect history
        """
        self.logger.info("Try to connect: " + str(link))
        self.is_f_req = True
        url_previos = ""
        redirect_counter = 0
        self.retry_index = 0
        self.cook_dick = self.load_cookies(self.load_cookie)
        headers_all = dict(self.headers_for_request)
        bytes_to_send = None
        payload_el = ""
        if "params" in kwargs:
            payload_dick = {}
            for key, value in kwargs["params"].items():
                value = "+".join(re.split(" ", value))
                payload_dick[key] = value

            payload_el = "?" + "&".join(
                [k + "=" + v for k, v in payload_dick.items()])

        if "headers" in kwargs:
            headers_all.update(kwargs["headers"])

        transfer_timeout = self.transfer_timeout
        if "transfer_timeout" in kwargs:
            transfer_timeout = kwargs["transfer_timeout"]

        max_size = self.max_size
        if "max_size" in kwargs:
            max_size = kwargs["max_size"]

        max_redir = self.max_redirects
        if "max_redirects" in kwargs:
            max_redir = kwargs["max_redirects"]

        if "output" in kwargs:
            self.output = kwargs["output"]

        self.history_body = None
        if "history_body" in kwargs:
            self.history_body = kwargs["history_body"]

        if "auth" in kwargs:
            self.auth = kwargs["auth"]

        self.proxy = None
        if "proxy" in kwargs:
            self.proxy = kwargs["proxy"]

        self.proxy_auth = None
        if "proxy_auth" in kwargs:
            self.proxy_auth = kwargs["proxy_auth"]

        retry = self.retry
        if "retry" in kwargs:
            retry = kwargs["retry"]

        # Specific
        self.raise_on_error = False
        if "raise_on_error" in kwargs:
            self.raise_on_error = kwargs["raise_on_error"]

        # Take from link: Host, Cookies pattern
        link_el = self.parslink(link)
        url = link_el[0] + payload_el
        self.host = link_el[1]
        start_cook_pattern = link_el[2]

        # Fiend Cookies for Request
        self.cook_dick = self.load_cookies(self.load_cookie)
        cook_arr = {}
        if "cookie" in kwargs:
            cook_arr = kwargs["cookie"]
        self.cookies = self.cookies_constr(
            cook_arr=cook_arr,
            link=link,
            start_cook_pattern=start_cook_pattern)

        if self.nonblocking:
            class getHttpClient(HttpClient):

                def __init__(self):
                    super(getHttpClient, self).__init__()

            children = getHttpClient()
            children.host = self.host
            children.cook_dick = self.cook_dick
            children.cookies = self.cookies
            children.url = url

            children.kwargs = kwargs
            children.headers_all = headers_all
            children.url_previos = url_previos
            children.type_req = "DELETE"
            children.bytes_to_send = bytes_to_send
            children.transfer_timeout = transfer_timeout
            children.redirect_counter = redirect_counter
            children.max_redir = max_redir
            children.max_size = max_size
            children.retry = retry
            children.logger = self.logger
            children.auth = self.auth
            children.proxy = self.proxy
            children.proxy_auth = self.proxy_auth
            children.raise_on_error = self.raise_on_error
            children.file_ = b""

            children.data = b""
            children.nonblocking = True
            children.isconnect = False
            children.issend = False

            children.isheaders = False
            children.isbody = False
            children.isrecv = False
            children.host_ip_dic = self.host_ip_dic
            return children

        if not self.nonblocking:
            return self.structure(
                url=url,
                kwargs=kwargs,
                headers_all=headers_all,
                url_previos=url_previos,
                type_req="DELETE",
                bytes_to_send=bytes_to_send,
                transfer_timeout=transfer_timeout,
                redirect_counter=redirect_counter,
                max_redir=max_redir,
                max_size=max_size,
                retry=retry)

    def head(self, link, **kwargs):
        """HEAD http request.

           Request for delete data on some link.

           Args:
                1) headers; 2) cookies 3) max_redir 4)transfer_timeout
                5) max_size 6) auth 7) output 8) history_body
                9) proxy 10) proxy_auth 11) retry

           Returns:
                status code: HTTP code of the request
                encoding: Represents a character encoding.
                headers: Dickt of reaponse headers
                history: list of redirect history

        """
        self.logger.info("Try to connect: " + str(link))
        self.is_f_req = True
        bytes_to_send = None
        url_previos = ""
        redirect_counter = 0
        self.retry_index = 0
        self.raise_on_error = False
        self.cook_dick = self.load_cookies(self.load_cookie)
        headers_all = dict(self.headers_for_request)
        payload_el = ""
        if "params" in kwargs:
            payload_dick = {}
            for key, value in kwargs["params"].items():
                value = "+".join(re.split(" ", value))
                payload_dick[key] = value

            payload_el = "&".join([k + "=" + v for
                                   k, v in payload_dick.items()])

        if "headers" in kwargs:
            headers_all.update(kwargs["headers"])

        max_redir = self.max_redirects
        if "max_redirects" in kwargs:
            max_redir = kwargs["max_redirects"]

        transfer_timeout = self.transfer_timeout
        if "transfer_timeout" in kwargs:
            transfer_timeout = kwargs["transfer_timeout"]

        max_size = self.max_size
        if "max_size" in kwargs:
            max_size = kwargs["max_size"]

        if "auth" in kwargs:
            self.auth = kwargs["auth"]

        if "output" in kwargs:
            self.output = kwargs["output"]

        self.history_body = None
        if "history_body" in kwargs:
            self.history_body = kwargs["history_body"]

        self.proxy = None
        if "proxy" in kwargs:
            self.proxy = kwargs["proxy"]

        self.proxy_auth = None
        if "proxy_auth" in kwargs:
            self.proxy_auth = kwargs["proxy_auth"]

        retry = self.retry
        if "retry" in kwargs:
            retry = kwargs["retry"]

        # Take from link: Host, Cookies pattern
        link_el = self.parslink(link)
        url = link_el[0] + payload_el
        self.host = link_el[1]
        start_cook_pattern = link_el[2]

        # Fiend Cookies for Request
        self.cook_dick = self.load_cookies(self.load_cookie)
        cook_arr = {}
        if "cookie" in kwargs:
            cook_arr = kwargs["cookie"]
        self.cookies = self.cookies_constr(
            cook_arr=cook_arr,
            link=link,
            start_cook_pattern=start_cook_pattern)

        if self.nonblocking:
            class getHttpClient(HttpClient):

                def __init__(self):
                    super(getHttpClient, self).__init__()

            children = getHttpClient()
            children.host = self.host
            children.cook_dick = self.cook_dick
            children.cookies = self.cookies
            children.url = url

            children.kwargs = kwargs
            children.headers_all = headers_all
            children.url_previos = url_previos
            children.type_req = "HEAD"
            children.bytes_to_send = bytes_to_send
            children.transfer_timeout = transfer_timeout
            children.redirect_counter = redirect_counter
            children.max_redir = max_redir
            children.max_size = max_size
            children.retry = retry
            children.logger = self.logger
            children.auth = self.auth
            children.proxy = self.proxy
            children.proxy_auth = self.proxy_auth
            children.raise_on_error = self.raise_on_error
            children.file_ = b""

            children.data = b""
            children.nonblocking = True
            children.isconnect = False
            children.issend = False

            children.isheaders = False
            children.isbody = False
            children.isrecv = False
            children.host_ip_dic = self.host_ip_dic
            return children

        if not self.nonblocking:
            return self.structure(
                url=url,
                kwargs=kwargs,
                headers_all=headers_all,
                url_previos=url_previos,
                type_req="HEAD",
                bytes_to_send=bytes_to_send,
                transfer_timeout=transfer_timeout,
                redirect_counter=redirect_counter,
                max_redir=max_redir,
                max_size=max_size,
                retry=retry)
