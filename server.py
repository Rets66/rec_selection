#!/usr/bin/env python3
import http
import logging
import os
import threading
import urllib.parse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class MyHTTPServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self.user_database = UserDatabase()


class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def _set_response_ok(self):
        # 200
        self.send_response(http.HTTPStatus.OK)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def _set_response_authenticate(self):
        # 401
        self.send_response(http.HTTPStatus.UNAUTHORIZED)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Authentication required\"')
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def _set_response_not_found(self):
        # 404
        self.send_response(http.HTTPStatus.NOT_FOUND)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def _set_response_bad_request(self):
        # 400
        self.send_response(http.HTTPStatus.BAD_REQUEST)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_POST(self):
        parser = urllib.parse.urlparse(self.path)
        logging.info(f"GET request\n"
                     f"Headers: {dict(self.headers)}\n"
                     f"Request: {dict(parser._asdict())}\n")
        if parser.path == '/signup':
            self._signup()
        else:
            self._not_found()

    def _not_found(self):
        self._set_response_not_found()
        self.wfile.write(json.dumps({}).encode())

    def _signup(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        json_data = json.loads(post_data)

        # Validate JSON keys
        if 'user_id' not in json_data.keys() or 'password' not in json_data.keys():
            self._set_response_bad_request()
            if 'user_id' not in json_data.keys() and 'password' in json_data.keys():
                msg = {
                    "message": "Account creation failed",
                    "cause": "required user_id"
                }
            elif 'user_id' in json_data.keys() and 'password' not in json_data.keys():
                msg = {
                    "message": "Account creation failed",
                    "cause": "required password"
                }
            else:
                msg = {
                    "message": "Account creation failed",
                    "cause": "required user_id and password"
                }
            res = json.dumps(msg)
            self.wfile.write(res.encode())
            return

        user_id, password = json_data['user_id'], json_data['password']
        assert type(user_id) == str
        assert type(password) == str

        # Validate value lengths
        if not (6 <= len(user_id) <= 20 and 8 <= len(password) <= 20):
            self._set_response_bad_request()
            if not (6 <= len(user_id) <= 20) and 8 <= len(password) <= 20:
                msg = {
                    "message": "Account creation failed",
                    "cause": "length user_id"
                }
            elif 6 <= len(user_id) <= 20 and not (8 <= len(password) <= 20):
                msg = {
                    "message": "Account creation failed",
                    "cause": "length password"
                }
            else:
                msg = {
                    "message": "Account creation failed",
                    "cause": "length user_id and password"
                }
            res = json.dumps(msg)
            self.wfile.write(res.encode())
            return

        succ = self.server.user_database.add_user(user_id, password)

        if succ:
            self._set_response_ok()
            msg = {
                "message": "Account successfully created",
                "user": {
                    "user_id": f"{user_id}",
                    "nickname": f"{self.server.user_database.database[user_id]['nickname']}",
                }
            }
            res = json.dumps(msg)
            self.wfile.write(res.encode())
        else:
            self._set_response_bad_request()
            msg = {
                "message": "Account creation failed",
                "cause": "already same user_id is used"
            }
            res = json.dumps(msg)
            self.wfile.write(res.encode())


class UserDatabase:
    def __init__(self):
        self.lock = threading.Lock()
        self.database = {}

    def add_user(self, user_id, password, nickname='', comment=''):
        with self.lock:
            if user_id in self.database.keys():
                return False
            self.database[user_id] = {
                "password": password,
                "nickname": nickname,
                "comment": comment
            }
        return True


def run():
    logging.basicConfig(level=logging.INFO)
    server_address = ("0.0.0.0", int(os.environ.get("PORT", 5000)))
    httpd = MyHTTPServer(server_address, MyHTTPRequestHandler)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')


if __name__ == '__main__':
    run()
