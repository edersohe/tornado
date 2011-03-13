#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging
import tornado.auth
import tornado.escape
import tornado.ioloop
import tornado.options
import tornado.web
import os.path
import uuid

from tornado.options import define, options

define("port", default=8888, help="run on the given port", type=int)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/auth/login", AuthLoginHandler),
            (r"/auth/logout", AuthLogoutHandler),
            (r"/a/message/new", MessageNewHandler),
            (r"/a/message/updates", MessageUpdatesHandler),
        ]
        settings = dict(
            cookie_secret="43oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            login_url="/auth/login",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
        )
        tornado.web.Application.__init__(self, handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("user")
    

class MessageMixin(object):
    waiters = {}
    cache = {}
    cache_size = 200

    def wait_for_messages(self, callback, cursor=None, owner=None):
        """owner is a propietary of callback"""
        
        cls = MessageMixin

        if not owner in cls.cache:
            cls.cache[owner] = []

        if cursor:
            index = 0
            for i in xrange(len(cls.cache[owner])):
                index = len(cls.cache[owner]) - i - 1
                if cls.cache[owner][index]["id"] == cursor: break
            recent = cls.cache[owner][index + 1:]
            if recent:
                callback(recent)
                return
        try:
            cls.waiters[owner].append(callback)
        except KeyError:
            cls.waiters[owner] = [callback]

    def new_messages(self, messages, dst=[]):
        """dst is a list of users where messages its sending,
        when dst list is empty messages send to all members"""
        
        cls = MessageMixin

        if len(dst)<1:
            for owner in cls.waiters:
                self._parse(owner, messages)

        else:
            for owner in dst:
                if not owner in cls.waiters and owner in cls.cache:
                    cls.waiters[owner]=[]
                if owner in cls.waiters:
                    self._parse(owner, messages)

    def _parse(self,owner, messages):
        cls = MessageMixin

        logging.info("Sending new message to %r listeners", len(cls.waiters[owner]))
        for callback in cls.waiters[owner]:
            try:
                callback(messages)
            except:
                logging.error("Error in waiter callback", exc_info=True)
        cls.waiters[owner] = []
        cls.cache[owner].extend(messages)
        if len(cls.cache[owner]) > self.cache_size:
            cls.cache[owner] = cls.cache[owner][-self.cache_size:]


class MainHandler(BaseHandler, MessageMixin):
    @tornado.web.authenticated
    def get(self):
        logging.info(self.current_user)
        if not self.current_user in self.cache:
            self.cache[self.current_user] = []
        message = {
            "id": str(uuid.uuid4()),
            "from": self.current_user,
            "body": "I START SESSION",
        }
        message["html"] = self.render_string("message.html", message=message)
        self.new_messages([message])
        self.render("index.html", messages=self.cache[self.current_user])
        

class MessageNewHandler(BaseHandler, MessageMixin):
    """Send private messages if you write on chatbox: 
        username::this is the messages for the username"""
        
    @tornado.web.authenticated
    def post(self):
        msg =  self.get_argument("body").split('::',1)
        to = []
        if len(msg)>1:
            to = [msg[0], self.current_user]
            msg = 'to ' + to[0] + ' -> '  + msg[1].strip()
        else:
            msg = msg[0]
        message = {
            "id": str(uuid.uuid4()),
            "from": self.current_user,
            "body": msg,
        }
        message["html"] = self.render_string("message.html", message=message)
        if self.get_argument("next", None):
            self.redirect(self.get_argument("next"))
        else:
            self.write(message)

        if len(to)>=1:
            self.new_messages([message], to)
        else:
            self.new_messages([message])


class MessageUpdatesHandler(BaseHandler, MessageMixin):
    @tornado.web.authenticated
    @tornado.web.asynchronous
    def post(self):
        cursor = self.get_argument("cursor", None)
        self.wait_for_messages(self.async_callback(self.on_new_messages),
                               cursor=cursor, owner=self.current_user)

    def on_new_messages(self, messages):
        # Closed client connection
        if self.request.connection.stream.closed():
            return
        self.finish(dict(messages=messages))


class AuthLoginHandler(BaseHandler, tornado.auth.GoogleMixin):
    @tornado.web.asynchronous
    def get(self):
        if self.get_argument("openid.mode", None):
            self.get_authenticated_user(self.async_callback(self._on_auth))
            return
        self.authenticate_redirect(ax_attrs=["name"])

    def _on_auth(self, user):
        if not user:
            raise tornado.web.HTTPError(500, "Google auth failed")
        self.set_secure_cookie("user", user['name'])
        self.redirect("/")


class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("user")
        self.write("You are now logged out")


def main():
    tornado.options.parse_command_line()
    app = Application()
    app.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
