#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import datetime
import logging
import hashlib
import uuid

import store
import scoring
from optparse import OptionParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from weakref import WeakKeyDictionary


SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class ValidationError(Exception):
    def __init__(self, text):
        self.text = text

class Validator:
    def __init__(self, required, nullable):
        self.required = required
        self.nullable = nullable
        self.data = WeakKeyDictionary()

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner):
        return self.data[instance]

    def validate(self, value):
        if not self.nullable and value is None:
            raise ValidationError('{self.name} cannot be NONE')

class CharField(Validator):

    def __set__(self, instance, value):
        if value is not None and not isinstance(value,str):
            raise ValidationError('{self.name} must be a str')
        self.validate(value)
        self.data[instance] = value

class ArgumentsField(Validator):
    def __set__(self, instance, value):
        if value is not None and not isinstance(value, dict):
            raise ValidationError('{self.name} must be a dict')
        self.validate(value)
        self.data[instance] = value

class EmailField(CharField):
    def __set__(self, instance, value):
        if isinstance(value, str) and '@' not in value:
            raise ValidationError('{self.name} must contain email')
        if value is not None and not isinstance(value, str):
            raise ValidationError('{self.name} must be str')
        self.validate(value)
        self.data[instance] = value

class PhoneField(Validator):
    def __set__(self, instance, value):
        if value is not None:
            if len(str(value)) != 11:
                raise ValidationError('{self.name} must contain 11 digits')
            if str(value)[0] != '7':
                raise ValidationError('{self.name} must begin with the number 7')
        self.validate(value)
        self.data[instance] = value

class DateField(Validator):
    def __set__(self, instance, value):
        if value is not None:
            value = datetime.datetime.strptime(value, '%d.%m.%Y')
        self.validate(value)
        self.data[instance] = value

class BirthDayField(Validator):
    age = 70
    def __set__(self, instance, value):
        value = datetime.datetime.strptime(value,'%d.%m.%Y')
        if self.is_less_than(value):
            raise ValidationError(f'{self.name} is less then {self.age}')
        self.validate(value)
        self.data[instance] = value

    def is_less_than(self, value):
        from_date = datetime.datetime.now()
        try:
            lower_date = from_date.replace(year=from_date.year-self.age)
        except ValueError:
            lower_date = from_date.replace(month=2, day=28, year=from_date.year-self.age)
        return value < lower_date

class GenderField(Validator):
    def __set__(self, instance, value):
        if value is not None and not isinstance(value, int):
            raise ValidationError('{self.name} must be a int')
        if value not in (0, 1, 2, None):
            raise ValidationError('{self.name} must be 0, 1, 2 or None')
        self.validate(value)
        self.data[instance] = value

class ClientIDsField:
    def __init__(self, required):
        self.required = required
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self.data[instance]

    def __set__(self, instance, value):
        if value is None:
            raise ValidationError('Client ID cannot be None')
        if not isinstance(value, list):
            raise ValidationError('Client ID must be a List')
        if set(isinstance(i, int) for i in value) != {True}:
            raise ValidationError('Client ID only digits')
        self.data[instance] = value

class ClientsInterestsRequest:
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)
    error = None

    def __init__(self, arguments):
        try:
            self.client_ids = arguments['client_ids']
            self.date = arguments.get('date')
        except Exception as e:
            self.error = str(e)

class ArgumentsMetaclass(type):

    def __new__(mcs, name, bases, dct):
        attr_required = tuple(name for name, value in dct.items() if not name.starswith('__') and not name.endswiht('_func') and value.required)
        attr_none_required = tuple(name for name, value in dct.items() if not name.starswith('__') and not name.endswiht('_func') and value.required)
        dct['attr_required'] = attr_required
        dct['attr_none_required'] = attr_none_required
        return type.__new__(mcs, name, bases, dct)

class OnlineScoreRequest(ArgumentsMetaclass):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


    def __init__(self, arguments: dict):
       try:
           for arg in self.attr_required:
               self.__setattr__(arg, arguments[arg])
           for arg in self.attr_none_required:
               self.__setattr__(arg, arguments.get(arg))
           self.has = self.create_has_fuunc(arguments)
           self.error = None
       except Exception as e:
           self.error = str(e)


    def validate_args_func(self) -> bool:
        if self.phone and self.email:
            return True
        if self.first_name and self.last_name:
            return True
        if self.gender is not None and self.birthday:
            return True
        return False


    def create_has_func(self, arguments: dict) -> list:
        has = []
        for arg in self.attr_required + self.attr_none_required:
            if arg in arguments:
                has.append(arg)
        return has


class MethodRequest(ArgumentsMetaclass):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, request):
        try:
            for arg in self.attr_required:
                self.__setattr__(arg, request['body'][arg])
            for arg in self.attr_none_required:
                self.__setattr__(arg, request['body'].get[arg])
            self.error = None
        except Exception as e:
            self.error = str(e)


    @property
    def is_admin_func(self):
        return self.login == ADMIN_LOGIN


def check_auth(request: MethodRequest) -> bool:
    if request.is_admin_func:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode('utf-8')).hexdigest()
    if digest == request.token:
        return True
    return False

def online_scor_handler(request: MethodRequest, ctx: dict, store) -> tuple:
    online_score = OnlineScoreRequest(request.arguments)
    if online_score.error is not None:
        code = 422
        response = online_score.error
    elif not online_score.validate_args_func():
        code = 422
        response = 'Not enough data in arguments'
    else:
        ctx['has'] = online_score.has
        if request.is_admin_func:
            code = 200
            response = {'score': 42}
        else:
            scor = scoring.get_score(
                store=store,
                first_name=online_score.first_name,
                last_name=online_score.last_name,
                phone=online_score.phone,
                email=online_score.email,
                birthday=online_score.birthday,
                gender=online_score.gender,
            )
            code = 200
            response = dict(score=scor)
        return code, response

def clients_interests_hander(request: MethodRequest, ctx: dict, store) -> tuple:
    clients_interest = ClientsInterestsRequest(request.arguments)
    if clients_interest.error is not None:
        code = 422
        response = clients_interest.error
    else:
        ctx['nclients'] = len(clients_interest.client_ids)
        code = 200
        response = {i: scoring.get_interests(store, i) for i in clients_interest.client_ids}
        return code, response


def method_handler(request: dict, ctx: dict, store) -> tuple:
    response, code = None, None
    request = MethodRequest(request)
    if request.error is not None:
        code = 422
        response = request.error
    elif not check_auth(request):
        code = 403
        response = ERRORS[code]
    elif request.method == 'online_score':
        code, response = online_scor_handler(request, ctx, store)
    elif request.method == 'clients_interests':
        code, response = clients_interests_hander(request, ctx, store)
    return response, code

class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = store.Story(
        parameters=('localhost', 11211),
        connect_attempts=5,
        timeout=1,
    )

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        json_bytes = (json.dumps(r)).encode('utf-8')
        self.wfile.write(json_bytes)
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
