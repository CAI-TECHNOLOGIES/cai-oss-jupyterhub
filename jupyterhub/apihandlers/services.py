"""Service handlers

Currently GET-only, no actions can be taken to modify services.
"""
# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
import json

from tornado import web
from .. import orm
from ..utils import token_authenticated

from ..scopes import needs_scope
from ..scopes import Scope
from .base import APIHandler
from ..scheduler import get_next_execution_time


class ServiceListAPIHandler(APIHandler):
    @needs_scope('list:services')
    def get(self):
        data = {}
        service_scope = self.parsed_scopes['list:services']
        for name, service in self.services.items():
            if service_scope == Scope.ALL or name in service_scope.get("service", {}):
                model = self.service_model(service)
                data[name] = model
        self.write(json.dumps(data))


class ServiceAPIHandler(APIHandler):
    @needs_scope('read:services', 'read:services:name', 'read:roles:services')
    def get(self, service_name):
        service = self.services[service_name]
        self.write(json.dumps(self.service_model(service)))


class ScheduleAPIHandler(APIHandler):
    @token_authenticated
    async def post(self):
        headers = self.request.headers
        data = self.get_json_body()
        command = data["command"]
        if not command:
            raise web.HTTPError(400, "command is a required field")
        schedule = data["schedule"]
        if not schedule:
            raise web.HTTPError(400, "schedule is a required field")

        token = headers["Authorization"].split()[1]
        user_id = orm.APIToken.find(self.db, token).user.id

        schedule_item = orm.Schedule(user_id=user_id, command=command, schedule=schedule, next_execution_time=get_next_execution_time(schedule))
        self.db.add(schedule_item)
        self.db.commit()
        self.write(json.dumps({"status": "success"}))

    @token_authenticated
    def get(self):
        headers = self.request.headers
        token = headers["Authorization"].split()[1]
        user_id = orm.APIToken.find(self.db, token).user.id
        schedules = orm.Schedule.find(self.db, user_id).all()
        self.write(json.dumps({"schedules": [str(s) for s in schedules]}))

    @token_authenticated
    def delete(self):
        headers = self.request.headers
        token = headers["Authorization"].split()[1]
        user_id = orm.APIToken.find(self.db, token).user.id
        data = self.get_json_body()
        id = data["id"]
        if not id:
            raise web.HTTPError(400, "id is a required field")
        schedules = orm.Schedule.find(self.db, user_id).all()
        found = False
        for s in schedules:
            if s.id == id:
                found = True
                self.db.delete(s)
                self.db.commit()
                break

        if found:
            self.write(json.dumps({"status": "success"}))
        else:
           raise web.HTTPError(404, "schedule not found")



default_handlers = [
    (r"/api/services", ServiceListAPIHandler),
    (r"/api/services/([^/]+)", ServiceAPIHandler),
    (r"/api/schedule", ScheduleAPIHandler),
]
