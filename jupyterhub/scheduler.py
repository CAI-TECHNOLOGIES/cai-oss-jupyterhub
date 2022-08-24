"""Scheduler for user jobs"""
import asyncio
import copy
import time
import os
from croniter import croniter
from datetime import datetime
from kubernetes_asyncio import client
from kubernetes_asyncio.stream import WsApiClient

from .user import User
from . import orm

POD_NAMESPACE = os.environ["POD_NAMESPACE"]

def get_next_execution_time(schedule):
    dt = datetime.utcnow()
    # Find next compatible time
    next_time = croniter(schedule, dt).get_next()
    return next_time



def scheduler(settings):
    db = settings['db']
    logger = settings['log']
    async def get_pod_name_from_ip(spawner):
        if not spawner.server:
            return None
        pod_name = None
        pods = await spawner.api.list_namespaced_pod(POD_NAMESPACE)
        for p in pods.items:
            if spawner.server.ip.startswith(p.metadata.name):
                pod_name = p.metadata.name
        return pod_name
                
    async def run_schedule(sch):
        orm_user = orm.User.find_by_id(db, sch.user_id)
        user = User(orm_user, settings, db)
        spawner = user.get_spawner(replace_failed=True)
        user_pod_name = await get_pod_name_from_ip(spawner)
        if not user_pod_name:
            logger.info(f'User pod not found for user {orm_user.name}. Attempting to start now.')
            await user.spawn()
            user_pod_name = await get_pod_name_from_ip(spawner)
            
        logger.info(f"running {sch} at {time.time()}, scheduled at {sch.next_execution_time}")
        # check for user_pod_name
        if user_pod_name is None:
            logger.info(f'User pod not found for user {orm_user.name}. Unable to execute schedule.')
            return
        v1_ws = client.CoreV1Api(api_client=WsApiClient())
        commands = ["/bin/sh",
                    "-c",
                    f"nohup {sch.command} &",
                    "exit"]
        await v1_ws.connect_get_namespaced_pod_exec(user_pod_name, POD_NAMESPACE, command=commands, stderr=True, stdin=False,
                                                                    stdout=True, tty=False, container="notebook")
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    while True:
        # execute once every 30 secs
        try:
            schedules = orm.Schedule.find_all(db).filter(orm.Schedule.next_execution_time < time.time()).all()
            if len(schedules) < 1:
                logger.info("no schedules to run!")
            else:
                tasks = []
                for sch in schedules:
                    # run schedules
                    tasks.append(loop.create_task(run_schedule(copy.deepcopy(sch))))
                    sch.next_execution_time = get_next_execution_time(sch.schedule)
                loop.run_until_complete(asyncio.wait(tasks, timeout=30.0))
                db.commit()
        except Exception as e:
            logger.error(e)
        finally:
            time.sleep(60 - (time.time() % 60))