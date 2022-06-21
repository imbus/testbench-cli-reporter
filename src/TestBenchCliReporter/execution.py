from time import sleep
from typing import Optional

from requests import Timeout

from . import questions
from .actions import Action
from .testbench import ConnectionLog, login, Connection
from .util import rotate, spin_spinner


def run_manual_mode(configuration=None):
    if configuration is None:
        configuration = {}
    print("Starting manual mode")
    connection_log = ConnectionLog()

    while True:
        config = configuration.get("configuration", [{}])[0]
        server = config.get("server_url", "")
        loginname = config.get("loginname", "")
        pwd = config.get("password", "")
        active_connection = login(server, loginname, pwd)
        connection_log.add_connection(active_connection)
        next_action = questions.ask_for_next_action()
        while next_action is not None:
            try:
                preparation_success = next_action.prepare(connection_log)
                if preparation_success:
                    if next_action.trigger(connection_log):
                        if next_action.wait(connection_log):
                            if next_action.finish(connection_log):
                                active_connection.add_action(next_action)
            except KeyError as e:
                print(f"key {str(e)} not found")
                print(f"Aborted action")

            except ValueError as e:
                print(str(e))
                print("Aborted action")

            except KeyboardInterrupt:
                print("Action aborted by user interrupt.")

            except Timeout:
                print("Action aborted due to timeout.")

            active_connection = connection_log.active_connection
            next_action = questions.ask_for_next_action()


def run_automatic_mode(
    configuration: dict, loginname: Optional[str] = None, password: Optional[str] = None
):
    print("Run Automatic Mode")
    connection_queue = ConnectionLog()
    try:
        for connection_data in configuration["configuration"]:
            connection = Connection(**connection_data)
            if loginname:
                connection.loginname = loginname
            if password:
                connection.password = password
            connection_queue.add_connection(connection)

        job_counter = 0
        for i in range(len(connection_queue.connections)):
            while connection_queue.active_connection.actions_to_trigger:
                action_to_trigger = (
                    connection_queue.active_connection.actions_to_trigger[0]
                )
                action = Action(
                    action_to_trigger["type"], action_to_trigger["parameters"]
                )
                try:
                    action.trigger(connection_queue)
                    connection_queue.active_connection.actions_to_wait_for.append(
                        action
                    )
                    job_counter += 1
                except AssertionError as e:
                    print(e)
                finally:
                    connection_queue.active_connection.actions_to_trigger.remove(
                        action_to_trigger
                    )
                sleep(0.05)
            connection_queue.next()

        print(
            f"{job_counter} jobs started at {len(connection_queue.connections)} server(s)."
        )

        while True:
            active_connection = connection_queue.active_connection

            spin_spinner("Wait for Jobs to be finished.")
            for i in range(len(active_connection.actions_to_wait_for)):
                action_to_wait_for = active_connection.actions_to_wait_for[0]
                if action_to_wait_for.poll(connection_queue):
                    active_connection.actions_to_finish.append(action_to_wait_for)
                    active_connection.actions_to_wait_for.remove(action_to_wait_for)
                else:
                    active_connection.actions_to_wait_for = rotate(
                        active_connection.actions_to_wait_for
                    )

            for i in range(len(active_connection.actions_to_finish)):
                action_to_finish = active_connection.actions_to_finish[0]
                if action_to_finish.finish(connection_queue):
                    active_connection.action_log.append(action_to_finish)
                    active_connection.actions_to_finish.remove(action_to_finish)
                else:
                    active_connection.actions_to_finish = rotate(
                        active_connection.actions_to_finish
                    )

            if (
                len(active_connection.actions_to_trigger)
                + len(active_connection.actions_to_wait_for)
                + len(active_connection.actions_to_finish)
                == 0
            ):
                connection_queue.remove(active_connection)
            if connection_queue.len > 1:
                connection_queue.next()
            elif connection_queue.len == 0:
                break

    except KeyError as e:
        # TODO proper error handling
        print(f"key {str(e)} not found")
