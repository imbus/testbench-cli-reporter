import traceback
from time import sleep
from typing import Any, Dict, Optional, Union

import requests.exceptions  # type: ignore
from requests import Timeout

from . import questions
from .actions import Action
from .config_model import CliReporterConfig, Configuration, LogLevel
from .log import logger, setup_logger
from .testbench import Connection, ConnectionLog, login
from .util import rotate, spin_spinner


def run_manual_mode(configuration: Optional[CliReporterConfig] = None):
    cli_config: CliReporterConfig = (
        CliReporterConfig(configuration=[]) if configuration is None else configuration
    )
    cli_config.loggingConfiguration.file = None
    cli_config.loggingConfiguration.console.logLevel = LogLevel.INFO
    cli_config.loggingConfiguration.console.logFormat = "%(message)s"
    setup_logger(cli_config.loggingConfiguration)

    print("Starting manual mode")
    connection_log = ConnectionLog()

    while True:
        config = cli_config.configuration[0] if len(cli_config.configuration) else Configuration("")
        active_connection = login(config.server_url, config.loginname, config.password)
        connection_log.add_connection(active_connection)
        next_action = questions.ask_for_next_action()
        while next_action is not None:
            try:
                if (
                    next_action.prepare(connection_log)
                    and next_action.trigger(connection_log)
                    and next_action.wait(connection_log)
                    and next_action.finish(connection_log)
                ):
                    active_connection.add_action(next_action)
            except KeyError as e:
                logger.error(f"key {e!s} not found")
                logger.info("Aborted action")

            except ValueError:
                logger.debug(traceback.format_exc())
                logger.info("Aborted action")

            except KeyboardInterrupt:
                logger.info("Action aborted by user interrupt.")

            except Timeout:
                logger.info("Action aborted due to timeout.")

            active_connection = connection_log.active_connection
            next_action = questions.ask_for_next_action()


def run_automatic_mode(
    configuration: Union[CliReporterConfig, Dict[str, Any]],
    loginname: Optional[str] = None,
    password: Optional[str] = None,
    raise_exceptions: bool = False,
):
    config = (
        configuration
        if isinstance(configuration, CliReporterConfig)
        else CliReporterConfig.from_dict(configuration)
    )
    setup_logger(config.loggingConfiguration)
    logger.info("Run Automatic Mode")
    connection_queue = ConnectionLog()
    try:
        fill_connection_queue(config, connection_queue, loginname, password)
        trigger_all_actions(connection_queue, raise_exceptions)
        poll_and_finish_actions(connection_queue, raise_exceptions)
        logger.info("All jobs finished.")
    except requests.HTTPError as e:
        logger.debug(traceback.format_exc())
        try:
            logger.error(e.response.json())
        except:
            pass
        raise e


def fill_connection_queue(configuration, connection_queue, loginname, password):
    for connection_data in configuration.configuration:
        connection = Connection(
            server_url=connection_data.server_url,
            verify=connection_data.verify,
            sessionToken=connection_data.sessionToken,
            basicAuth=connection_data.basicAuth,
            actions=connection_data.actions,
            loginname=loginname,
            password=password,
        )
        connection_queue.add_connection(connection)


def poll_and_finish_actions(connection_queue, raise_exceptions):
    while True:
        active_connection = connection_queue.active_connection
        spin_spinner("Wait for Jobs to be finished.")
        poll_actions_to_wait_for(active_connection, connection_queue, raise_exceptions)
        execute_actions_to_finish(active_connection, connection_queue, raise_exceptions)

        if active_connection_finished(active_connection):
            connection_queue.remove(active_connection)
        if connection_queue.len > 1:
            connection_queue.next()
        elif connection_queue.len == 0:
            break


def trigger_all_actions(connection_queue, raise_exceptions):
    job_counter = 0
    for _ in range(len(connection_queue.connections)):
        while connection_queue.active_connection.actions_to_trigger:
            action_to_trigger = connection_queue.active_connection.actions_to_trigger[0]
            action = Action(action_to_trigger.type, action_to_trigger.parameters)
            logger.debug(
                f"Triggering action: {action.__class__.__name__}\n"
                f"Parameters: {action.parameters}"
            )
            try:
                action.trigger(connection_queue)
                connection_queue.active_connection.actions_to_wait_for.append(action)
                job_counter += 1
                logger.info(f"Job {action.__class__.__name__}: {action.job_id} started.")
            except requests.exceptions.HTTPError as e:
                if raise_exceptions:
                    raise e
                logger.exception("Action trigger failed")
                logger.error(e.response.json())
            finally:
                connection_queue.active_connection.actions_to_trigger.remove(action_to_trigger)
            sleep(0.05)
        connection_queue.next()
    logger.info(f"{job_counter} jobs started at {len(connection_queue.connections)} server(s).")


def execute_actions_to_finish(active_connection, connection_queue, raise_exceptions):
    for _ in range(len(active_connection.actions_to_finish)):
        action_to_finish = active_connection.actions_to_finish[0]
        try:
            if action_to_finish.finish(connection_queue):
                active_connection.action_log.append(action_to_finish)
                active_connection.actions_to_finish.remove(action_to_finish)
            else:
                active_connection.actions_to_finish = rotate(active_connection.actions_to_finish)
        except requests.exceptions.HTTPError as e:
            active_connection.actions_to_finish.remove(action_to_finish)
            if raise_exceptions:
                raise e
            logger.exception("Action finish failed, skipping action.")
            logger.error(e.response.json())


def poll_actions_to_wait_for(active_connection, connection_queue, raise_exceptions):
    for _ in range(len(active_connection.actions_to_wait_for)):
        action_to_wait_for = active_connection.actions_to_wait_for[0]
        try:
            if action_to_wait_for.poll(connection_queue):
                active_connection.actions_to_finish.append(action_to_wait_for)
                active_connection.actions_to_wait_for.remove(action_to_wait_for)
            else:
                active_connection.actions_to_wait_for = rotate(
                    active_connection.actions_to_wait_for
                )
        except requests.exceptions.HTTPError as e:
            active_connection.actions_to_wait_for.remove(action_to_wait_for)
            if raise_exceptions:
                raise e
            logger.exception("Action poll failed, skipping action.")
            logger.error(e.response.json())


def active_connection_finished(active_connection):
    return (
        len(active_connection.actions_to_trigger)
        + len(active_connection.actions_to_wait_for)
        + len(active_connection.actions_to_finish)
        == 0
    )
