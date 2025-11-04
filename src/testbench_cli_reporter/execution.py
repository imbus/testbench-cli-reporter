import base64
import traceback
from contextlib import suppress
from time import sleep
from typing import Any

import requests.exceptions  # type: ignore
from requests import Timeout

from . import questions
from .actions import Action, UnloggedAction
from .config_model import CliReporterConfig, Configuration, LogLevel
from .log import logger, setup_logger
from .testbench import Connection, ConnectionLog, login
from .util import close_program, rotate, spin_spinner


def _handle_session_terminated(active_connection, connection_log):
    print("HTTP Error: Session terminated by server. See log for details.")
    action = questions.ask_for_action_after_session_terminated(
        getattr(active_connection, "loginname", None),
        active_connection.server_url,
    )
    if action == "relogin_same":
        return login(
            active_connection.server_url,
            getattr(active_connection, "loginname", ""),
            getattr(active_connection, "password", ""),
            "",
        )
    if action == "change_user":
        return login(active_connection.server_url)
    if action == "change_server":
        connection_log.active_connection.close()
        new_conn = login()
        connection_log.add_connection(new_conn)
        return new_conn
    close_program()
    return None


def run_manual_mode(configuration: CliReporterConfig | None = None):
    cli_config: CliReporterConfig = (
        CliReporterConfig(configuration=[]) if configuration is None else configuration
    )
    cli_config.loggingConfiguration.console.logLevel = LogLevel.INFO
    cli_config.loggingConfiguration.console.logFormat = "%(message)s"
    setup_logger(cli_config.loggingConfiguration)

    print("Starting manual mode")
    connection_log = ConnectionLog()

    while True:
        config = cli_config.configuration[0] if len(cli_config.configuration) else Configuration("")
        _analyse_basic_auth(config)
        active_connection = login(config.server_url, config.loginname, config.password, config.sessionToken)
        connection_log.add_connection(active_connection)
        active_connection = _reconnect_if_logged_out(connection_log, active_connection)
        next_action = questions.ask_for_main_action(
            active_connection.server_version, active_connection.is_admin
        )
        while next_action is not None:
            try:
                if isinstance(next_action, UnloggedAction):
                    next_action.prepare(active_connection)
                    next_action.trigger_connections(connection_log)
                elif (
                    next_action.prepare(active_connection)
                    and next_action.trigger(active_connection)
                    and next_action.wait(active_connection)
                    and next_action.finish(active_connection)
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
            except Exception:
                logger.exception("An unexpected error occurred while executing the action.")
                logger.debug(
                    f"Action: {next_action.__class__.__name__}, Parameters: {next_action.parameters}"
                )

            active_connection = _reconnect_if_logged_out(connection_log, connection_log.active_connection)
            next_action = questions.ask_for_main_action(
                active_connection.server_version, active_connection.is_admin
            )


def _analyse_basic_auth(config):
    if config.basicAuth:
        credentials = base64.b64decode(config.basicAuth.encode()).decode("utf-8")
        config.loginname, config.password = credentials.split(":", 1)


def _reconnect_if_logged_out(connection_log, active_connection):
    return (
        _handle_session_terminated(active_connection, connection_log)
        if active_connection.session_terminated
        else active_connection
    )


def run_automatic_mode(
    configuration: CliReporterConfig | dict[str, Any],
    loginname: str | None = None,
    password: str | None = None,
    sessionToken: str | None = None,
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
        fill_connection_queue(config, connection_queue, loginname, password, sessionToken)
        while connection_queue.len:
            trigger_possible_actions(connection_queue, raise_exceptions)
            spin_spinner("Wait for Jobs to be finished.")
            poll_and_finish_actions(connection_queue, raise_exceptions)
        logger.info("All jobs finished.")
    except requests.HTTPError as e:
        logger.debug(traceback.format_exc())
        with suppress(Exception):
            logger.error(e.response.json())
        raise e


def fill_connection_queue(
    configuration: CliReporterConfig,
    connection_queue: ConnectionLog,
    loginname: str | None,
    password: str | None,
    sessionToken: str | None,
):
    for connection_data in configuration.configuration:
        connection = Connection(
            server_url=connection_data.server_url or "https://localhost:443",
            verify=connection_data.verify,
            sessionToken=sessionToken or connection_data.sessionToken,
            basicAuth=connection_data.basicAuth,
            actions=connection_data.actions,
            loginname=loginname,
            password=password,
            thread_limit=connection_data.thread_limit,
        )
        connection_queue.add_connection(connection)


def trigger_possible_actions(connection_queue: ConnectionLog, raise_exceptions: bool = False):
    job_counter = 0
    server_ids = set()
    for _ in range(len(connection_queue.connections)):
        active_connection = connection_queue.active_connection
        while active_connection.actions_to_trigger and (
            active_connection.thread_limit is None
            or len(active_connection.actions_to_wait_for) < active_connection.thread_limit
        ):
            trigger_next_action(active_connection, raise_exceptions)
            job_counter += 1
            server_ids.add(active_connection.server_url)
            sleep(0.05)
        connection_queue.next()
    if job_counter:
        logger.info(f"{job_counter} jobs started at {len(server_ids)} server(s).")


def trigger_next_action(active_connection: Connection, raise_exceptions: bool):
    action_to_trigger = active_connection.actions_to_trigger[0]
    try:
        action = Action(action_to_trigger.type, action_to_trigger.parameters)  # type:ignore
        logger.debug(f"Triggering action: {action.__class__.__name__}\nParameters: {action.parameters}")
        action.trigger(active_connection)
        active_connection.actions_to_wait_for.append(action)
        logger.info(f"Job {action.__class__.__name__}: {action.job_id} started.")
    except requests.exceptions.HTTPError as e:
        if raise_exceptions:
            raise e
        logger.exception("Action trigger failed")
        logger.error(e.response.json())
    except TypeError as e:
        if raise_exceptions:
            raise e
        logger.error(e)
    finally:
        active_connection.actions_to_trigger.remove(action_to_trigger)


def poll_and_finish_actions(connection_queue: ConnectionLog, raise_exceptions: bool):
    for _ in range(len(connection_queue.connections)):
        active_connection = connection_queue.active_connection
        poll_actions_to_wait_for(active_connection, raise_exceptions)
        execute_actions_to_finish(active_connection, raise_exceptions)
        if active_connection_finished(active_connection):
            connection_queue.remove(active_connection)
        if connection_queue.len > 1:
            connection_queue.next()


def poll_actions_to_wait_for(active_connection: Connection, raise_exceptions: bool):
    for _ in range(len(active_connection.actions_to_wait_for)):
        action_to_wait_for = active_connection.actions_to_wait_for[0]
        try:
            if action_to_wait_for.poll(active_connection):
                active_connection.actions_to_finish.append(action_to_wait_for)
                active_connection.actions_to_wait_for.remove(action_to_wait_for)
            else:
                active_connection.actions_to_wait_for = rotate(active_connection.actions_to_wait_for)
        except (requests.exceptions.HTTPError, AssertionError) as e:
            active_connection.actions_to_wait_for.remove(action_to_wait_for)
            if raise_exceptions:
                raise e
            logger.exception(f"Polling job {action_to_wait_for.job_id} failed.")
            if hasattr(e, "response") and e.response is not None:
                logger.error(e.response.json())


def execute_actions_to_finish(active_connection: Connection, raise_exceptions: bool):
    for _ in range(len(active_connection.actions_to_finish)):
        action_to_finish = active_connection.actions_to_finish[0]
        try:
            if action_to_finish.finish(active_connection):
                active_connection.action_log.append(action_to_finish)
                active_connection.actions_to_finish.remove(action_to_finish)
            else:
                active_connection.actions_to_finish = rotate(active_connection.actions_to_finish)
        except (requests.exceptions.HTTPError, AssertionError) as e:
            active_connection.actions_to_finish.remove(action_to_finish)
            if raise_exceptions:
                raise e
            logger.exception(f"Finishing job {action_to_finish.job_id} failed, skipping action.")
            if hasattr(e, "response") and e.response is not None:
                logger.error(e.response.json())
            logger.error(f"Error: {e!s}")


def active_connection_finished(active_connection):
    return (
        len(active_connection.actions_to_trigger)
        + len(active_connection.actions_to_wait_for)
        + len(active_connection.actions_to_finish)
        == 0
    )
