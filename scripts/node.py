#!/usr/bin/env python3
# Copyright (c) 2014-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Helpful routines for regression testing."""

import errno
import http
import inspect
import logging
import os
import subprocess
import tempfile
import time
import urllib

from authproxy import AuthServiceProxy, JSONRPCException

logger = logging.getLogger("TestFramework.utils")

BITCOIND_PROC_WAIT_TIMEOUT = 60


def wait_until_helper(predicate, *, attempts=float('inf'), timeout=float('inf'), lock=None, timeout_factor=1.0):
    """Sleep until the predicate resolves to be True.

    Warning: Note that this method is not recommended to be used in tests as it is
    not aware of the context of the test framework. Using the `wait_until()` members
    from `BitcoinTestFramework` or `P2PInterface` class ensures the timeout is
    properly scaled. Furthermore, `wait_until()` from `P2PInterface` class in
    `p2p.py` has a preset lock.
    """
    if attempts == float('inf') and timeout == float('inf'):
        timeout = 60
    timeout = timeout * timeout_factor
    attempt = 0
    time_end = time.time() + timeout

    while attempt < attempts and time.time() < time_end:
        if lock:
            with lock:
                if predicate():
                    return
        else:
            if predicate():
                return
        attempt += 1
        time.sleep(0.05)

    # Print the cause of the timeout
    predicate_source = "''''\n" + inspect.getsource(predicate) + "'''"
    logger.error("wait_until() failed. Predicate: {}".format(predicate_source))
    if attempt >= attempts:
        raise AssertionError("Predicate {} not true after {} attempts".format(predicate_source, attempts))
    elif time.time() >= time_end:
        raise AssertionError("Predicate {} not true after {} seconds".format(predicate_source, timeout))
    raise RuntimeError('Unreachable')


# The maximum number of nodes a single test can spawn
MAX_NODES = 12
# Don't assign rpc or p2p ports lower than this
PORT_MIN = int(os.getenv('TEST_RUNNER_PORT_MIN', default=11000))
# The number of ports to "reserve" for p2p and rpc, each
PORT_RANGE = 5000


class PortSeed:
    # Must be initialized with a unique integer for each process
    n = None


def get_rpc_proxy(url: str, node_number: int, *, timeout: int = None) -> AuthServiceProxy:
    """
    Args:
        url: URL of the RPC server to call
        node_number: the node number (or id) that this calls to

    Kwargs:
        timeout: HTTP timeout in seconds
        coveragedir: Directory

    Returns:
        AuthServiceProxy. convenience object for making RPC calls.

    """
    proxy_kwargs = {}
    if timeout is not None:
        proxy_kwargs['timeout'] = int(timeout)

    proxy = AuthServiceProxy(url, **proxy_kwargs)
    return proxy


def p2p_port(n):
    assert n <= MAX_NODES
    return PORT_MIN + n + (MAX_NODES * PortSeed.n) % (PORT_RANGE - 1 - MAX_NODES)


def rpc_port(n):
    return PORT_MIN + PORT_RANGE + n + (MAX_NODES * PortSeed.n) % (PORT_RANGE - 1 - MAX_NODES)


def rpc_url(datadir, i, chain, rpchost):
    rpc_u, rpc_p = get_auth_cookie(datadir, chain)
    host = '127.0.0.1'
    port = rpc_port(i)
    if rpchost:
        parts = rpchost.split(':')
        if len(parts) == 2:
            host, port = parts
        else:
            host = rpchost
    return "http://%s:%s@%s:%d" % (rpc_u, rpc_p, host, int(port))


# Node functions
################


def initialize_datadir(dirname, n, chain, disable_autoconnect=True):
    datadir = get_datadir_path(dirname, n)
    if not os.path.isdir(datadir):
        os.makedirs(datadir)
    write_config(os.path.join(datadir, "bitcoin.conf"), n=n, chain=chain, disable_autoconnect=disable_autoconnect)
    os.makedirs(os.path.join(datadir, 'stderr'), exist_ok=True)
    os.makedirs(os.path.join(datadir, 'stdout'), exist_ok=True)
    return datadir


def write_config(config_path, *, n, chain, extra_config="", disable_autoconnect=True):
    # Translate chain subdirectory name to config name
    if chain == 'testnet3':
        chain_name_conf_arg = 'testnet'
        chain_name_conf_section = 'test'
    else:
        chain_name_conf_arg = chain
        chain_name_conf_section = chain
    with open(config_path, 'w', encoding='utf8') as f:
        if chain_name_conf_arg:
            f.write("{}=1\n".format(chain_name_conf_arg))
        if chain_name_conf_section:
            f.write("[{}]\n".format(chain_name_conf_section))
        f.write("port=" + str(p2p_port(n)) + "\n")
        f.write("rpcport=" + str(rpc_port(n)) + "\n")
        f.write("fallbackfee=0.0002\n")
        f.write("server=1\n")
        f.write("keypool=1\n")
        f.write("discover=0\n")
        f.write("dnsseed=0\n")
        f.write("fixedseeds=0\n")
        f.write("listenonion=0\n")
        # Increase peertimeout to avoid disconnects while using mocktime.
        # peertimeout is measured in mock time, so setting it large enough to
        # cover any duration in mock time is sufficient. It can be overridden
        # in tests.
        f.write("peertimeout=999999999\n")
        f.write("printtoconsole=0\n")
        f.write("upnp=0\n")
        f.write("natpmp=0\n")
        f.write("shrinkdebugfile=0\n")
        # To improve SQLite wallet performance so that the tests don't timeout, use -unsafesqlitesync
        f.write("unsafesqlitesync=1\n")
        if disable_autoconnect:
            f.write("connect=0\n")
        f.write(extra_config)


def get_datadir_path(dirname, n):
    return os.path.join(dirname, "node" + str(n))


def append_config(datadir, options):
    with open(os.path.join(datadir, "bitcoin.conf"), 'a', encoding='utf8') as f:
        for option in options:
            f.write(option + "\n")


def get_auth_cookie(datadir, chain):
    user = None
    password = None
    if os.path.isfile(os.path.join(datadir, "bitcoin.conf")):
        with open(os.path.join(datadir, "bitcoin.conf"), 'r', encoding='utf8') as f:
            for line in f:
                if line.startswith("rpcuser="):
                    assert user is None  # Ensure that there is only one rpcuser line
                    user = line.split("=")[1].strip("\n")
                if line.startswith("rpcpassword="):
                    assert password is None  # Ensure that there is only one rpcpassword line
                    password = line.split("=")[1].strip("\n")
    try:
        with open(os.path.join(datadir, chain, ".cookie"), 'r', encoding="ascii") as f:
            userpass = f.read()
            split_userpass = userpass.split(':')
            user = split_userpass[0]
            password = split_userpass[1]
    except OSError:
        pass
    if user is None or password is None:
        raise ValueError("No RPC credentials")
    return user, password


# If a cookie file exists in the given datadir, delete it.
def delete_cookie_file(datadir, chain):
    if os.path.isfile(os.path.join(datadir, chain, ".cookie")):
        logger.debug("Deleting leftover cookie file")
        os.remove(os.path.join(datadir, chain, ".cookie"))


class Node:
    """Modified from Bitcoin Core's test framework TestNode"""
    def __init__(
        self,
        i,
        datadir,
        *,
        chain,
        rpchost,
        timewait,
        timeout_factor,
        bitcoind,
        cwd,
        extra_conf=None,
        extra_args=None,
    ):
        """
        Kwargs:
            start_perf (bool): If True, begin profiling the node with `perf` as soon as
                the node starts.
        """

        self.index = i
        self.p2p_conn_index = 1
        self.datadir = datadir
        self.bitcoinconf = os.path.join(self.datadir, "bitcoin.conf")
        self.stdout_dir = os.path.join(self.datadir, "stdout")
        self.stderr_dir = os.path.join(self.datadir, "stderr")
        self.chain = chain
        self.rpchost = rpchost
        self.rpc_timeout = timewait
        self.binary = bitcoind
        self.cwd = cwd
        if extra_conf is not None:
            append_config(datadir, extra_conf)
        # Most callers will just need to add extra args to the standard list below.
        # For those callers that need more flexibility, they can just set the args property directly.
        # Note that common args are set in the config file (see initialize_datadir)
        self.extra_args = extra_args
        # Configuration for logging is set as command-line args rather than in the bitcoin.conf file.
        # This means that starting a bitcoind using the temp dir to debug a failed test won't
        # spam debug.log.
        self.args = [
            self.binary,
            "-datadir=" + self.datadir,
            "-logtimemicros",
            "-debug",
            "-debugexclude=libevent",
            "-debugexclude=leveldb",
            "-uacomment=testnode%d" % i,
        ]

        self.running = False
        self.process = None
        self.rpc_connected = False
        self.rpc = None
        self.url = None
        self.log = logging.getLogger("TestFramework.node%d" % i)
        self.cleanup_on_exit = (
            True  # Whether to kill the node when this object goes away
        )

        self.timeout_factor = timeout_factor

    def _node_msg(self, msg: str) -> str:
        """Return a modified msg that identifies this node by its index as a debugging aid."""
        return "[node %d] %s" % (self.index, msg)

    def _raise_assertion_error(self, msg: str):
        """Raise an AssertionError with msg modified to identify this node."""
        raise AssertionError(self._node_msg(msg))

    def __del__(self):
        # Ensure that we don't leave any bitcoind processes lying around after
        # the test ends
        if self.process and self.cleanup_on_exit:
            # Should only happen on test failure
            # Avoid using logger, as that may have already been shutdown when
            # this destructor is called.
            print(self._node_msg("Cleaning up leftover process"))
            self.process.kill()

    def __getattr__(self, name):
        """Dispatches any unrecognised messages to the RPC connection or a CLI instance."""
        assert self.rpc_connected and self.rpc is not None, self._node_msg(
            "Error: no RPC connection"
        )
        return getattr(self.rpc, name)

    def start(self, extra_args=None, *, cwd=None, stdout=None, stderr=None, **kwargs):
        """Start the node."""
        if extra_args is None:
            extra_args = self.extra_args

        # Add a new stdout and stderr file each time bitcoind is started
        if stderr is None:
            stderr = tempfile.NamedTemporaryFile(dir=self.stderr_dir, delete=False)
        if stdout is None:
            stdout = tempfile.NamedTemporaryFile(dir=self.stdout_dir, delete=False)
        self.stderr = stderr
        self.stdout = stdout

        if cwd is None:
            cwd = self.cwd

        # Delete any existing cookie file -- if such a file exists (eg due to
        # unclean shutdown), it will get overwritten anyway by bitcoind, and
        # potentially interfere with our attempt to authenticate
        delete_cookie_file(self.datadir, self.chain)

        # add environment variable LIBC_FATAL_STDERR_=1 so that libc errors are written to stderr and not the terminal
        subp_env = dict(os.environ, LIBC_FATAL_STDERR_="1")

        self.process = subprocess.Popen(
            self.args + extra_args,
            env=subp_env,
            stdout=stdout,
            stderr=stderr,
            cwd=cwd,
            **kwargs,
        )

        self.running = True
        self.log.debug("bitcoind started, waiting for RPC to come up")

    def wait_for_rpc_connection(self):
        """Sets up an RPC connection to the bitcoind process. Returns False if unable to connect."""
        # Poll at a rate of four times per second
        poll_per_s = 4
        for _ in range(poll_per_s * self.rpc_timeout):
            if self.process.poll() is not None:
                raise Exception(
                    self._node_msg(
                        "bitcoind exited with status {} during initialization".format(
                            self.process.returncode
                        )
                    )
                )
            try:
                rpc = get_rpc_proxy(
                    rpc_url(self.datadir, self.index, self.chain, self.rpchost),
                    self.index,
                    timeout=self.rpc_timeout // 2,  # Shorter timeout to allow for one retry in case of ETIMEDOUT
                )
                rpc.getblockcount()
                # If the call to getblockcount() succeeds then the RPC connection is up
                wait_until_helper(
                    lambda: rpc.getmempoolinfo()["loaded"],
                    timeout_factor=self.timeout_factor,
                )
                # Wait for the node to finish reindex, block import, and
                # loading the mempool. Usually importing happens fast or
                # even "immediate" when the node is started. However, there
                # is no guarantee and sometimes ThreadImport might finish
                # later. This is going to cause intermittent test failures,
                # because generally the tests assume the node is fully
                # ready after being started.
                #
                # For example, the node will reject block messages from p2p
                # when it is still importing with the error "Unexpected
                # block message received"
                #
                # The wait is done here to make tests as robust as possible
                # and prevent racy tests and intermittent failures as much
                # as possible. Some tests might not need this, but the
                # overhead is trivial, and the added guarantees are worth
                # the minimal performance cost.
                self.log.debug("RPC successfully started")
                self.rpc = rpc
                self.rpc_connected = True
                self.url = self.rpc.rpc_url
                return
            except JSONRPCException as e:  # Initialization phase
                # -28 RPC in warmup
                # -342 Service unavailable, RPC server started but is shutting down due to error
                if e.error["code"] != -28 and e.error["code"] != -342:
                    raise  # unknown JSON RPC exception
            except ConnectionResetError:
                # This might happen when the RPC server is in warmup, but shut down before the call to getblockcount
                # succeeds. Try again to properly raise the FailedToStartError
                pass
            except OSError as e:
                if e.errno == errno.ETIMEDOUT:
                    pass  # Treat identical to ConnectionResetError
                elif e.errno == errno.ECONNREFUSED:
                    pass  # Port not yet open?
                else:
                    raise  # unknown OS error
            except ValueError as e:  # cookie file not found and no rpcuser or rpcpassword; bitcoind is still starting
                if "No RPC credentials" not in str(e):
                    raise
            time.sleep(1.0 / poll_per_s)
        self._raise_assertion_error(
            "Unable to connect to bitcoind after {}s".format(self.rpc_timeout)
        )

    def wait_for_cookie_credentials(self):
        """Ensures auth cookie credentials can be read, e.g. for testing CLI with -rpcwait before RPC connection is up."""
        self.log.debug("Waiting for cookie credentials")
        # Poll at a rate of four times per second.
        poll_per_s = 4
        for _ in range(poll_per_s * self.rpc_timeout):
            try:
                get_auth_cookie(self.datadir, self.chain)
                self.log.debug("Cookie credentials successfully retrieved")
                return
            except ValueError:  # cookie file not found and no rpcuser or rpcpassword; bitcoind is still starting
                pass  # so we continue polling until RPC credentials are retrieved
            time.sleep(1.0 / poll_per_s)
        self._raise_assertion_error(
            "Unable to retrieve cookie credentials after {}s".format(self.rpc_timeout)
        )

    def get_wallet_rpc(self, wallet_name):
        assert self.rpc_connected and self.rpc, self._node_msg("RPC not connected")
        wallet_path = "wallet/{}".format(urllib.parse.quote(wallet_name))
        return self.rpc / wallet_path

    def stop_node(self, expected_stderr="", *, wait=0, wait_until_stopped=True):
        """Stop the node."""
        if not self.running:
            return
        self.log.debug("Stopping node")
        try:
            self.stop(wait=wait)
        except http.client.CannotSendRequest:
            self.log.exception("Unable to stop node.")

        # Check that stderr is as expected
        self.stderr.seek(0)
        stderr = self.stderr.read().decode("utf-8").strip()
        if stderr != expected_stderr:
            raise AssertionError(
                "Unexpected stderr {} != {}".format(stderr, expected_stderr)
            )

        self.stdout.close()
        self.stderr.close()

        if wait_until_stopped:
            self.wait_until_stopped()

    def is_node_stopped(self):
        """Checks whether the node has stopped.

        Returns True if the node has stopped. False otherwise.
        This method is responsible for freeing resources (self.process)."""
        if not self.running:
            return True
        return_code = self.process.poll()
        if return_code is None:
            return False

        # process has stopped. Assert that it didn't return an error code.
        assert return_code == 0, self._node_msg(
            "Node returned non-zero exit code (%d) when stopping" % return_code
        )
        self.running = False
        self.process = None
        self.rpc_connected = False
        self.rpc = None
        self.log.debug("Node stopped")
        return True

    def wait_until_stopped(self, timeout=BITCOIND_PROC_WAIT_TIMEOUT):
        wait_until_helper(
            self.is_node_stopped, timeout=timeout, timeout_factor=self.timeout_factor
        )
