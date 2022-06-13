import argparse
import configparser
import json
import logging
import os
import shutil
import sys
import tempfile
import time

from decimal import Decimal
from typing import List
from node import (
    get_datadir_path,
    initialize_datadir,
    Node,
    PortSeed,
)


class ScenarioOptionsAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if namespace.payments or namespace.feerates:
            parser.error(
                "--scenario cannot be provided when --payments and --feerates are provided"
            )
        setattr(namespace, self.dest, values)


class PaymentsFeeratesOptionsAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if namespace.scenario:
            parser.error(
                "--payments and --feerates cannot be provided when --scenario is provided"
            )
        setattr(namespace, self.dest, values)


class OutputTypeWeightsOptionsAction(argparse.Action):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if len(values) != 4:
            parser.error(
                "must provide weights for each address type (bech32m, bech32, p2sh-segwit, legacy)"
            )
        if sum(values) != 100:
            parser.error("weights must sum to 100")
        total = 0
        cumulative = []
        for v in values:
            total += v
            cumulative.append(total)
        setattr(namespace, self.dest, cumulative)


def check_json_precision():
    """Make sure json library being used does not lose precision converting BTC values"""
    n = Decimal("20000000.00000003")
    satoshis = int(json.loads(json.dumps(float(n))) * 1.0e8)
    if satoshis != 2000000000000003:
        raise RuntimeError("JSON encode/decode loses precision")


class Simulation:
    def __init__(self):
        self.chain: str = "regtest"
        self.setup_clean_chain: bool = True
        self.nodes: List[Node] = []
        self.network_thread = None
        self.rpc_timeout = 60  # Wait for up to 60 seconds for the RPC server to respond
        self.parse_args()
        self.requires_wallet = True
        # Disable ThreadOpenConnections by default, so that adding entries to
        # addrman will not result in automatic connections to them.
        self.disable_autoconnect = True
        self.set_sim_params()
        if self.options.timeout_factor == 0:
            self.options.timeout_factor = 99999
        self.rpc_timeout = int(
            self.rpc_timeout * self.options.timeout_factor
        )  # optionally, increase timeout by a factor

    def parse_args(self):
        parser = argparse.ArgumentParser(usage="%(prog)s [options]")
        parser.add_argument(
            "--nocleanup",
            dest="nocleanup",
            default=False,
            action="store_true",
            help="Leave bitcoinds and test.* datadir on exit or error",
        )
        parser.add_argument(
            "--noshutdown",
            dest="noshutdown",
            default=False,
            action="store_true",
            help="Don't stop bitcoinds after the test execution",
        )
        parser.add_argument(
            "--cachedir",
            dest="cachedir",
            default=os.path.abspath(
                os.path.dirname(os.path.realpath(__file__)) + "/../../cache"
            ),
            help="Directory for caching pregenerated datadirs (default: %(default)s)",
        )
        parser.add_argument(
            "--tmpdir", dest="tmpdir", help="Root directory for datadirs"
        )
        parser.add_argument(
            "-l",
            "--loglevel",
            dest="loglevel",
            default="INFO",
            help="log events at this level and higher to the console. Can be set to DEBUG, INFO, WARNING, ERROR or CRITICAL. Passing --loglevel DEBUG will output all logs to console. Note that logs at all levels are always written to the test_framework.log file in the temporary test directory.",
        )
        parser.add_argument(
            "--tracerpc",
            dest="trace_rpc",
            default=False,
            action="store_true",
            help="Print out all RPC calls as they are made",
        )
        parser.add_argument(
            "--portseed",
            dest="port_seed",
            default=os.getpid(),
            type=int,
            help="The seed to use for assigning port numbers (default: current process id)",
        )
        parser.add_argument(
            "--randomseed",
            type=int,
            help="set a random seed for deterministically reproducing a previous test run",
        )
        parser.add_argument(
            "--timeout-factor",
            dest="timeout_factor",
            type=float,
            default=1.0,
            help="adjust test timeouts by a factor. Setting it to 0 disables all timeouts",
        )

        parser.add_argument("--scenario", default=None, action=ScenarioOptionsAction)
        parser.add_argument("--label", default=None)
        parser.add_argument(
            "--payments",
            default=None,
            required="--feerates" in sys.argv,
            action=PaymentsFeeratesOptionsAction,
        )
        parser.add_argument(
            "--feerates",
            default=None,
            required="--payments" in sys.argv,
            action=PaymentsFeeratesOptionsAction,
        )
        parser.add_argument("--ops", type=int, default=None)
        parser.add_argument(
            "--weights",
            type=int,
            nargs="+",
            default=None,
            required="--weights" in sys.argv,
            action=OutputTypeWeightsOptionsAction,
            help="Causes recipient output types to be chosen randomly with provided weights per address type. Weights must add to 100 and be provided in the following order: bech32m bech32 p2sh-segwit legacy",
        )
        parser.add_argument("configfile", help="Path to the config.ini file generated by compiling Bitcoin Core usually in test/config.ini")
        parser.add_argument("resultsdir", help="Path to a directory where the simulation results will be stored")

        self.options = parser.parse_args()

        if self.options.scenario is None and self.options.payments is None:
            parser.error("One of --scenario or --payments and --feerates must be provided")

        config = configparser.ConfigParser()
        config.read_file(open(self.options.configfile))
        self.config = config

        PortSeed.n = self.options.port_seed

    def main(self):
        self.setup()
        self.run()
        self.shutdown()

    def setup(self):
        if not self.is_usdt_compiled():
            raise Exception("USDT Tracepoints are not compiled, cannot run simulation")
        if not self.is_sqlite_compiled():
            raise Exception("SQLite is not compiled, cannot run simulation")

        check_json_precision()

        self.options.cachedir = os.path.abspath(self.options.cachedir)

        config = self.config

        fname_bitcoind = os.path.join(
            config["environment"]["BUILDDIR"],
            "src",
            "bitcoind" + config["environment"]["EXEEXT"],
        )
        self.options.bitcoind = os.getenv("BITCOIND", default=fname_bitcoind)

        # Set up temp directory and start logging
        if self.options.tmpdir:
            self.options.tmpdir = os.path.abspath(self.options.tmpdir)
            os.makedirs(self.options.tmpdir, exist_ok=False)
        else:
            self.options.tmpdir = tempfile.mkdtemp(prefix="bitcoin_coin_sel_sim_")
        self._start_logging()

        self.setup_chain()
        self.setup_nodes()

    def shutdown(self):
        if not self.options.noshutdown:
            self.log.info("Stopping nodes")
            if self.nodes:
                self.stop_nodes()
        else:
            for node in self.nodes:
                node.cleanup_on_exit = False
            self.log.info("Note: bitcoinds were not stopped and may still be running")

        should_clean_up = not self.options.nocleanup and not self.options.noshutdown
        if should_clean_up:
            self.log.info("Cleaning up {} on exit".format(self.options.tmpdir))
            cleanup_tree_on_exit = True
        else:
            self.log.warning("Not cleaning up dir {}".format(self.options.tmpdir))
            cleanup_tree_on_exit = False

        # Logging.shutdown will not remove stream- and filehandlers, so we must
        # do it explicitly. Handlers are removed so the next test run can apply
        # different log handler settings.
        # See: https://docs.python.org/3/library/logging.html#logging.shutdown
        for h in list(self.log.handlers):
            h.flush()
            h.close()
            self.log.removeHandler(h)
        rpc_logger = logging.getLogger("BitcoinRPC")
        for h in list(rpc_logger.handlers):
            h.flush()
            rpc_logger.removeHandler(h)
        if cleanup_tree_on_exit:
            shutil.rmtree(self.options.tmpdir)

        self.nodes.clear()

    def _start_logging(self):
        # Add logger and logging handlers
        self.log = logging.getLogger("TestFramework")
        self.log.setLevel(logging.DEBUG)
        # Create file handler to log all messages
        fh = logging.FileHandler(
            self.options.tmpdir + "/test_framework.log", encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        # Create console handler to log messages to stderr. By default this logs only error messages, but can be configured with --loglevel.
        ch = logging.StreamHandler(sys.stdout)
        # User can provide log level as a number or string (eg DEBUG). loglevel was caught as a string, so try to convert it to an int
        ll = (
            int(self.options.loglevel)
            if self.options.loglevel.isdigit()
            else self.options.loglevel.upper()
        )
        ch.setLevel(ll)
        # Format logs the same as bitcoind's debug.log with microprecision (so log files can be concatenated and sorted)
        formatter = logging.Formatter(
            fmt="%(asctime)s.%(msecs)03d000Z %(name)s (%(levelname)s): %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        formatter.converter = time.gmtime
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # add the handlers to the logger
        self.log.addHandler(fh)
        self.log.addHandler(ch)

        if self.options.trace_rpc:
            rpc_logger = logging.getLogger("BitcoinRPC")
            rpc_logger.setLevel(logging.DEBUG)
            rpc_handler = logging.StreamHandler(sys.stdout)
            rpc_handler.setLevel(logging.DEBUG)
            rpc_logger.addHandler(rpc_handler)

    def setup_chain(self):
        """Override this method to customize blockchain setup"""
        self.log.info("Initializing test directory " + self.options.tmpdir)
        if self.setup_clean_chain:
            self._initialize_chain_clean()
        else:
            self._initialize_chain()

    def _initialize_chain_clean(self):
        """Initialize empty blockchain for use by the test.

        Create an empty blockchain and num_nodes wallets.
        Useful if a test case wants complete control over initialization."""
        for i in range(self.num_nodes):
            initialize_datadir(
                self.options.tmpdir, i, self.chain, self.disable_autoconnect
            )

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_nodes()

    def add_nodes(self, num_nodes: int, extra_args=None):
        extra_confs = [["bind=127.0.0.1"]] * num_nodes
        binary = [self.options.bitcoind]
        assert len(extra_confs) == num_nodes
        assert len(extra_args) == num_nodes
        assert len(binary) == num_nodes
        for i in range(num_nodes):
            test_node_i = Node(
                i,
                get_datadir_path(self.options.tmpdir, i),
                chain=self.chain,
                rpchost=None,
                timewait=self.rpc_timeout,
                timeout_factor=self.options.timeout_factor,
                bitcoind=binary[i],
                cwd=self.options.tmpdir,
                extra_conf=extra_confs[i],
                extra_args=extra_args[i],
            )
            self.nodes.append(test_node_i)

    def start_nodes(self):
        """Start multiple bitcoinds"""

        try:
            for i, node in enumerate(self.nodes):
                node.start()
            for node in self.nodes:
                node.wait_for_rpc_connection()
        except:
            # If one node failed to start, stop the others
            self.stop_nodes()
            raise

    def stop_nodes(self, wait=0):
        """Stop multiple bitcoind test nodes"""
        for node in self.nodes:
            # Issue RPC to stop nodes
            node.stop_node(wait=wait, wait_until_stopped=False)

        for node in self.nodes:
            # Wait for nodes to stop
            node.wait_until_stopped()

    def is_usdt_compiled(self):
        """Checks whether the USDT tracepoints were compiled."""
        return self.config["components"].getboolean("ENABLE_USDT_TRACEPOINTS")

    def is_sqlite_compiled(self):
        """Checks whether the wallet module was compiled with Sqlite support."""
        return self.config["components"].getboolean("USE_SQLITE")
