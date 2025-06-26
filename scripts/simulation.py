#! /usr/bin/env python3
import argparse
import csv
import git
import logging
import os
import struct
import uuid

from authproxy import JSONRPCException
from bcc import BPF, USDT
from bisect import bisect
from collections import defaultdict
from decimal import Decimal, getcontext
from framework import Simulation
from random import random
from statistics import mean, stdev
from datetime import datetime

program = """
#include <uapi/linux/ptrace.h>

#define WALLET_NAME_LENGTH 16
#define ALGO_NAME_LENGTH 16

struct event_data
{
    u8 type;
    char wallet_name[WALLET_NAME_LENGTH];

    // selected coins event
    char algo[ALGO_NAME_LENGTH];
    s64 target;
    s64 waste;
    s64 selected_value;

    // create tx event
    u8 success;
    s64 fee;
    s32 change_pos;

    // aps create tx event
    u8 use_aps;
};

BPF_QUEUE(coin_selection_events, struct event_data, 1024);

int trace_selected_coins(struct pt_regs *ctx) {
    struct event_data data;
    __builtin_memset(&data, 0, sizeof(data));
    data.type = 1;
    bpf_usdt_readarg_p(1, ctx, &data.wallet_name, WALLET_NAME_LENGTH);
    bpf_usdt_readarg_p(2, ctx, &data.algo, ALGO_NAME_LENGTH);
    bpf_usdt_readarg(3, ctx, &data.target);
    bpf_usdt_readarg(4, ctx, &data.waste);
    bpf_usdt_readarg(5, ctx, &data.selected_value);
    coin_selection_events.push(&data, 0);
    return 0;
}

int trace_normal_create_tx(struct pt_regs *ctx) {
    struct event_data data;
    __builtin_memset(&data, 0, sizeof(data));
    data.type = 2;
    bpf_usdt_readarg_p(1, ctx, &data.wallet_name, WALLET_NAME_LENGTH);
    bpf_usdt_readarg(2, ctx, &data.success);
    bpf_usdt_readarg(3, ctx, &data.fee);
    bpf_usdt_readarg(4, ctx, &data.change_pos);
    coin_selection_events.push(&data, 0);
    return 0;
}

int trace_attempt_aps(struct pt_regs *ctx) {
    struct event_data data;
    __builtin_memset(&data, 0, sizeof(data));
    data.type = 3;
    bpf_usdt_readarg_p(1, ctx, &data.wallet_name, WALLET_NAME_LENGTH);
    coin_selection_events.push(&data, 0);
    return 0;
}

int trace_aps_create_tx(struct pt_regs *ctx) {
    struct event_data data;
    __builtin_memset(&data, 0, sizeof(data));
    data.type = 4;
    bpf_usdt_readarg_p(1, ctx, &data.wallet_name, WALLET_NAME_LENGTH);
    bpf_usdt_readarg(2, ctx, &data.use_aps);
    bpf_usdt_readarg(3, ctx, &data.success);
    bpf_usdt_readarg(4, ctx, &data.fee);
    bpf_usdt_readarg(5, ctx, &data.change_pos);
    coin_selection_events.push(&data, 0);
    return 0;
}
"""


def ser_compact_size(l):
    r = b""
    if l < 253:
        r = struct.pack("B", l)
    elif l < 0x10000:
        r = struct.pack("<BH", 253, l)
    elif l < 0x100000000:
        r = struct.pack("<BI", 254, l)
    else:
        r = struct.pack("<BQ", 255, l)
    return r


class CoinSelectionSimulation(Simulation):
    def set_sim_params(self):
        self.num_nodes = 1
        self.extra_args = [["-dustrelayfee=0", "-maxtxfee=1"]]
        self.output_types = ["bech32m", "bech32", "p2sh-segwit", "legacy"]

    def log_sim_results(self, res_file, csvw):
        getcontext().prec = 12
        # Find change stats
        change_vals = sorted(self.change_vals)
        min_change = Decimal(change_vals[0]) if len(self.change_vals) > 0 else 0
        max_change = Decimal(change_vals[-1]) if len(self.change_vals) > 0 else 0
        mean_change = (
            Decimal(mean(change_vals)) * Decimal(1) if len(self.change_vals) > 0 else 0
        )
        stdev_change = (
            Decimal(stdev(change_vals)) * Decimal(1) if len(self.change_vals) > 0 else 0
        )

        # Remaining utxos and fee stats
        remaining_utxos = self.tester.listunspent()
        cost_to_empty = (
            Decimal(len(remaining_utxos)) * Decimal(68) * Decimal(0.0001) / Decimal(1000)
        )
        total_cost = self.total_fees + cost_to_empty
        mean_fees = (
            Decimal(self.total_fees) / Decimal(self.withdraws)
            if self.withdraws > 0
            else 0
        )

        # input stats
        input_sizes = sorted(self.input_sizes)
        min_input_size = Decimal(input_sizes[0]) if len(self.input_sizes) > 0 else 0
        max_input_size = Decimal(input_sizes[-1]) if len(self.input_sizes) > 0 else 0
        mean_input_size = (
            (Decimal(mean(input_sizes)) * Decimal(1))
            if len(self.input_sizes) > 0
            else 0
        )
        stdev_input_size = (
            (Decimal(stdev(input_sizes)) * Decimal(1))
            if len(self.input_sizes) > 0
            else 0
        )

        # UTXO stats
        mean_utxo_set_size = (
            (Decimal(mean(self.utxo_set_sizes)) * Decimal(1))
            if len(self.utxo_set_sizes) > 0
            else 0
        )

        # No change counts
        no_change_str = ""
        no_change_total = 0
        for algo, c in self.no_change.items():
            no_change_total += c
            no_change_str += f"{algo}: **{c}** ; "
        no_change_str += f"Total: **{no_change_total}**"

        # Usage counts
        usage_str = ""
        for algo, c in self.algo_counts.items():
            usage_str += f"{algo}: **{c}** ; "
        usage_str = usage_str[:-3]

        result = [
            self.scenario_name,
            str(self.tester.getbalance()),
            str(mean_utxo_set_size),
            str(len(remaining_utxos)),
            str(self.count_received),
            str(self.count_sent),
            str(self.withdraws),
            str(self.unec_utxos),
            str(len(self.change_vals)),
            no_change_str,
            str(min_change),
            str(max_change),
            str(mean_change),
            str(stdev_change),
            str(self.total_fees),
            str(mean_fees),
            str(cost_to_empty),
            str(total_cost),
            str(min_input_size),
            str(max_input_size),
            str(mean_input_size),
            str(stdev_input_size),
            usage_str,
        ]
        result_str = f"| {' | '.join(result)} |"
        res_file.write(f"{result_str}\n")
        res_file.flush()
        self.log.debug(result_str)
        csvw.writerow(result)
        return result_str

    def run(self):
        # Get Git commit
        repo = git.Repo(self.config["environment"]["SRCDIR"])
        commit = repo.commit("HEAD")
        commit_hash = commit.hexsha[:7]
        branch = repo.active_branch.name
        if self.options.label is None:
            self.log.info(f"Based on branch {branch}({commit_hash})")
        else:
            label = self.options.label
            self.log.info(f"Based on branch: {branch} ({commit_hash}), label: {label}")

        # Get a unique id
        date = datetime.now().strftime("%Y-%m-%dT%H-%M")
        unique_id = date + "_" + uuid.uuid4().hex[:8]
        self.log.info(f"This simulation's Unique ID: {unique_id}")

        if self.options.scenario:
            self.scenario_name = os.path.splitext(os.path.basename(self.options.scenario))[0]

            def get_scenario_data(file):
                for line in file:
                    val_str, fee_str = line.rstrip().lstrip().split(",")
                    yield val_str, fee_str

            scenario_files = [open(self.options.scenario, "r")]
            scenario_data = get_scenario_data(scenario_files[0])
        elif self.options.payments and self.options.feerates:
            self.scenario_name = f"{os.path.splitext(os.path.basename(self.options.payments))[0]}_{os.path.splitext(os.path.basename(self.options.feerates))[0]}"

            def cycle(file):
                while True:
                    for line in file:
                        yield line
                    file.seek(0)

            scenario_files = [
                open(self.options.payments, "r"),
                open(self.options.feerates, "r"),
            ]
            scenario_data = zip(scenario_files[0], cycle(scenario_files[1]))

        self.scenario_path = self.options.scenario

        # Make an output folder
        if self.options.label is None:
            results_dir = os.path.join(
                self.options.resultsdir,
                f"{self.scenario_name}",
                f"{branch}-{commit_hash}",
                f"sim_{unique_id}"
            )
        else:
            results_dir = os.path.join(
                self.options.resultsdir,
                f"{self.scenario_name}",
                f"{branch}-{commit_hash}-{label}",
                f"sim_{unique_id}",
            )
        os.makedirs(results_dir, exist_ok=True)

        # Setup debug logging
        debug_log_handler = logging.FileHandler(
            os.path.join(results_dir, "sim_debug.log")
        )
        debug_log_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            fmt="%(asctime)s.%(msecs)03d000Z %(name)s (%(levelname)s): %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        debug_log_handler.setFormatter(formatter)
        self.log.addHandler(debug_log_handler)

        # Decimal precision
        getcontext().prec = 12

        # Make two wallets
        self.nodes[0].createwallet(wallet_name="funder", descriptors=True)
        self.nodes[0].createwallet(wallet_name="tester", descriptors=True)
        self.funder = self.nodes[0].get_wallet_rpc("funder")
        self.tester = self.nodes[0].get_wallet_rpc("tester")

        # Check that there's no UTXO on the wallets
        assert len(self.funder.listunspent()) == 0
        assert len(self.tester.listunspent()) == 0

        self.log.info("Mining blocks for node0 to be able to send enough coins")

        gen_addr = self.funder.getnewaddress()
        self.funder.generatetoaddress(600, gen_addr)  # > 14,000 BTC
        withdraw_addresses = {
            output: self.funder.getnewaddress(address_type=output)
            for output in self.output_types
        }

        # set this as the default. if weights are provided by the user, we will update this when creating the psbt
        withdraw_address = withdraw_addresses["bech32"]

        fields = [
            "Scenario File",
            "Current Balance",
            "Mean #UTXO",
            "Current #UTXO",
            "#Deposits",
            "#Inputs Spent",
            "#Withdraws",
            "#Uneconomical outputs spent",
            "#Change Created",
            "#Changeless",
            "Min Change Value",
            "Max Change Value",
            "Mean Change Value",
            "Std. Dev. of Change Value",
            "Total Fees",
            "Mean Fees per Withdraw",
            "Cost to Empty (10 sat/vB)",
            "Total Cost",
            "Min Input Size",
            "Max Input Size",
            "Mean Input Size",
            "Std. Dev. of Input Size",
            "Usage",
        ]
        header = f"| {' | '.join(fields)} |"

        # Connect tracepoints
        bitcoind_with_usdts = USDT(pid=self.nodes[0].process.pid)
        bitcoind_with_usdts.enable_probe(
            probe="selected_coins", fn_name="trace_selected_coins"
        )
        bitcoind_with_usdts.enable_probe(
            probe="normal_create_tx_internal", fn_name="trace_normal_create_tx"
        )
        bitcoind_with_usdts.enable_probe(
            probe="attempting_aps_create_tx", fn_name="trace_attempt_aps"
        )
        bitcoind_with_usdts.enable_probe(
            probe="aps_create_tx_internal", fn_name="trace_aps_create_tx"
        )
        bpf = BPF(text=program, usdt_contexts=[bitcoind_with_usdts])

        self.log.info(f"Simulating using scenario: {self.scenario_name}")
        if self.options.label is None:
            self.log.info(f"Based on branch {branch}({commit_hash})")
        else:
            label = self.options.label
            self.log.info(f"Based on branch: {branch} ({commit_hash}), label: {label}")
        self.total_fees = Decimal()
        self.ops = 0
        self.count_sent = 0
        self.change_vals = []
        self.no_change = defaultdict(int)
        self.withdraws = 0
        self.input_sizes = []
        self.utxo_set_sizes = []
        self.count_change = 0
        self.count_received = 0
        self.unec_utxos = 0
        self.algo_counts = defaultdict(int)
        with open(
            os.path.join(results_dir, "full_results.csv"), "a+"
        ) as full_res, open(
            os.path.join(results_dir, "results.txt"), "a+"
        ) as res, open(
            os.path.join(results_dir, "results.csv"), "a+"
        ) as csv_res, open(
            os.path.join(results_dir, "utxos.csv"), "a+"
        ) as utxos_res, open(
            os.path.join(results_dir, "inputs.csv"), "a+"
        ) as inputs_res:

            dw = csv.DictWriter(
                full_res,
                [
                    "id",
                    "amount",
                    "fees",
                    "target_feerate",
                    "real_feerate",
                    "algo",
                    "num_inputs",
                    "negative_ev",
                    "num_outputs",
                    "change_amount",
                    "before_num_utxos",
                    "after_num_utxos",
                    "waste",
                ],
            )
            dw.writeheader()
            utxos_dw = csv.DictWriter(utxos_res, ["id", "utxo_amounts"])
            utxos_dw.writeheader()
            inputs_dw = csv.DictWriter(inputs_res, ["id", "input_amounts"])
            inputs_dw.writeheader()
            sum_csvw = csv.writer(csv_res)
            sum_csvw.writerow(fields)

            res.write(
                f"----BEGIN SIMULATION RESULTS----\nScenario: {self.scenario_name}\nBranch: {branch}-{commit_hash} \n{header}\n"
            )
            res.flush()
            for val_str, fee_str in scenario_data:
                if self.options.ops and self.ops > self.options.ops:
                    break
                if self.ops % 500 == 0:
                    self.log.info(f"{self.ops} operations performed so far")
                    self.log_sim_results(res, sum_csvw)

                # Make deposit or withdrawal
                value = Decimal(val_str.strip())
                feerate = Decimal(fee_str.strip())
                if self.options.weights:

                    # choose a random address type based on the weights provided by the user
                    i = bisect(self.options.weights, random() * 100)
                    withdraw_address = withdraw_addresses[self.output_types[i]]
                if value > 0:
                    try:
                        # deposit
                        self.funder.sendall(
                            [{self.tester.getnewaddress(): value}, withdraw_address]
                        )
                        self.count_received += 1
                        self.log.debug(
                            f"Op {self.ops} Received {self.count_received}th deposit of {value} BTC"
                        )
                    except JSONRPCException as e:
                        self.log.warning(
                            f"Failure on op {self.ops} with funder sending {value} with error {str(e)}"
                        )
                if value < 0:
                    try:
                        payment_stats = {"id": self.withdraws}
                        # Before listunspent
                        before_utxos = self.tester.listunspent()
                        payment_stats["before_num_utxos"] = len(before_utxos)
                        utxo_amounts = [str(u["amount"]) for u in before_utxos]
                        utxos_dw.writerow(
                            {"id": self.withdraws, "utxo_amounts": utxo_amounts}
                        )
                        # Prepare withdraw
                        value = value * -1
                        payment_stats["amount"] = value
                        payment_stats["target_feerate"] = feerate
                        # use the bech32 withdraw address by default
                        # if weights are provided, then choose an address type based on the provided distribution
                        psbt = self.tester.walletcreatefundedpsbt(
                            outputs=[{withdraw_address: value}],
                            options={"feeRate": feerate},
                        )["psbt"]
                        psbt = self.tester.walletprocesspsbt(psbt)["psbt"]
                        # Send the tx
                        psbt = self.tester.finalizepsbt(psbt, False)["psbt"]
                        tx = self.tester.finalizepsbt(psbt)["hex"]
                        self.tester.sendrawtransaction(tx)
                        # Get data from the tracepoints
                        algo = None
                        change_pos = None
                        waste = None
                        try:
                            is_aps = False
                            sc_events = []
                            while True:
                                event = bpf["coin_selection_events"].pop()
                                if b"tester" not in event.wallet_name:
                                    continue
                                if event.type == 1:
                                    if not is_aps:
                                        algo = event.algo.decode()
                                        waste = event.waste
                                    sc_events.append(event)
                                elif event.type == 2:
                                    assert event.success == 1
                                    if not is_aps and event.change_pos != -1:
                                        change_pos = event.change_pos
                                elif event.type == 3:
                                    is_aps = True
                                elif event.type == 4:
                                    assert is_aps
                                    if event.use_aps == 1:
                                        assert len(sc_events) == 2
                                        algo = sc_events[1].algo.decode()
                                        waste = sc_events[1].waste
                                        change_pos = event.change_pos
                        except KeyError:
                            pass
                        assert algo is not None
                        assert waste is not None
                        payment_stats["algo"] = algo
                        payment_stats["waste"] = waste
                        self.algo_counts[algo] += 1
                        # Get negative EV UTXOs
                        payment_stats["negative_ev"] = 0
                        dec = self.tester.decodepsbt(psbt)
                        input_amounts = []
                        for in_idx, inp in enumerate(dec["inputs"]):
                            inp_size = (
                                4 + 36 + 4
                            )  # prev txid, output index, sequence are all fixed size
                            ev = 0
                            if "final_scriptSig" in inp:
                                scriptsig_len = len(inp["final_scriptSig"])
                                inp_size += scriptsig_len + len(
                                    ser_compact_size(scriptsig_len)
                                )
                            else:
                                inp_size += 1
                            if "final_scriptWitness" in inp:
                                witness_len = len(inp["final_scriptWitness"])
                                inp_size += witness_len / 4
                            inp_fee = feerate * (Decimal(inp_size) / Decimal(1000.0))
                            if "witness_utxo" in inp:
                                utxo = inp["witness_utxo"]
                                input_amounts.append(str(inp["witness_utxo"]["amount"]))
                                ev = inp["witness_utxo"]["amount"] - inp_fee
                            else:
                                assert "non_witness_utxo" in inp
                                out_index = dec["tx"]["vin"][in_idx]["vout"]
                                utxo = inp["non_witness_utxo"]["vout"][out_index]
                                input_amounts.append(str(utxo["value"]))
                                ev = utxo["value"] - inp_fee
                            if ev <= 0:
                                self.unec_utxos += 1
                                payment_stats["negative_ev"] += 1
                        inputs_dw.writerow(
                            {"id": self.withdraws, "input_amounts": input_amounts}
                        )
                        # Get fee info
                        fee = dec["fee"]
                        self.total_fees += fee
                        payment_stats["fees"] = fee
                        # Get real feerate
                        dec_tx = self.tester.decoderawtransaction(tx)
                        payment_stats["real_feerate"] = fee / dec_tx["vsize"] * 1000
                        # Spent utxo counts and input info
                        num_in = len(dec["inputs"])
                        self.count_sent += num_in
                        self.input_sizes.append(num_in)
                        payment_stats["num_inputs"] = num_in
                        payment_stats["num_outputs"] = len(dec["outputs"])
                        # Change info
                        payment_stats["change_amount"] = None
                        if change_pos is not None and change_pos != -1:
                            assert len(dec["tx"]["vout"]) == 2
                            change_out = dec["tx"]["vout"][change_pos]
                            payment_stats["change_amount"] = change_out["value"]
                            self.change_vals.append(change_out["value"])
                            self.count_change += 1
                        else:
                            assert len(dec["tx"]["vout"]) == 1
                            self.no_change[algo] += 1
                        # After listunspent
                        payment_stats["after_num_utxos"] = len(
                            self.tester.listunspent(0)
                        )
                        dw.writerow(payment_stats)
                        self.log.debug(
                            f"Op {self.ops} Sent {self.withdraws}th withdraw of {value} BTC using {num_in} inputs with fee {fee} ({feerate} BTC/kvB) and algo {algo}"
                        )
                        self.withdraws += 1
                    except JSONRPCException as e:
                        # Make sure all tracepoint events are consumed
                        try:
                            while True:
                                bpf["coin_selection_events"].pop()
                        except KeyError:
                            pass
                        self.log.warning(
                            f"Failure on op {self.ops} with tester sending {value} with error {str(e)}"
                        )
                self.utxo_set_sizes.append(len(self.tester.listunspent(0)))
                self.funder.generatetoaddress(1, gen_addr)
                self.ops += 1

            for f in scenario_files:
                f.close()

            final_result = self.log_sim_results(res, sum_csvw)
            res.write("----END SIMULATION RESULTS----\n\n\n")
            res.flush()
            self.log.info(header)
            self.log.info(final_result)


if __name__ == "__main__":
    CoinSelectionSimulation().main()
