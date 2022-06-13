# Bitcoin Core Coin Selection Simulation

This repository contains data and results from running coin selection simulations

## Running Simulations

The simulation script is `scripts/simulation.py`. It is based on a slimmed down version of the Bitcoin Core test framework.

To run, first compile the Bitcoin Core branch you wish to simulate. Then find the `config.ini` file that is usually located in `test/config.ini`.

GitPython will also need to be installed and available to the Python executed by the root user:

    sudo pip install gitpython

A simulation can be run with:

    sudo scripts/simulation.py --scenario <path/to/scenario/file> <path/to/config.ini> results/

Note that the script uses USDT Tracepoints which requires either running the script as root, or setting the requisite privileges for using tracepoints as per [these instructions](https://github.com/bitcoin/bitcoin/pull/24358#issuecomment-1083149220).

The script uses GitPython which executes git itself in order to get some information about the repo.
However sometimes git does not like it when the repo is owned by a different user than the one that is executing commands on it, so you may need to run the following:

    sudo sudo git config --global --add safe.directory <path/to/repo>

## Results

Inside the results directory is a directory for the commit hash the simulation was run on.
Inside of the commit hash directory are directories for each simulation run.
These are named with random generated unique ids.
Inside each simulation run's directory are the files:

* `results.txt`: Summarized data about the simulation taken every 500 operations and at the end.
* `full_results.csv`: Data about each payment sent from the test wallet, including amount, fees, feerates, algorithm used, etc.
* `inputs.csv`: The values of every input for each payment
* `utxos.csv`: The values of each UTXO in the UTXO pool prior to each payment.
* `sim_debug.log`: Log file of every operation in the simulation, primarily for debugging purposes.

## Scenarios

CSV files containing the simulation scenarios are stored in this directory.
Each line contains a pair of the amount being sent/withdrawn from the wallet, and the feerate it is done at.
If the amount is positive, the wallet is receiving this amount.
If it is negative, the wallet is sending the that amount.
