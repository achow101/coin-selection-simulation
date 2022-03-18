# Bitcoin Core Coin Selection Simulation

This repository contains data and results from running coin selection simulations

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
