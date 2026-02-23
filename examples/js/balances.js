// Show balances for all known accounts
for (let acc of accounts()) {
    let bal = balance(acc.address)
    let algoBalance = bal.algo / 1e6
    let signable = acc.isSignable ? " (signable)" : ""
    let name = acc.alias ? acc.alias : acc.address.substring(0, 8) + "..."
    print(name + ": " + algoBalance.toFixed(6) + " ALGO" + signable)
}
