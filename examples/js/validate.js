// Validate the first signable account with a 0-ALGO self-transfer.
// Usage: apshell -js examples/js/validate.js

let account = null
let label = null

for (let acc of accounts()) {
    if (acc.isSignable) {
        account = acc.address
        label = acc.alias ? acc.alias : acc.address.substring(0, 8) + "..."
        break
    }
}

if (!account) {
    print("Error: No signable account found")
} else {
    print("Validating account: " + label)
    let result = validate(account)
    print("  txid: " + result.txid)
    print("  confirmed: " + result.confirmed)
    print("Validation complete!")
}
