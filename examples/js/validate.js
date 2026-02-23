// Validate an account by sending 0 ALGO to itself
// Usage: apshell -js validate.js <account>
//   or in REPL: js validate.js (uses first signable account)

let account = null

// Try to use first signable account
for (let acc of accounts()) {
    if (acc.isSignable) {
        account = acc.address
        break
    }
}

if (!account) {
    print("Error: No signable account found")
} else {
    print("Validating account: " + account)
    for (let i = 1; i <= 2; i++) {
        print("  Attempt " + i + " of 2...")
        let result = send(account, account, 0)
        print("    txid: " + result.txid)
    }
    print("Validation complete!")
}
