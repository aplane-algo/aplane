// Distribute ALGO from treasury to validators with low balance
// This is an example script - modify the parameters below

let treasury = "treasury"          // Alias of the source account
let minBalance = algo(100)         // Top up if below this
let topUpAmount = algo(10)         // Amount to send

let validators = set("validators")
if (!validators) {
    print("Error: No 'validators' set defined")
    print("Create one with: sets validators [addr1 addr2 ...]")
} else {
    print("Checking " + validators.length + " validators...")
    let toppedUp = 0
    
    for (let validator of validators) {
        let bal = balance(validator)
        if (bal.algo < minBalance) {
            print("  " + validator.substring(0, 8) + "... has " + (bal.algo / 1e6).toFixed(2) + " ALGO, topping up")
            send(treasury, validator, topUpAmount)
            toppedUp++
        }
    }
    
    if (toppedUp === 0) {
        print("All validators have sufficient balance")
    } else {
        print("Topped up " + toppedUp + " validators")
    }
}
