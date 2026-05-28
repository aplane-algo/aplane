// Show current apshell scripting context.

let st = status()

print("Network: " + st.network)
print("Connected: " + st.connected)
print("Write Mode: " + st.writeMode)
print("")

print("Known aliases:")
for (let [name, address] of Object.entries(aliases())) {
    print("  " + name + " -> " + address)
}
if (Object.keys(aliases()).length === 0) {
    print("  (none)")
}

print("")
print("Known sets:")
for (let name of sets()) {
    let members = set(name) || []
    print("  " + name + " (" + members.length + ")")
}
if (sets().length === 0) {
    print("  (none)")
}

print("")
print("Known accounts:")
for (let acc of accounts()) {
    let name = acc.alias ? acc.alias : acc.address.substring(0, 8) + "..."
    let signable = acc.isSignable ? " signable" : ""
    print("  " + name + " [" + acc.keyType + "]" + signable)
}
if (accounts().length === 0) {
    print("  (none)")
}
