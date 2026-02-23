// Test script for apshell JS integration

print("=== AlgoSh JavaScript Integration Test ===")
print("")

// Test helper functions
print("Testing algo() helper:")
print("  algo(1) =", algo(1))
print("  algo(0.5) =", algo(0.5))
print("  algo(100) =", algo(100))
print("")

// Test network info
print("Network:", network())
print("Connected:", connected())
print("")

// Test status
let st = status()
print("Status:")
print("  Network:", st.network)
print("  Connected:", st.connected)
print("  Write Mode:", st.writeMode)
print("")

// Test aliases (will be empty if none defined)
print("Aliases:", JSON.stringify(aliases()))
print("Sets:", JSON.stringify(sets()))
print("")

print("=== Test Complete ===")
