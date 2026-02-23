"""Swap configuration — edit these values for your environment."""

# Algorand addresses
BUYER = "YOUR_BUYER_ADDRESS"
SELLER = "YOUR_SELLER_ADDRESS"

# Assets to swap (use 0 for ALGO)
ASA_A = 0           # what the buyer offers (ALGO)
ASA_B = 10458941    # what the seller offers (testnet USDC)

# Amounts in base units (microAlgos if ALGO, or smallest ASA unit)
ASA_A_AMOUNT = 1000000  # 1 ALGO (6 decimals)
ASA_B_AMOUNT = 1000000  # 1 USDC (6 decimals)
