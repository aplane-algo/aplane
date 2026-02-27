# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 aPlane Authors

"""
aPlane Python SDK - Transaction signing via apsignerd

Data directory: ~/.apclient (override with APCLIENT_DATA)

Token provisioning:
    from aplane import request_token_to_file
    request_token_to_file()  # operator must approve in apadmin

Usage:
    from aplane import SignerClient, send_raw_transaction

    client = SignerClient.from_env()
    signed_txn = client.sign_transaction(txn)
    txid = send_raw_transaction(algod_client, signed_txn)
    client.close()
"""

from .signer import (
    # Main client
    SignerClient,

    # Submission helpers
    send_raw_transaction,
    assemble_group,

    # Token provisioning
    request_token,
    request_token_to_file,

    # Utility
    load_token,
    load_config,

    # Exceptions
    SignerError,
    AuthenticationError,
    SigningRejectedError,
    SignerUnavailableError,
    KeyNotFoundError,
    KeyDeletionError,
    TokenProvisioningError,
    TransactionRejectedError,
    LogicSigRejectedError,
    InsufficientFundsError,
    InvalidTransactionError,

    # Types
    RuntimeArg,
    KeyInfo,
    SSHConfig,
    ClientConfig,
    CreationParam,
    KeyTypeInfo,
    GenerateResult,
)

__version__ = "0.2.0"
__all__ = [
    # Main client
    "SignerClient",

    # Submission helpers
    "send_raw_transaction",
    "assemble_group",

    # Token provisioning
    "request_token",
    "request_token_to_file",

    # Utility
    "load_token",
    "load_config",

    # Exceptions
    "SignerError",
    "AuthenticationError",
    "SigningRejectedError",
    "SignerUnavailableError",
    "KeyNotFoundError",
    "KeyDeletionError",
    "TokenProvisioningError",
    "TransactionRejectedError",
    "LogicSigRejectedError",
    "InsufficientFundsError",
    "InvalidTransactionError",

    # Types
    "RuntimeArg",
    "KeyInfo",
    "SSHConfig",
    "ClientConfig",
    "CreationParam",
    "KeyTypeInfo",
    "GenerateResult",
]
