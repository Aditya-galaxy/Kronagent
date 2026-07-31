"""
Unit and integration tests for cryptographic signing of forensic custody chains.
"""

from __future__ import annotations

import os
import boto3
from moto import mock_aws

from kronagent.crypto import LocalAsymmetricSigner, KmsSigner, get_signer
from kronagent.config import Settings
from kronagent.forensics import EvidenceItem


def test_local_asymmetric_signer_lifecycle(tmp_path) -> None:
    # 1. Setup local key PEM path
    key_pem = str(tmp_path / "kronagent_key.pem")

    # 2. First instantiation generates key
    signer = LocalAsymmetricSigner(key_pem)
    assert os.path.exists(key_pem)

    msg = b"forensic-custody-chain-payload-hash"
    sig = signer.sign(msg)
    assert len(sig) > 0

    # 3. Verification succeeds
    assert signer.verify(msg, sig) is True

    # 4. Verification fails on modified message
    assert signer.verify(b"different-payload", sig) is False

    # 5. Verification fails on modified signature
    bad_sig = sig[:-4] + b"AAAA"
    assert signer.verify(msg, bad_sig) is False

    # 6. Re-instantiating loads existing key instead of generating new one
    loaded_signer = LocalAsymmetricSigner(key_pem)
    assert loaded_signer.verify(msg, sig) is True


@mock_aws
def test_kms_signer_integration() -> None:
    # 1. Setup mock KMS Key
    kms_client = boto3.client("kms", region_name="us-east-1")
    key_res = kms_client.create_key(
        Description="Kronagent Test Key",
        KeyUsage="SIGN_VERIFY",
        CustomerMasterKeySpec="RSA_2048",
    )
    key_id = key_res["KeyMetadata"]["KeyId"]

    # 2. Instantiate KmsSigner
    signer = KmsSigner(key_id, region="us-east-1")

    msg = b"kms-test-forensics-custody-hash"
    sig = signer.sign(msg)
    assert len(sig) > 0

    # 3. Verification succeeds
    assert signer.verify(msg, sig) is True

    # 4. Verification fails on modified payload
    assert signer.verify(b"different-payload", sig) is False


def test_evidence_item_custody_verification_with_signature(tmp_path) -> None:
    key_pem = str(tmp_path / "kronagent_key.pem")
    signer = LocalAsymmetricSigner(key_pem)

    item = EvidenceItem(
        kind="aws.ebs.snapshot",
        target="i-abcd123",
        description="EBS snapshot",
    ).with_custody_signature(signer)

    # 1. Verification succeeds
    assert item.verify_custody(signer) is True

    # 2. Verification fails if manifest changes
    item_modified = item.model_copy(update={"target": "i-modified"})
    assert item_modified.verify_custody(signer) is False

    # 3. Verification fails if signature is altered
    item_bad_sig = item.model_copy(update={"custody_signature": "invalid_sig_base64"})
    assert item_bad_sig.verify_custody(signer) is False


def test_get_signer_factory(tmp_path) -> None:
    db_path = str(tmp_path / "kronagent.db")
    settings = Settings(
        kms_key_id="",
        db_path=db_path,
    )

    signer = get_signer(settings)
    assert isinstance(signer, LocalAsymmetricSigner)
    # Check that key was created in database directory
    expected_key_path = str(tmp_path / "kronagent_key.pem")
    assert signer.key_path == expected_key_path
