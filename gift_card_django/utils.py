from dataclasses import dataclass
import os, json, opshin, cbor2
from venv import logger
from typing import List, Tuple, Union
from pycardano import (
    BlockFrostChainContext,
    #     PaymentSigningKey,
    #     PaymentVerificationKey,
    Address,
    PlutusV2Script,
    PlutusData,
    plutus_script_hash,
    Transaction,
    TransactionBody,
    TransactionInput,
    TransactionWitnessSet,
    Redeemer,
    RedeemerTag,
    Datum,
    #     ScriptHash,
    Network,
    UTxO,
    IndefiniteList,
    TransactionBuilder,
    TransactionOutput,
    MultiAsset,
    Value,
)

# from pycardano.hash import (
#     TransactionId,
#     ScriptHash,
# )


def read_validator() -> dict:
    with open("/home/lincon/aiken/gift-card_pycardano/plutus.json", "r") as f:
        validators = json.load(f)

    for val in validators["validators"]:
        if val["title"] == "oneshot.gift_card":
            gift_card = val
        elif val["title"] == "oneshot.redeem":
            redeem = val

    return {
        "redeem": {
            "type": "PlutusV2",
            # "script_bytes": PlutusV2Script(bytes.fromhex(redeem["compiledCode"])),
            "script": redeem["compiledCode"],
            # "script_hash": ScriptHash(bytes.fromhex(redeem["hash"]))
        },
        "gift_card": {
            "type": "PlutusV2",
            # "script_bytes": PlutusV2Script(bytes.fromhex(gift_card["compiledCode"])),
            "script": gift_card["compiledCode"],
            # "script_hash": ScriptHash(bytes.fromhex(gift_card["hash"]))
        },
    }


# Address.from_primitive(bytes.fromhex('e06bc0fb7bf3fb63213db81655a33d8c4a7c1c7e4bd75fc33ff176784b'))
@dataclass
class TxHash(PlutusData):
    CONSTR_ID = 0
    payload: bytes


@dataclass
class UtxoRef(PlutusData):
    tx_hash: TxHash
    index: int


@dataclass
class TokenName(PlutusData):
    # CONSTR_ID = 0
    token_name: bytes
    # utxo_ref: UtxoRef


def apply_params(token_name: str, output_reference, validators):
    gift_card = PlutusV2Script(bytes.fromhex(validators["gift_card"]["script"]))
    redeem = PlutusV2Script(bytes.fromhex(validators["redeem"]["script"]))

    # select the biggest utxo as reference
    # output_reference = sorted(utxos, key=lambda x: x.output.amount.coin)[0]

    original_datum = PlutusData.from_dict({"bytes": token_name.encode("utf-8").hex()})
    empty_datum = PlutusData()

    tx_hash_datum = TxHash(output_reference.input.transaction_id.payload)
    utxo_ref_datum = UtxoRef(
        # tx_hash=output_reference.input.transaction_id,
        tx_hash=tx_hash_datum,
        index=output_reference.input.index,
    )
    token_name_datum = TokenName(token_name.encode("utf-8"))

    parameterized_gift_card_0 = opshin.builder.apply_parameters(
        gift_card,
        PlutusData.from_dict({"bytes": token_name.encode("utf-8").hex()}),
        utxo_ref_datum,
    )

    parameterized_gift_card = PlutusV2Script(
        cbor2.dumps(bytes.fromhex(parameterized_gift_card_0.hex()))
    )

    policy_id = plutus_script_hash(parameterized_gift_card_0)

    # parameterize redeem with token name and policy id
    parameterized_redeem_0 = opshin.builder.apply_parameters(
        redeem,
        # token name as string
        PlutusData.from_dict({"bytes": token_name.encode("utf-8").hex()}),
        # policy id as bytes
        PlutusData.from_dict(
            {
                "bytes": policy_id.payload.hex(),
            }
        ),
    )

    parameterized_redeem = PlutusV2Script(
        cbor2.dumps(bytes.fromhex(parameterized_redeem_0.hex()))
    )

    lock_address = Address(
        plutus_script_hash(parameterized_redeem_0), network=Network.TESTNET
    )

    logger.debug("original datum: {}".format(original_datum.hex()))
    logger.debug("empty datum hex: {}".format(empty_datum.to_primitive()))
    logger.debug("empty datum cbor hex: {}".format(empty_datum.to_cbor_hex()))
    logger.debug("token name datum: {}".format(token_name_datum.to_cbor_hex()))
    logger.debug("utxo ref datum: {}".format(utxo_ref_datum.to_cbor_hex()))
    logger.debug("lock address: {}".format(lock_address.encode()))
    logger.debug("original redeemer hash: %s", plutus_script_hash(redeem))
    logger.debug("redeemer hash: %s", plutus_script_hash(parameterized_redeem))
    logger.debug("redeemer hash_0: %s", plutus_script_hash(parameterized_redeem_0))
    logger.debug("original gift card hash: %s", plutus_script_hash(gift_card))
    logger.debug("gift card hash: %s", plutus_script_hash(parameterized_gift_card))
    logger.debug("gift card_0 hash: %s", plutus_script_hash(parameterized_gift_card_0))

    # return everything as string for easy JSON serialization
    return {
        "redeem": parameterized_redeem_0.hex(),
        "gift_card": parameterized_gift_card_0.hex(),
        "policy_id": policy_id.payload.hex(),
        "lock_address": lock_address.encode(),
    }


def get_out_ref(utxos):
    # convert str to UTxO objects
    logger.debug(utxos[0])
    utxos = [UTxO.from_cbor(bytes.fromhex(utxo)) for utxo in utxos]

    filtered_utxos = [utxo for utxo in utxos if not utxo.output.amount.multi_asset]

    if filtered_utxos:
        # select the biggest utxo as reference
        logger.debug("filtered utxos: {}".format(filtered_utxos))  #
        # return the highest value utxo
        return sorted(filtered_utxos, key=lambda x: x.output.amount.coin)[-1]

    return None


def compose_signed_transaction(
    tx_body, script_witness, unsigned_tx: str, witness: str
) -> Transaction:
    """This function is used to compose a signed transaction.

    Args:
        unsigned_tx: unsigned transaction in cbor format.
        witness: witness returned after signing tx, in cbor format.

    Returns:
        The signed transaction in cbor format, ready for submission.

    """
    tx = Transaction.from_cbor(unsigned_tx)

    # tx = Transaction(tx_body, script_witness)
    # logger.debug("unsigned tx: {}".format(tx.to_cbor_hex()))
    user_witness = TransactionWitnessSet.from_cbor(witness)
    # tx.transaction_witness_set = witness
    tx.transaction_witness_set = user_witness

    logger.debug(
        repr({"message": "Signed tx successfully composed.", "data": {"tx_id": tx.id}})
    )

    return tx


def get_bf_context():
    return BlockFrostChainContext(
        project_id=os.environ["BLOCKFROST_PROJECT_ID"],
        base_url="https://cardano-preprod.blockfrost.io/api",
    )


def get_utxo(address: str, tx_in: TransactionInput) -> UTxO:
    bf_context = get_bf_context()
    utxos = bf_context.utxos(address=address)
    for utxo in utxos:
        if (
            utxo.input.transaction_id == tx_in.transaction_id
            and utxo.input.index == tx_in.index
        ):
            return utxo


def get_tx_status(tx_hash: str) -> str:
    """This function is used to get the status of a transaction.

    Args:
        tx_hash: transaction hash.

    Returns:
        The status of the transaction.

    """
    bf_context = get_bf_context()

    try:
        res = bf_context.api.transaction(tx_hash, return_type="json")
        return "confirmed"

    except Exception as e:
        if e.status_code == 404:
            return "pending"

        return "error - {}: {}, {}".format(e.status_code, e.error, e.message)


def get_mint_builder(
    request, ttl: int | None = None, validity_start: int | None = None
) -> TransactionBuilder:
    # prepare data for tx
    ada_value = request.session["ada_value"]
    policy_id = request.session["policy_id"]
    token_name = request.session["token_name"].encode().hex()

    gift_card_script = PlutusV2Script(
        bytes.fromhex(request.session["parameterized_gift_card"])
    )
    redeem_script = PlutusV2Script(
        bytes.fromhex(request.session["parameterized_redeem"])
    )
    nft_asset = MultiAsset.from_primitive(
        {
            policy_id: {
                token_name: 1,
            }
        }
    )
    data = Mint()
    mint_redeemer = MintRdmr(data)

    out_ref = request.session["out_ref"]
    tx_in = TransactionInput.from_primitive((out_ref["tx_hash"], out_ref["index"]))
    tx_out_1 = TransactionOutput(
        address=request.session["lock_address"],
        amount=Value(ada_value * 1000000),
        datum=data,
    )
    tx_out_2 = TransactionOutput(
        address=request.session["user_addr"],
        amount=Value(2 * 1000000, nft_asset),
    )

    utxos_from_session = request.session.get("utxos", [])["utxos"]
    utxo = [
        utxo
        for utxo in utxos_from_session
        if UTxO.from_cbor(bytes.fromhex(utxo)).input == tx_in
    ]

    # build tx
    bf_context = get_bf_context()
    builder = TransactionBuilder(bf_context, ttl=ttl, validity_start=validity_start)
    builder.mint = nft_asset
    builder.add_input(UTxO.from_cbor(bytes.fromhex(utxo[0])))
    builder.add_output(tx_out_1)
    builder.add_output(tx_out_2)
    builder.add_minting_script(gift_card_script, mint_redeemer)

    return builder


def get_burn_builder(request, ttl: int | None = None, validity_start: int | None = None
) -> TransactionBuilder:
    # prepare data for tx
    policy_id = request.session["policy_id"]
    token_name = request.session["token_name"].encode().hex()

    gift_card_script = PlutusV2Script(
        bytes.fromhex(request.session["parameterized_gift_card"])
    )
    redeem_script = PlutusV2Script(
        bytes.fromhex(request.session["parameterized_redeem"])
    )
    nft_asset = MultiAsset.from_primitive(
        {
            policy_id: {
                token_name: -1,
            }
        }
    )
    burn_redeemer = BurnRdmr()

    lock_tx_utxo = request.session["lock_tx_hash"]
    lock_address = request.session["lock_address"]

    # get the utxo at the redeem validator's address
    tx_in_1 = TransactionInput.from_primitive((lock_tx_utxo, 0))
    script_utxo = get_utxo(lock_address, tx_in_1)

    # get the utxo at the user's address
    tx_in_2 = TransactionInput.from_primitive((lock_tx_utxo, 1))
    nft_utxo = get_utxo(request.session["user_addr"], tx_in_2)

    # build tx
    bf_context = get_bf_context()
    builder = TransactionBuilder(bf_context, ttl=ttl, validity_start=validity_start)
    builder.mint = nft_asset
    builder.add_script_input(  # add an empty redeemer
        script_utxo, redeem_script, datum=None, redeemer=Redeemer(PlutusData())
    )
    builder.add_input(nft_utxo)
    builder.add_minting_script(gift_card_script, burn_redeemer)

    return builder


@dataclass
class Mint(PlutusData):
    CONSTR_ID = 0


@dataclass
class Burn(PlutusData):
    CONSTR_ID = 1


@dataclass
class MintRdmr(Redeemer):
    data: Mint


@dataclass
class BurnRdmr(Redeemer):
    data: Burn = Burn()
    # tag: RedeemerTag = RedeemerTag.SPEND
