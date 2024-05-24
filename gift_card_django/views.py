import json, logging
import os
from re import T
import re
from unittest.util import _MIN_COMMON_LEN

from django.http import HttpResponse
from django.shortcuts import render, redirect
from pycardano import (
    UTxO,
    PlutusV2Script,
    Transaction,
    TransactionInput,
    TransactionOutput,
    TransactionBuilder,
    TransactionWitnessSet,
    Value,
    MultiAsset,
    Redeemer,
    PlutusData,
    RedeemerTag,
    BlockFrostChainContext,
    TransactionBody,
    Network,
    Address,
    plutus_script_hash,
    VerificationKeyWitness,
)

from . import utils

# setup logging with datetime (matching django style)
logging.basicConfig(
    format='[%(asctime)s] %(levelname)s "%(message)s"',
    datefmt="%d/%b/%Y %H:%M:%S",
    level=logging.DEBUG,
)
logger = logging.getLogger(__name__)


def home(request):
    if request.method == "POST":
        context = {"validators": utils.read_validator()}

        request.session["utxos"] = json.loads(request.body)
        request.session["wallet_connected"] = True
        print(
            "wallet is connected on post: ",
            request.session.get("wallet_connected", False),
        )

        # get utxos from json body
        utxos = [
            UTxO.from_cbor(bytes.fromhex(utxo))
            for utxo in json.loads(request.body)["utxos"]
        ]
        logger.debug(utxos[0])
        # filter out utxos that have multi assets
        utxos = [utxo for utxo in utxos if not utxo.output.amount.multi_asset]
        logger.debug(utxos)
        return HttpResponse("success")

    elif request.method == "GET":
        context = {"validators": utils.read_validator()}
        logger.debug(
            "wallet is connected: {}".format(
                request.session.get("wallet_connected", False)
            )
        )
        context["wallet_connected"] = request.session.get("wallet_connected", False)
        return render(request, "base.html", context=context)


def make_contracts(request):
    if request.method == "POST":
        context = {"validators": utils.read_validator()}

        token_name = request.POST["tokenName"]
        request.session["token_name"] = token_name
        utxos = request.session.get("utxos", [])["utxos"]
        output_reference = utils.get_out_ref(utxos)
        if not output_reference:
            return HttpResponse("no utxos")
        user_addr = output_reference.output.address

        parameterized_contracts = utils.apply_params(
            token_name, output_reference, context["validators"]
        )

        # save the value in session
        request.session["parameterized_gift_card"] = parameterized_contracts[
            "gift_card"
        ]
        request.session["parameterized_redeem"] = parameterized_contracts["redeem"]
        request.session["policy_id"] = parameterized_contracts["policy_id"]
        request.session["lock_address"] = parameterized_contracts["lock_address"]
        request.session["out_ref"] = {
            "tx_hash": str(output_reference.input.transaction_id),
            "index": output_reference.input.index,
        }
        request.session["user_addr"] = user_addr.encode()

        # redirect to lock page
        logger.debug(parameterized_contracts)
        logger.info("redirecting to lock page...")
        return redirect("lock")


def lock(request):
    if request.method == "GET":
        ctx = {}

        # read from session
        ctx["parameterized_gift_card"] = request.session["parameterized_gift_card"]
        ctx["parameterized_redeem"] = request.session["parameterized_redeem"]
        ctx["policy_id"] = request.session["policy_id"]
        ctx["lock_address"] = request.session["lock_address"]

        return render(request, "lock.html", context=ctx)

    elif request.method == "POST":
        # build, sign, submit tx
        logger.info("building tx...")
        request.session["ada_value"] = int(request.POST["giftADA"])

        builder = utils.get_mint_builder(request)

        tx_body = builder.build(change_address=request.session["user_addr"])
        script_witness = builder.build_witness_set()

        unsigned_lock_tx = Transaction(tx_body, script_witness)

        request.session["lock_ttl"] = tx_body.ttl
        request.session["lock_val_start"] = tx_body.validity_start
        request.session["tx_body"] = tx_body.to_cbor_hex()
        request.session["script_witness"] = script_witness.to_cbor_hex()
        request.session["unsigned_lock_tx"] = unsigned_lock_tx.to_cbor_hex()

        return redirect("lock_sign")


def lock_sign(request):
    if request.method == "GET":
        context = {
            "unsigned_lock_tx": request.session["unsigned_lock_tx"],
        }

        return render(request, "lock_sign.html", context=context)

    elif request.method == "POST":
        data = json.loads(request.body)
        vkey_witness = data["witness"]

        builder = utils.get_mint_builder(
            request,
            request.session["lock_ttl"],
            request.session["lock_val_start"],
        )

        tx_body = builder.build(change_address=request.session["user_addr"])
        script_witness = builder.build_witness_set()

        vkey_witnesses = [VerificationKeyWitness.from_cbor(vkey_witness[6:])]
        # need to strip the cbor tag

        script_witness.vkey_witnesses = vkey_witnesses

        logger.debug("script witness: {}".format(script_witness))

        signed_lock_tx = Transaction(tx_body, script_witness)

        request.session["lock_tx_hash"] = str(signed_lock_tx.id)

        logger.debug("signed tx: {}".format(signed_lock_tx.to_cbor_hex()))

        bf_context = utils.get_bf_context()
        logger.debug("tx id: {}".format(signed_lock_tx.id))
        bf_context.submit_tx(signed_lock_tx)
        # TODO: error handling for submiting tx
        return HttpResponse("success")


def lock_success(request):
    lock_tx_hash = request.session["lock_tx_hash"]

    tx_status = utils.get_tx_status(lock_tx_hash)

    context = {
        "lock_tx_hash": lock_tx_hash,
        "tx_status": tx_status,
    }

    return render(request, "lock_success.html", context=context)


def unlock(request):
    if request.method == "GET":
        pass

    elif request.method == "POST":
        # build, sign, submit tx
        logger.info("building unlocking tx...")

        builder = utils.get_burn_builder(request)

        tx_body = builder.build(change_address=request.session["user_addr"])
        script_witness = builder.build_witness_set()

        unsigned_unlock_tx = Transaction(tx_body, script_witness)

        request.session["unlock_ttl"] = tx_body.ttl
        request.session["unlock_val_start"] = tx_body.validity_start
        request.session["unsigned_unlock_tx"] = unsigned_unlock_tx.to_cbor_hex()

        return redirect("unlock_sign")


def unlock_sign(request):
    if request.method == "GET":
        context = {
            "unsigned_unlock_tx": request.session["unsigned_unlock_tx"],
        }

        return render(request, "unlock_sign.html", context=context)

    elif request.method == "POST":
        data = json.loads(request.body)
        vkey_witness = data["witness"]

        builder = utils.get_burn_builder(
            request,
            request.session["unlock_ttl"],
            request.session["unlock_val_start"],
        )

        tx_body = builder.build(change_address=request.session["user_addr"])
        script_witness = builder.build_witness_set()

        vkey_witnesses = [VerificationKeyWitness.from_cbor(vkey_witness[6:])]
        # need to strip the cbor tag

        script_witness.vkey_witnesses = vkey_witnesses

        logger.debug("script witness: {}".format(script_witness))

        signed_unlock_tx = Transaction(tx_body, script_witness)

        request.session["unlock_tx_hash"] = str(signed_unlock_tx.id)

        logger.debug("signed tx: {}".format(signed_unlock_tx.to_cbor_hex()))

        bf_context = utils.get_bf_context()
        logger.debug("tx id: {}".format(signed_unlock_tx.id))
        bf_context.submit_tx(signed_unlock_tx)

        return HttpResponse("success")


def unlock_success(request):
    unlock_tx_hash = request.session["unlock_tx_hash"]
    context = {
        "unlock_tx_hash": unlock_tx_hash,
        "tx_status": utils.get_tx_status(unlock_tx_hash),
    }

    return render(request, "unlock_success.html", context=context)
