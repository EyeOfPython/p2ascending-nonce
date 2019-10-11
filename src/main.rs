//mod trade;
mod script_interpreter;
mod evaluation_assignment;

use cashcontracts::*;
use hex_literal::hex;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    //trade::create_trade_interactive().unwrap();
    let curve = secp256k1::Secp256k1::new();

    let alice_sk = secp256k1::SecretKey::from_slice(&hex!("11"))?;
    let alice_pk = secp256k1::PublicKey::from_secret_key(&curve, &alice_sk);

    let covenant_sk = secp256k1::SecretKey::from_slice(&hex!("50e3de05f2a071aa8f660c6bb70952967530f0abda141ae3c1b569576837311a"))?;
    let covenant_pk = secp256k1::PublicKey::from_secret_key(&curve, &covenant_sk);

    let bob_address = Address::from_cash_addr("bitcoincash:qza0yckn3j3wjpketurjpayvqzzdhvjflcdyg6d40d".to_string()).unwrap();

    let wallet_amount = 10_000;
    let payment_amount = 5_000;
    let tx_fee = 1000;
    let bob_output = P2PKHOutput {
        value: payment_amount - tx_fee,
        address: bob_address.clone(),
    };

    let mut outputs_preimage = Vec::new();
    let bob_tx_output = TxOutput {
        value: bob_output.value(),
        script: bob_output.script(),
    };
    bob_tx_output.write_to_stream(&mut outputs_preimage)?;
    let mut owner_preimage = Vec::with_capacity(32 + 8 + 8);
    owner_preimage.extend_from_slice(&single_sha256(&outputs_preimage));
    owner_preimage.extend_from_slice(&(payment_amount as u64).to_le_bytes());
    owner_preimage.extend_from_slice(&hex!("feffff7f00000080"));
    println!("owner_preimage: {}", hex::encode(&owner_preimage));
    let alice_sig = curve.sign(&secp256k1::Message::from_slice(&single_sha256(&owner_preimage))?, &alice_sk);

    let alice_input = P2AscendingNonce {
        lokad_id: hex!("b17c012c").to_vec(),
        old_value: wallet_amount,
        owner_pk: alice_pk.serialize().to_vec(),
        old_nonce: -0x7fff_ffff,
        spend_params: Some(P2AscendingNonceSpendParams::Nonce {
            payment_amount: payment_amount as i32,
            new_nonce: -0x7fff_fffe,
            owner_sig: alice_sig.serialize_der().to_vec(),
        }),
    };

    println!("{}", Address::from_bytes(AddressType::P2SH, hash160(&alice_input.script().to_vec())).cash_addr());

    let alice_output = P2AscendingNonce {
        lokad_id: hex!("b17c012c").to_vec(),
        old_value: wallet_amount - payment_amount,
        owner_pk: alice_pk.serialize().to_vec(),
        old_nonce: -0x7fff_fffe,
        spend_params: None,
    };

    let mut tx_build = UnsignedTx::new_simple();
    tx_build.add_input(UnsignedInput {
        output: Box::new(P2SHOutput { output: Box::new(alice_input.clone()) }),
        outpoint: TxOutpoint {
            tx_hash: tx_hex_to_hash("fda497320fa950d01d2e8cf4f1229fff733ce7073aa47ac06c175f210b4a9cb1").unwrap(),
            //tx_hash: tx_hex_to_hash("bb6dc256d6680015b5669aa6d22c85edb087b25728d478d90acdaf3496238ac9").unwrap(),
            vout: 0,
        },
        sequence: 0xffff_ffff,
    });
    tx_build.add_output(TxOutput {
        value: wallet_amount - payment_amount,
        script: P2SHOutput {
            output: Box::new(alice_output),
        }.script(),
    });
    tx_build.add_output(bob_tx_output);

    let pre_images = tx_build.pre_images(0x41);
    let pks = vec![covenant_pk.serialize().to_vec()];
    let sigs = pre_images.iter().map(|pre_image| {
        let mut pre_image_serialized = Vec::new();
        pre_image.write_to_stream(&mut pre_image_serialized).unwrap();
        curve.sign(&secp256k1::Message::from_slice(&double_sha256(&pre_image_serialized)).unwrap(), &covenant_sk).serialize_der().to_vec()
    }).collect::<Vec<_>>();

    let tx = tx_build.sign(sigs, pks);
    let mut tx_ser = Vec::new();
    tx.write_to_stream(&mut tx_ser)?;

    let p2sh_idx = 0;

    println!("tx len: {}", tx_ser.len());
    println!("tx hex: {}", hex::encode(tx_ser));
    let mut pre_image_serialized = Vec::new();
    let sig_ops = tx.inputs()[p2sh_idx].script.ops();
    let mut sig_script = Script::new(sig_ops[..sig_ops.len() - 1].to_vec());
    let redeem_script = alice_input.script();
    sig_script.extend(redeem_script);
    pre_images[p2sh_idx].write_to_stream(&mut pre_image_serialized).unwrap();
    println!("Preimage serialized: {}", hex::encode(&pre_image_serialized));
    println!("Preimage hash: {}", hex::encode(&single_sha256(&pre_image_serialized)));
    println!("Script: {}", sig_script);
    println!("Running interpreter now...");
    let mut interpreter = script_interpreter::ScriptInterpreter::new(sig_script, pre_image_serialized, 0);
    interpreter.run_interactive().unwrap();

    /*let wallet = Wallet::from_cash_addr(
        "bitcoincash:qzz99248gae60pvdkckdsegn7gwt4u5cuuv5fq8muw".to_string(),
    )?;
    let mut tx_build = wallet.init_tx(&[UtxoEntry {
        tx_id_hex: "d6f091913c53a3c1867486593d1f11eb70cc5d5f298d1615c63981a82a90250a".to_string(),
        vout: 3,
        amount: 1171,
    }]);
    tx_build.add_output(TxOutput {
        value: 976,
        script: P2PKHOutput {
            value: 0,
            address: Address::from_cash_addr("bitcoincash:qr4tqy4xye3y7cxtwxskr0l445lf55tnnchv8474jd".to_string())?,
        }.script(),
    });
    tx_build.add_leftover_output(wallet.address().clone(), 1000, 0x222).unwrap();
    let size = tx_build.estimate_size();
    println!("size = {}", size);
    let tx = tx_build.sign(vec![vec![]], vec![vec![]]);
    dbg!(tx.outputs());
*/
    /*let fee_addr = Address::from_cash_addr("bitcoincash:qp5x5tmxluwm62ny66zy9u4zuqvkmcv8sq2ceuxmwd".to_string())?;
    let wallet = Wallet::from_cash_addr(
        "bitcoincash:qzz99248gae60pvdkckdsegn7gwt4u5cuuv5fq8muw".to_string(),
    )?;
    let mut tx_build = wallet.init_tx(&[UtxoEntry {
        tx_id_hex: "333865066bc22177875f8342bb8e0c250869b1bbe335de4c6bf5b61af35cd0bc".to_string(),
        vout: 4,
        amount: 7874,
    }]);
    tx_build.add_input(cashcontracts::UnsignedInput {
        outpoint: TxOutpoint {
            tx_hash: tx_hex_to_hash("bc01d764c9dc66d7e9124de48956ef30320a8d4c6d179a2aeae5bb4c039b89e1").unwrap(),
            vout: 1,
        },
        sequence: 0xffff_ffff,
        output: cashcontracts::AdvancedTradeOffer {
            value: 0x222,
            lokad_id: b"EXCH".to_vec(),
            version: 2,
            power: 0,
            is_inverted: false,
            token_id: "28022a6d389f3ecd5ae96fb3bc63083e95d2f2ebbffdb544fe186125640eb117".clone(),
            token_type: 1,
            sell_amount_token: 1700,
            price: 2,
            dust_amount: 0x222,
            address: wallet.address().clone(),
            fee_address: Some(fee_addr.clone()),
            fee_divisor: Some(500),
            spend_params: Some(AdvancedTradeOfferSpendParams::Cancel),
        },
    });
    tx_build.add_output()
    tx_build.add_leftover_output(wallet.address().clone(), 1000, 0x222);

    let tx = tx_build.sign(vec![vec![

    ]], vec![b"0340c2f9a0c8c2e82fbc03a50b0a601663d25a4f83dff4cd6e0201feb78513a8ed".to_vec()]);
    let mut tx_ser = Vec::new();
    tx.write_to_stream(&mut tx_ser);
    println!("{}", hex::encode(&tx_ser));*/

    //let wallet_secret = secp256k1::SecretKey::from_slice(b"0000000000000000000000000000000000000000000000000000000000000000").unwrap();
    //curve.sign(&secp256k1::Message::from_slice(&double_sha256(&pre_image_serialized)).unwrap(), &wallet_secret).serialize_der();

    Ok(())
}
