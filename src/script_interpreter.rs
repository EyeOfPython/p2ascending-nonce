use cashcontracts::{Script, Op, OpCodeType};
use cashcontracts::{single_sha256, double_sha256, hash160, serialize::*};
use secp256k1::{Secp256k1, All, PublicKey, Signature, Message};
use byteorder::{LittleEndian, WriteBytesExt, ReadBytesExt};
use std::collections::HashMap;

use std::io::{self, Write, Read};
use text_io::{read, try_read, try_scan};

pub struct ScriptInterpreter {
    stack: Vec<Vec<u8>>,
    alt_stack: Vec<Vec<u8>>,
    curve: Secp256k1<All>,
    pre_image_serialized: Vec<u8>,
    jump_table: HashMap<usize, usize>,
    instruction_pointer: usize,
    script: Script,
    lock_time: u32,
}

#[derive(Clone, Copy, Debug)]
pub enum ScriptError {
    InvalidPubKey,
    InvalidSignatureFormat,
    InvalidSignature,
    VerifyFailed,
    NotImplemented,
    ScriptFinished,
}

/*fn encode_bool(b: bool) -> Vec<u8> {
    if b {
        vec![0x01]
    } else {
        vec![]
    }
}

fn vec_to_int(vec: &[u8]) -> i32 {
    if vec.len() == 0 {
        return 0;
    }
    let mut shift = 0;
    let mut int = 0;
    let sign_bit = vec[vec.len() - 1] & 0x80;
    for (i, value) in vec.iter().enumerate() {
        if i == vec.len() - 1 && sign_bit != 0 {
            int += ((*value ^ sign_bit) as i32) << (shift);
            int *= -1;
        } else {
            int += (*value as i32) << (shift);
            shift += 8;
        }
    }
    int
}

fn encode_minimally(vec: &mut Vec<u8>) {
    // If the last byte is not 0x00 or 0x80, we are minimally encoded.
    if let Some(&last) = vec.last() {
        if last & 0x7f != 0 {
            return;
        }
        // If the script is one byte long, then we have a zero, which encodes as an
        // empty array.
        if vec.len() == 1 {
            vec.clear();
            return;
        }
        // If the next byte has it sign bit set, then we are minimally encoded.
        if vec[vec.len() - 2] & 0x80 != 0 {
            return;
        }
        // We are not minimally encoded, we need to figure out how much to trim.
        let mut i = vec.len() - 1;
        while i > 0 {
            // We found a non zero byte, time to encode.
            if vec[i - 1] != 0 {
                if vec[i - 1] & 0x80 != 0 {
                    // We found a byte with it sign bit set so we need one more byte.
                    vec[i] = last;
                    i += 1;
                } else {
                    // the sign bit is clear, we can use it.
                    vec[i - 1] |= last;
                }
                vec.resize(i, 0u8);
                return;
            }
            i -= 1;
        }
        vec.resize(i, 0u8);
    }
}

pub fn encode_int(int: i32) -> Vec<u8> {
    let mut vec = Vec::new();
    vec.write_i32::<LittleEndian>(int);
    encode_minimally(&mut vec);
    vec
}*/

fn build_jump_table(script: &Script) -> Result<HashMap<usize, usize>, ()> {
    fn recurse(if_idx: usize, script: &Script, hash_map: &mut HashMap<usize, usize>) -> usize {
        let mut i = if_idx + 1;
        let mut else_idx = None;
        loop {
            let op = script.ops().get(i).unwrap();
            match op {
                Op::Code(OpCodeType::OpIf) => {
                    i = recurse(i, script, hash_map);
                },
                Op::Code(OpCodeType::OpElse) => {
                    else_idx = Some(i);
                    hash_map.insert(if_idx, i);
                },
                Op::Code(OpCodeType::OpEndIf) => {
                    hash_map.insert(else_idx.unwrap(), i);
                    return i;
                },
                _ => {},
            }
            i += 1;
        }
    }
    let mut hash_map = HashMap::new();
    if let Some(if_idx) = script.ops().iter().position(|op| op == &Op::Code(OpCodeType::OpIf)) {
        recurse(if_idx, script, &mut hash_map);
    }
    //println!("HashMap:");
    //println!("{:?}", hash_map);
    Ok(hash_map)
}

impl ScriptInterpreter {
    pub fn new(script: Script, pre_image_serialized: Vec<u8>, lock_time: u32) -> Self {
        ScriptInterpreter {
            stack: Vec::new(),
            alt_stack: Vec::new(),
            curve: Secp256k1::new(),
            jump_table: build_jump_table(&script).unwrap(),
            script,
            instruction_pointer: 0,
            pre_image_serialized,
            lock_time,
        }
    }

    pub fn run_interactive(&mut self) -> Result<(), ScriptError> {
        while self.instruction_pointer < self.script.ops().len() {
            self.print_stack();
            let op = self.script.ops()[self.instruction_pointer].clone();
            print!("Running: {}\n", op);
            io::stdout().flush().unwrap();
            self.run_op()?;
            //if op == Op::Code(OpCodeType::OpHash256) || op == Op::Code(OpCodeType::OpHash160) {
            //    self.print_stack();
                let _: String = read!("{}\n");
            //}
            println!("----------------------------------------------------");
        }
        self.print_stack();
        Ok(())
    }

    pub fn run(&mut self) -> Result<bool, ScriptError> {
        while self.instruction_pointer < self.script.ops().len() {
            self.run_op()?;
        }
        Ok(&self.stack[0] == &[1])
    }

    pub fn run_op(&mut self) -> Result<(), ScriptError> {
        if self.instruction_pointer >= self.script.ops().len() {
            return Err(ScriptError::ScriptFinished);
        }
        let op = &self.script.ops()[self.instruction_pointer];
        match op {
            Op::Push(data) => {
                self.stack.push(data.clone());
                self.instruction_pointer += 1;
                Ok(())
            },
            Op::Code(code) => self.run_op_code(*code),
        }
    }

    pub fn stack(&self) -> &[Vec<u8>] {
        &self.stack
    }

    pub fn print_stack(&self) {
        for (i, item) in self.stack.iter().rev().enumerate() {
            println!("{:5}: {}", i, hex::encode(item));
        }
    }

    fn run_op_code(&mut self, op_code: OpCodeType) -> Result<(), ScriptError> {
        use cashcontracts::OpCodeType::*;
        use self::ScriptError::*;
        match op_code {
            OpSwap => {
                let top = self.stack.remove(self.stack.len() - 1);
                self.stack.insert(self.stack.len() - 1, top);
            },
            OpDup => {
                self.stack.push(self.stack[self.stack.len() - 1].clone());
            },
            OpOver => {
                self.stack.push(self.stack[self.stack.len() - 2].clone());
            },
            Op2Dup => {
                self.stack.extend(
                    self.stack[self.stack.len() - 2..].iter().cloned().collect::<Vec<_>>()
                );
            },
            Op2Swap => {
                let item1 = self.stack.remove(self.stack.len() - 1);
                let item2 = self.stack.remove(self.stack.len() - 1);
                let item3 = self.stack.remove(self.stack.len() - 1);
                let item4 = self.stack.remove(self.stack.len() - 1);
                self.stack.push(item2);
                self.stack.push(item1);
                self.stack.push(item4);
                self.stack.push(item3);
            },
            Op3Dup => {
                self.stack.extend(
                    self.stack[self.stack.len() - 3..].iter().cloned().collect::<Vec<_>>()
                );
            },
            OpTuck => {
                self.stack.insert(self.stack.len() - 2, self.stack[self.stack.len() - 1].clone());
            },
            OpPick => {
                let offset = vec_to_int(&self.stack.remove(self.stack.len() - 1)) as usize;
                self.stack.push(self.stack[self.stack.len() - offset - 1].clone());
            },
            OpRoll => {
                let offset = vec_to_int(&self.stack.remove(self.stack.len() - 1)) as usize;
                let item = self.stack.remove(self.stack.len() - offset - 1);
                self.stack.push(item);
            },
            OpDrop => {
                self.stack.remove(self.stack.len() - 1);
            },
            Op2Drop => {
                self.stack.remove(self.stack.len() - 1);
                self.stack.remove(self.stack.len() - 1);
            },
            OpNip => {
                self.stack.remove(self.stack.len() - 2);
            },
            OpRot => {
                let third = self.stack.remove(self.stack.len() - 3);
                self.stack.push(third);
            },
            OpToAltStack => {
                let top = self.stack.remove(self.stack.len() - 1);
                self.alt_stack.push(top);
            },
            OpFromAltStack => {
                let top = self.alt_stack.remove(self.alt_stack.len() - 1);
                self.stack.push(top);
            },
            OpCat => {
                let mut first = self.stack.remove(self.stack.len() - 1);
                let mut second = self.stack.remove(self.stack.len() - 1);
                second.append(&mut first);
                self.stack.push(second);
            },
            OpSplit => {
                let split_idx = vec_to_int(&self.stack.remove(self.stack.len() - 1)) as usize;
                let top = self.stack.remove(self.stack.len() - 1);
                let (left, right) = top.split_at(split_idx);
                self.stack.push(left.to_vec());
                self.stack.push(right.to_vec());
            },
            OpNum2Bin => {
                let bytes = vec_to_int(&self.stack.remove(self.stack.len() - 1)) as usize;
                let top = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                let mut vec = Vec::with_capacity(bytes);
                vec.write_i32::<LittleEndian>(top.abs()).unwrap();
                vec.extend((vec.len()..bytes-1).into_iter().map(|_| 0));
                vec.push(if top < 0 { 0x80 } else { 0 });
                self.stack.push(vec);
            },
            OpBin2Num => {
                let mut top = self.stack.remove(self.stack.len() - 1);
                encode_minimally(&mut top);
                self.stack.push(top);
            },
            OpSize => {
                let top = &self.stack[self.stack.len() - 1];
                self.stack.push(encode_int(top.len() as i32));
            },
            OpHash256 => {
                let top = self.stack.remove(self.stack.len() - 1);
                self.stack.push(double_sha256(&top).to_vec());
            },
            OpSha256 => {
                let top = self.stack.remove(self.stack.len() - 1);
                self.stack.push(single_sha256(&top).to_vec());
            },
            OpHash160 => {
                let top = self.stack.remove(self.stack.len() - 1);
                self.stack.push(hash160(&top).to_vec());
            },
            OpEqual | OpEqualVerify => {
                let first = self.stack.remove(self.stack.len() - 1);
                let second = self.stack.remove(self.stack.len() - 1);
                let equal = first == second;
                if op_code == OpEqualVerify {
                    if !equal {
                        return Err(VerifyFailed);
                    }
                } else {
                    self.stack.push(encode_bool(equal));
                }
            },
            OpNumEqualVerify => {
                let first = self.stack.remove(self.stack.len() - 1);
                let second = self.stack.remove(self.stack.len() - 1);
                if first != second {
                    return Err(VerifyFailed);
                }
            },
            OpGreaterThan => {
                let first = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                let second = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                self.stack.push(encode_bool(second > first));
            },
            OpGreaterThanOrEqual => {
                let first = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                let second = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                self.stack.push(encode_bool(second >= first));
            },
            OpLessThanOrEqual => {
                let first = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                let second = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                self.stack.push(encode_bool(second <= first));
            },
            OpLessThan => {
                let first = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                let second = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                self.stack.push(encode_bool(second < first));
            },
            OpMax => {
                let first = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                let second = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                self.stack.push(encode_int(second.max(first)));
            },
            Op0NotEqual => {
                let top = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                self.stack.push(encode_bool(top != 0));
            },
            OpAdd => {
                let mut first = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                let mut second = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                self.stack.push(encode_int(second + first));
            },
            OpSub => {
                let mut first = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                let mut second = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                self.stack.push(encode_int(second - first));
            },
            OpDiv => {
                let mut first = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                let mut second = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                self.stack.push(encode_int(second / first));
            },
            OpMod => {
                let mut first = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                let mut second = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                self.stack.push(encode_int(second % first));
            },
            OpIf => {
                let mut top = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                if top == 0 {
                    self.instruction_pointer = self.jump_table[&self.instruction_pointer];
                }
            },
            OpElse => {
                self.instruction_pointer = self.jump_table[&self.instruction_pointer];
            },
            OpEndIf => {

            },
            OpVerify => {
                let mut top = vec_to_int(&self.stack.remove(self.stack.len() - 1));
                if top == 0 {
                    return Err(VerifyFailed);
                }
            },
            OpCheckSig | OpCheckSigVerify => {
                let pub_key = PublicKey::from_slice(
                    &self.stack.remove(self.stack.len() - 1)
                ).map_err(|_| InvalidPubKey)?;
                let mut sig_ser = self.stack.remove(self.stack.len() - 1);
                sig_ser.remove(sig_ser.len() - 1);
                let sig = Signature::from_der(&sig_ser)
                    .map_err(|_| InvalidSignatureFormat)?;
                let msg = Message::from_slice(&double_sha256(&self.pre_image_serialized))
                    .expect("Invalid message (this is a bug)");
                /*let verification = self.curve.verify(&msg, &sig, &pub_key);
                if op_code == OpCheckSigVerify {
                    verification.map_err(|_| InvalidSignature)?;
                } else {
                    self.stack.push(
                        encode_bool(
                            verification
                                .map_err(|err| {
                                    println!("Note: OP_CHECKSIG failed");
                                    err
                                })
                                .is_ok()
                        )
                    );
                }*/
            },
            OpCheckDataSig | OpCheckDataSigVerify => {
                let pub_key = PublicKey::from_slice(
                    &self.stack.remove(self.stack.len() - 1)
                ).map_err(|_| InvalidPubKey)?;
                let msg = Message::from_slice(
                    &single_sha256(&self.stack.remove(self.stack.len() - 1))
                ).expect("Invalid message (this is a bug)");
                let sig = Signature::from_der(&self.stack.remove(self.stack.len() - 1))
                    .map_err(|_| InvalidSignatureFormat)?;
                /*let verification = self.curve.verify(&msg, &sig, &pub_key);
                if op_code == OpCheckDataSigVerify {
                    verification.map_err(|_| InvalidSignature)?;
                } else {
                    self.stack.push(
                        encode_bool(
                            verification
                                .map_err(|err| {
                                    println!("Note: OP_CHECKDATASIG failed");
                                    err
                                })
                                .is_ok()
                        )
                    );
                }*/
            },
            OpCodeSeparator => {

            },
            OpCheckLockTimeVerify => {
                if self.lock_time > vec_to_int(&self.stack[self.stack.len() - 1]) as u32 {
                    return Err(VerifyFailed);
                }
            },
            _ => return Err(NotImplemented),
        };
        self.instruction_pointer += 1;
        Ok(())
    }
}
