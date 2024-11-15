use dep::std;
use std::hash::poseidon;

global TREE_LEVEL: u32 = 17; 
global TX_NUMBER: u32 = 1;

fn hash_values(leaves: [Field; 2]) -> Field {
    let hash = poseidon::bn254::hash_2(leaves);
    hash
}

fn operation_hasher(account_identifier: Field, secret: Field, op: Field) -> Field {
    let account_information_hash = poseidon::bn254::hash_1([account_identifier + secret]);
    let op_hash = hash_values([account_information_hash, op]);
    op_hash
}


fn merkle_tree_root<let N: u32>(leaf: Field, path_indices: Field, siblings: ([Field; N])) -> Field {
    let index_bits: [u1; N] = path_indices.to_be_bits();
    let mut current = leaf;
    for i in 0..N {
        let path_bit = index_bits[i] as bool;
        let (hash_left, hash_right) = if path_bit {
            (siblings[i], current)
        } else {
            (current, siblings[i])
        };
        current = hash_values([hash_left, hash_right]);
    }
    current
}

fn validate_user_operations<let T: u32, let L: u32>(account_identifier: Field, session_key_identifier: Field, allowed_smart_contract_tree_root: Field, allowed_to_tree_root: Field,
   op: Field,  dest: [Field; T], value: [Field; T], function_selector: [Field; T], erc20_transfer_to: [Field; T],
   eth_to_siblings: [[Field; L]; T],  eth_to_path_indices: [Field; T], 
   allowed_smart_contract_call_siblings: [[Field; L]; T], allowed_smart_contract_call_path_indices: [Field; T],
   erc20_to_address_siblings: [[Field; L]; T], erc20_to_address_path_indices: [Field; T],) -> (Field, Field){

    let sessionTree01 = hash_values([account_identifier, session_key_identifier]);
    let sessionTree23 = hash_values([allowed_smart_contract_tree_root, allowed_to_tree_root]);
    let sessionRoot = hash_values([sessionTree01, sessionTree23]);
    for i in 0..T {
        if (dest[i] != 0) {
            if (value[i] != 0){
                let eth_to_root = merkle_tree_root(dest[i], eth_to_path_indices[i], eth_to_siblings[i]);
                 assert(eth_to_root == allowed_to_tree_root);
            }
            if(function_selector[i] != 0) {
                let smart_contract_root = merkle_tree_root(dest[i], allowed_smart_contract_call_path_indices[i], allowed_smart_contract_call_siblings[i]);
                assert(smart_contract_root == allowed_smart_contract_tree_root);
                if(function_selector[i] == 2835717307) {
                    let erc20_to_root = merkle_tree_root(erc20_transfer_to[i], erc20_to_address_path_indices[i], erc20_to_address_siblings[i]);
                    assert(erc20_to_root == allowed_to_tree_root);
                }
            }
        }
    }
    let opHash= operation_hasher(account_identifier+session_key_identifier, sessionRoot, op);
    let out: (Field, Field) = (sessionRoot, opHash);
    out
}

fn main(account_identifier: pub Field, session_key_identifier: pub Field, allowed_smart_contract_tree_root: Field, allowed_to_tree_root: Field, 
op: pub Field,  dest: pub [Field; TX_NUMBER], value: pub [Field; TX_NUMBER], function_selector: pub [Field; TX_NUMBER], erc20_transfer_to: pub [Field; TX_NUMBER],
eth_to_siblings: [[Field; TREE_LEVEL]; TX_NUMBER],  eth_to_path_indices: [Field; TX_NUMBER],
allowed_smart_contract_call_siblings: [[Field; TREE_LEVEL]; TX_NUMBER], allowed_smart_contract_call_path_indices: [Field; TX_NUMBER],
erc20_to_address_siblings: [[Field; TREE_LEVEL]; TX_NUMBER], erc20_to_address_path_indices: [Field; TX_NUMBER],
) -> pub (Field, Field) {
    let out= validate_user_operations(account_identifier, session_key_identifier, allowed_smart_contract_tree_root, allowed_to_tree_root, op, dest, value, function_selector, erc20_transfer_to, eth_to_siblings, eth_to_path_indices, allowed_smart_contract_call_siblings, allowed_smart_contract_call_path_indices, erc20_to_address_siblings, erc20_to_address_path_indices);
    out
}

#[test]
fn test_main() {
    //main(1, 2);

    let account_identifier = 755214674609239513844094901006445707489962006989;
    let session_key_identifier = 630582199873387284701482249245097140889445580438;
    let allowed_smart_contract_tree_root = 1772011440465659367974540880227024983878887423287925274503066546974529382177;
    let allowed_to_tree_root = 13506592134768766857243003844004427544778631289511354676795669135056344408623;
    let op = 4148667739399203055288431972743540829846567430608043454045393934424895256720;

    let dest = [213148054024196271689910033015808239619859249780];
    let value = [10000000000000000];
    let function_selector = [0];
    let erc20_transfer_to = [0];

    let eth_to_siblings = [[
        1432269006499943160490243957128603964592885679140,
      14569315071440144662108998501596314685881909704314835167358592995111912548221,
      7423237065226347324353380772367382631490014989348495481811164164159255474657,
      11286972368698509976183087595462810875513684078608517520839298933882497716792,
      3607627140608796879659380071776844901612302623152076817094415224584923813162,
      19712377064642672829441595136074946683621277828620209496774504837737984048981,
      20775607673010627194014556968476266066927294572720319469184847051418138353016,
      3396914609616007258851405644437304192397291162432396347162513310381425243293,
      21551820661461729022865262380882070649935529853313286572328683688269863701601,
      6573136701248752079028194407151022595060682063033565181951145966236778420039,
      12413880268183407374852357075976609371175688755676981206018884971008854919922,
      14271763308400718165336499097156975241954733520325982997864342600795471836726,
      20066985985293572387227381049700832219069292839614107140851619262827735677018,
      9394776414966240069580838672673694685292165040808226440647796406499139370960,
      11331146992410411304059858900317123658895005918277453009197229807340014528524,
      15819538789928229930262697811477882737253464456578333862691129291651619515538,
      19217088683336594659449020493828377907203207941212636669271704950158751593251

    ]];
    let eth_to_path_indices = [0];
    let allowed_smart_contract_call_siblings = [[0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0,0, 0, 0]];
    let allowed_smart_contract_call_path_indices = [0];
    let erc20_to_address_siblings = [[0, 0, 0, 0, 0, 0, 0,0, 0, 0, 0, 0, 0, 0,0, 0, 0]];
    let erc20_to_address_path_indices = [0];
    let out = main(account_identifier, session_key_identifier, allowed_smart_contract_tree_root, allowed_to_tree_root, 
    op, dest, value, function_selector, erc20_transfer_to, eth_to_siblings, eth_to_path_indices,
    allowed_smart_contract_call_siblings, allowed_smart_contract_call_path_indices, erc20_to_address_siblings, erc20_to_address_path_indices);
    println(out);
}

#[test]
fn test_compute_merkle_root() {
    let leaf = 1116957140489402092651358983432869346627105023585;
    let path_indices = 32768;
    let siblings = [1031163873806781096383561723591525354944716437182,
    3263702263784020662449256635623543278899310644944515835032625364501297280300,
    1312359680379326562440355792178271262864665782735010629806169706496504775134,
    11286972368698509976183087595462810875513684078608517520839298933882497716792,
    3607627140608796879659380071776844901612302623152076817094415224584923813162,
    19712377064642672829441595136074946683621277828620209496774504837737984048981,
    20775607673010627194014556968476266066927294572720319469184847051418138353016,
    3396914609616007258851405644437304192397291162432396347162513310381425243293,
    21551820661461729022865262380882070649935529853313286572328683688269863701601,
    6573136701248752079028194407151022595060682063033565181951145966236778420039,
    12413880268183407374852357075976609371175688755676981206018884971008854919922,
    14271763308400718165336499097156975241954733520325982997864342600795471836726,
    20066985985293572387227381049700832219069292839614107140851619262827735677018,
    9394776414966240069580838672673694685292165040808226440647796406499139370960,
    11331146992410411304059858900317123658895005918277453009197229807340014528524,
    15819538789928229930262697811477882737253464456578333862691129291651619515538];
    let root = merkle_tree_root(leaf, path_indices, siblings);
    println(root);
    assert(root == 4369810217809802993016471241197189216102149656143390676747961658771171308987);
}
