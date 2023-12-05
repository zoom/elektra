INSERT INTO vrf_cache(
        tree_id,period,key,hidden_key,vrf_proof
) SELECT '\x@@@',period,key,hidden_key,vrf_proof
FROM vrf_cache WHERE tree_id='\x###';
INSERT INTO pairs(
    tree_id,seqno,period,hidden_key,key,added_at_seqno,encoded_value,entropy
) SELECT '\x@@@',seqno,period,hidden_key,key,added_at_seqno,encoded_value,entropy
FROM pairs WHERE tree_id='\x###';
INSERT INTO roots(
    tree_id,seqno,root_metadata
) SELECT '\x@@@',seqno,root_metadata
FROM roots WHERE tree_id='\x###';
INSERT INTO vrf_rotation_proofs(
    tree_id,period,proof
) SELECT '\x@@@',period,proof
FROM vrf_rotation_proofs WHERE tree_id='\x###';
INSERT INTO vrf_private_keys(
    tree_id,period,private_key
) SELECT '\x@@@',period,private_key
FROM vrf_private_keys WHERE tree_id='\x###';
INSERT INTO history_tree_nodes(
    tree_id,idx,value
) SELECT '\x@@@',idx,value
FROM history_tree_nodes WHERE tree_id='\x###';
INSERT INTO sigchain_player_cache(
    tree_id,user_id,value
) SELECT '\x@@@',user_id,value
FROM sigchain_player_cache WHERE tree_id='\x###';
