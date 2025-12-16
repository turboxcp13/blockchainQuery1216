pub mod hash;
pub mod vo;

use crate::{
    acc::{AccPublicKey, AccValue, Set},
    chain::{
        traits::Num,
        {block::Height, id_tree::ObjId, object::Object, traits::ReadInterface},
    },
    digest::{Digest, Digestible},
    utils::{binary_encode, Time},
};
use anyhow::{bail, ensure, Context, Result};
use hash::{ads_hash, bplus_roots_hash};
use hash::{id_tree_root_hash, obj_hash};
use petgraph::{graph::NodeIndex, EdgeDirection::Outgoing, Graph};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::AddAssign,
};
use vo::VO;

use crate::chain::query::query_dag::DagNode;

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyInfo {
    pub vo_size: VOSize,
    pub verify_time: Time,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VOSize {
    pub vo_dag_s: usize,
    pub trie_proof_s: usize,
    pub id_proof_s: usize,
    pub cur_id_s: usize,
    pub merkle_s: usize,
    pub total_s: usize,
}

impl AddAssign for VOSize {
    fn add_assign(&mut self, other: Self) {
        *self = Self {
            vo_dag_s: self.vo_dag_s + other.vo_dag_s,
            trie_proof_s: self.trie_proof_s + other.trie_proof_s,
            id_proof_s: self.id_proof_s + other.id_proof_s,
            cur_id_s: self.cur_id_s + other.cur_id_s,
            merkle_s: self.merkle_s + other.merkle_s,
            total_s: self.total_s + other.total_s,
        };
    }
}

impl VOSize {
    pub fn new(
        vo_dag_s: usize,
        trie_proof_s: usize,
        id_proof_s: usize,
        cur_id_s: usize,
        merkle_s: usize,
        total_s: usize,
    ) -> Self {
        Self {
            vo_dag_s,
            trie_proof_s,
            id_proof_s,
            cur_id_s,
            merkle_s,
            total_s,
        }
    }
}

fn inner_verify<K: Num, T: ReadInterface<K = K>>(
    chain: &T,
    res_content: &HashMap<ObjId, Object<K>>,
    vo_content: &VO<K>,
    graph: &Graph<DagNode<K>, bool>,
    pk: &AccPublicKey,
) -> Result<()> {
    // verify dag, including range query and set operation
    let empty_acc = AccValue::from_set(&Set::new(), pk);
    let vo_dag_idxs = graph.node_indices();
    let vo_dag_content = &vo_content.vo_dag_content.dag_content;
    let vo_output_sets = &vo_content.vo_dag_content.output_sets;
    let mut time_win_map = HashMap::<Height, u16>::new();
    let mut bplus_roots = HashMap::<Height, (u16, BTreeMap<u8, Digest>)>::new();
    let trie_proofs = &vo_content.trie_proofs;
    for idx in vo_dag_idxs {
        if let Some(content) = vo_dag_content.get(&idx) {
            if let Some(node) = graph.node_weight(idx) {
                match node {
                    DagNode::Range(n) => match content {
                        vo::VONode::Range(r_n) => {
                            let blk_height = r_n.blk_height;
                            time_win_map.insert(blk_height, r_n.win_size);
                            let res_digest = r_n.proof.verify(n.range, r_n.acc, pk)?;
                            match bplus_roots.get_mut(&blk_height) {
                                Some((_win_size, btree_map)) => {
                                    btree_map.insert(n.dim, res_digest);
                                }
                                None => {
                                    let mut btree_map = BTreeMap::<u8, Digest>::new();
                                    btree_map.insert(n.dim, res_digest);
                                    bplus_roots.insert(blk_height, (r_n.win_size, btree_map));
                                }
                            }
                        }
                        _ => {
                            bail!("mismatched type");
                        }
                    },
                    DagNode::Keyword(n) => match content {
                        vo::VONode::Keyword(k_n) => {
                            let blk_height = k_n.blk_height;
                            time_win_map.insert(blk_height, k_n.win_size);
                            let proof = trie_proofs
                                .get(&blk_height)
                                .context("Inside dag: cannot find trie proof in VO")?;
                            proof.verify_acc(k_n.acc, &n.keyword, pk)?;
                        }
                        _ => {
                            bail!("mismatched type");
                        }
                    },
                    DagNode::BlkRt(_) => match content {
                        vo::VONode::BlkRt(br_n) => {
                            let blk_height = br_n.blk_height;
                            time_win_map.insert(blk_height, br_n.win_size);
                        }
                        _ => {
                            bail!("mismatched type");
                        }
                    },
                    DagNode::Union(_) => match content {
                        vo::VONode::InterUnion(u_n) => {
                            let mut child_idxs = Vec::<NodeIndex>::new();
                            for idx in graph.neighbors_directed(idx, Outgoing) {
                                child_idxs.push(idx);
                            }
                            let mut child_idx1 = child_idxs
                                .get(1)
                                .context("Cannot find the first child idx of final difference")?;
                            let child_idx2;
                            let edge_idx = graph
                                .find_edge(idx, *child_idx1)
                                .context("Cannot find edge")?;
                            let weight = graph.edge_weight(edge_idx).context("Cannot find edge")?;
                            if !*weight {
                                child_idx2 = child_idxs.get(0).context(
                                    "Cannot find the second child idx of final difference",
                                )?;
                            } else {
                                child_idx1 = child_idxs.get(0).context(
                                    "Cannot find the first child idx of final difference",
                                )?;
                                child_idx2 = child_idxs.get(1).context(
                                    "Cannot find the second child idx of final difference",
                                )?;
                            }
                            let child1 = vo_dag_content.get(child_idx1).context(
                                "Cannot find the first child node of intermediate union",
                            )?;
                            let child2 = vo_dag_content.get(child_idx2).context(
                                "Cannot find the first child node of intermediate union",
                            )?;
                            u_n.proof
                                .verify(child1.get_acc()?, child2.get_acc()?, &u_n.acc, pk)?;
                        }
                        vo::VONode::FinalUnion(u_n) => {
                            let mut child_idxs = Vec::<NodeIndex>::new();
                            for idx in graph.neighbors_directed(idx, Outgoing) {
                                child_idxs.push(idx);
                            }
                            let mut child_idx1 = child_idxs
                                .get(1)
                                .context("Cannot find the first child idx of final difference")?;
                            let child_idx2;
                            let edge_idx = graph
                                .find_edge(idx, *child_idx1)
                                .context("Cannot find edge")?;
                            let weight = graph.edge_weight(edge_idx).context("Cannot find edge")?;
                            if !*weight {
                                child_idx2 = child_idxs.get(0).context(
                                    "Cannot find the second child idx of final difference",
                                )?;
                            } else {
                                child_idx1 = child_idxs.get(0).context(
                                    "Cannot find the first child idx of final difference",
                                )?;
                                child_idx2 = child_idxs.get(1).context(
                                    "Cannot find the second child idx of final difference",
                                )?;
                            }
                            let child1 = vo_dag_content
                                .get(child_idx1)
                                .context("Cannot find the first child node of final union")?;
                            let child2 = vo_dag_content
                                .get(child_idx2)
                                .context("Cannot find the first child node of final union")?;
                            let final_set = vo_output_sets
                                .get(&idx)
                                .context("Cannot find set in VO output sets")?;
                            u_n.proof.verify(
                                child1.get_acc()?,
                                child2.get_acc()?,
                                final_set,
                                pk,
                            )?;
                        }
                        _ => {
                            bail!("mismatched type");
                        }
                    },
                    DagNode::Intersec(_) => match content {
                        vo::VONode::InterIntersec(i_n) => {
                            let mut child_idxs = Vec::<NodeIndex>::new();
                            for idx in graph.neighbors_directed(idx, Outgoing) {
                                child_idxs.push(idx);
                            }
                            let mut child_idx1 = child_idxs
                                .get(1)
                                .context("Cannot find the first child idx of final difference")?;
                            let child_idx2;
                            let edge_idx = graph
                                .find_edge(idx, *child_idx1)
                                .context("Cannot find edge")?;
                            let weight = graph.edge_weight(edge_idx).context("Cannot find edge")?;
                            if !*weight {
                                child_idx2 = child_idxs.get(0).context(
                                    "Cannot find the second child idx of final difference",
                                )?;
                            } else {
                                child_idx1 = child_idxs.get(0).context(
                                    "Cannot find the first child idx of final difference",
                                )?;
                                child_idx2 = child_idxs.get(1).context(
                                    "Cannot find the second child idx of final difference",
                                )?;
                            }
                            let acc1 = if let Some(child1) = vo_dag_content.get(child_idx1) {
                                child1.get_acc()?
                            } else {
                                let child2 = vo_dag_content.get(child_idx2).context(
                                "Cannot find the second child node of intermediate intersection",
                            )?;
                                ensure!(
                                    *child2.get_acc()? == empty_acc,
                                    "The child of intersec should be empty"
                                );
                                continue;
                            };
                            let acc2 = if let Some(child2) = vo_dag_content.get(child_idx2) {
                                child2.get_acc()?
                            } else {
                                let child1 = vo_dag_content.get(child_idx1).context(
                                    "Cannot find the first child node of intermediate intersection",
                                )?;
                                ensure!(
                                    *child1.get_acc()? == empty_acc,
                                    "The child of intersec should be empty"
                                );
                                continue;
                            };
                            i_n.proof
                                .context("Intermediate intersection proof does not exist")?
                                .verify(acc1, acc2, &i_n.acc, pk)?;
                        }
                        vo::VONode::FinalIntersec(i_n) => {
                            let mut child_idxs = Vec::<NodeIndex>::new();
                            for idx in graph.neighbors_directed(idx, Outgoing) {
                                child_idxs.push(idx);
                            }
                            let mut child_idx1 = child_idxs
                                .get(1)
                                .context("Cannot find the first child idx of final difference")?;
                            let child_idx2;
                            let edge_idx = graph
                                .find_edge(idx, *child_idx1)
                                .context("Cannot find edge")?;
                            let weight = graph.edge_weight(edge_idx).context("Cannot find edge")?;
                            if !*weight {
                                child_idx2 = child_idxs.get(0).context(
                                    "Cannot find the second child idx of final difference",
                                )?;
                            } else {
                                child_idx1 = child_idxs.get(0).context(
                                    "Cannot find the first child idx of final difference",
                                )?;
                                child_idx2 = child_idxs.get(1).context(
                                    "Cannot find the second child idx of final difference",
                                )?;
                            }
                            let child1 = vo_dag_content.get(child_idx1).context(
                                "Cannot find the first child node of final intersection",
                            )?;
                            let child2 = vo_dag_content.get(child_idx2).context(
                                "Cannot find the first child node of final intersection",
                            )?;
                            let final_set = vo_output_sets
                                .get(&idx)
                                .context("Cannot find set in VO output sets")?;
                            i_n.proof.verify(
                                child1.get_acc()?,
                                child2.get_acc()?,
                                final_set,
                                pk,
                            )?;
                        }
                        _ => {
                            bail!("mismatched type");
                        }
                    },
                    DagNode::Diff(_) => match content {
                        vo::VONode::InterDiff(d_n) => {
                            let mut child_idxs = Vec::<NodeIndex>::new();
                            for idx in graph.neighbors_directed(idx, Outgoing) {
                                child_idxs.push(idx);
                            }
                            let mut child_idx1 = child_idxs.get(1).context(
                                "Cannot find the first child idx of intermediate difference",
                            )?;
                            let child_idx2;
                            let edge_idx = graph
                                .find_edge(idx, *child_idx1)
                                .context("Cannot find edge")?;
                            let weight = graph.edge_weight(edge_idx).context("Cannot find edge")?;
                            if !*weight {
                                child_idx2 = child_idxs.get(0).context(
                                    "Cannot find the second child idx of intermediate difference",
                                )?;
                            } else {
                                child_idx1 = child_idxs.get(0).context(
                                    "Cannot find the first child idx of intermediate difference",
                                )?;
                                child_idx2 = child_idxs.get(1).context(
                                    "Cannot find the second child idx of intermediate difference",
                                )?;
                            }
                            let acc2 = if let Some(child2) = vo_dag_content.get(child_idx2) {
                                child2.get_acc()?
                            } else {
                                let child1 = vo_dag_content.get(child_idx1).context(
                                    "Cannot find the first child node of intermediate difference",
                                )?;
                                ensure!(
                                    *child1.get_acc()? == empty_acc,
                                    "The child of diff should be empty"
                                );
                                continue;
                            };
                            let child1 = vo_dag_content.get(child_idx1).context(
                                "Cannot find the first child node of intermediate difference",
                            )?;
                            let acc1 = child1.get_acc()?;
                            d_n.proof
                                .context("Intermediate difference proof does not exist")?
                                .verify(acc1, acc2, &d_n.acc, pk)?;
                        }
                        vo::VONode::FinalDiff(d_n) => {
                            let mut child_idxs = Vec::<NodeIndex>::new();
                            for idx in graph.neighbors_directed(idx, Outgoing) {
                                child_idxs.push(idx);
                            }
                            let mut child_idx1 = child_idxs
                                .get(1)
                                .context("Cannot find the first child idx of final difference")?;
                            let child_idx2;
                            let edge_idx = graph
                                .find_edge(idx, *child_idx1)
                                .context("Cannot find edge")?;
                            let weight = graph.edge_weight(edge_idx).context("Cannot find edge")?;
                            if !*weight {
                                child_idx2 = child_idxs.get(0).context(
                                    "Cannot find the second child idx of final difference",
                                )?;
                            } else {
                                child_idx1 = child_idxs.get(0).context(
                                    "Cannot find the first child idx of final difference",
                                )?;
                                child_idx2 = child_idxs.get(1).context(
                                    "Cannot find the second child idx of final difference",
                                )?;
                            }
                            let child1 = vo_dag_content
                                .get(child_idx1)
                                .context("Cannot find the first child node of final difference")?;
                            let child2 = vo_dag_content
                                .get(child_idx2)
                                .context("Cannot find the second child node of final difference")?;
                            let final_set = vo_output_sets
                                .get(&idx)
                                .context("Cannot find set in VO output sets")?;
                            d_n.proof.verify(
                                child1.get_acc()?,
                                child2.get_acc()?,
                                final_set,
                                pk,
                            )?;
                        }
                        _ => {
                            bail!("mismatched type");
                        }
                    },
                }
            }
        }
    }

    // verify id tree
     // verify id tree
    let id_tree_proof = &vo_content.id_tree_proof;
    let param = chain.get_parameter()?;
    let max_id_num = param.max_id_num;
    let id_tree_fanout = param.id_tree_fanout;
    for (id, obj) in res_content {
        let target_hash = obj_hash(obj, id);
        id_tree_proof.verify_value(target_hash, *id, max_id_num, id_tree_fanout)?;
    }
    let id_tree_root_node_hash = id_tree_proof.root_hash();
    let id_tree_root_hash =
        id_tree_root_hash(vo_content.cur_obj_id.to_digest(), id_tree_root_node_hash);

    // 【创新点1】使用 BlockADSComponents 进行结构化验证
    //
    // 验证流程：
    // 1. 计算各索引的哈希（bplus_root_hash, trie_root_hash → multi_ads_hash）
    // 2. 构建 BlockADSComponents
    // 3. 计算 compute_root() 得到统一承诺
    // 4. 与区块头中的 ads_root 比较
    let merkle_proofs = &vo_content.merkle_proofs;
    for (height, time_win) in time_win_map {
        if let Some((_win_size, bplus_hashes)) = bplus_roots.get_mut(&height) {
            let merkle_proof = merkle_proofs
                .get(&height)
                .context("Cannot find merkle proof")?;

            // Step 1: 收集并计算 B+树根哈希
            let extra_bplus_hashes = &merkle_proof.extra_bplus_rt_hashes;
            for (d, h) in extra_bplus_hashes {
                bplus_hashes.insert(*d, *h);
            }
            let bplus_root_hash = bplus_roots_hash(bplus_hashes.iter());

            // Step 2: 获取 Trie 根哈希
            let trie_proof = trie_proofs.get(&height).context("Cannot find trie proof")?;
            let trie_root_hash = trie_proof.root_hash();

            // Step 3: 计算单个时间窗口的 ads_hash
            let single_ads_hash = ads_hash(bplus_root_hash, trie_root_hash);

            // Step 4: 计算完整的 multi_ads_hash（合并所有时间窗口）
            let mut ads_hashes = merkle_proof.ads_hashes.clone();
            ads_hashes.insert(time_win, single_ads_hash);
            let multi_ads_hash = compute_multi_ads_hash(ads_hashes.iter());

            // Step 5: 确定 id_tree_root_hash
            let id_root_hash = match merkle_proof.id_tree_root_hash {
                Some(d) => d,
                None => id_tree_root_hash,
            };

            // 【创新点1】Step 6: 使用 BlockADSComponents 进行结构化验证
            let computed_components = BlockADSComponents::new(
                merkle_proof.id_set_root_hash,
                id_root_hash,
                multi_ads_hash,
            );
            let computed_ads_root = computed_components.compute_root();

            // Step 7: 获取区块头中的 BlockADSRoot 并验证
            let expect_ads_root = chain.read_block_head(height)?.get_ads_root();
            ensure!(
                computed_ads_root == expect_ads_root,
                "BlockADSRoot verification failed for height {:?}!\n\
                 Computed components: id_set={:?}, id_tree={:?}, multi_ads={:?}\n\
                 Computed root: {:?}\n\
                 Expected root: {:?}",
                height,
                merkle_proof.id_set_root_hash,
                id_root_hash,
                multi_ads_hash,
                computed_ads_root,
                expect_ads_root
            );
        }
    }

    let mut vo_outputs = Set::new();
    for set in vo_output_sets.values() {
        vo_outputs = &vo_outputs | set;
    }
    let mut res_outputs: Set = Set::new();
    for key in res_content.keys() {
        res_outputs.insert(key.0);
    }
    ensure!(
        vo_outputs == res_outputs,
        "VO outputs do not match results!"
    );
    info!(
        "Total number of result object returned: {}",
        res_obj_hashes.len()
    );

    let mut total_vo_size = VOSize::new(0, 0, 0, 0, 0, 0);
    for (_, vo) in res_contents {
        total_vo_size += cal_vo_size(vo)?;
    }

    Ok(VerifyInfo {
        vo_size: total_vo_size,
        verify_time: time,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_graph() {
        use petgraph::{EdgeDirection::Outgoing, Graph};
        let mut dag = Graph::<u32, ()>::new();
        let idx1 = dag.add_node(1);
        let idx2 = dag.add_node(2);
        let idx3 = dag.add_node(3);
        let idx4 = dag.add_node(4);
        let idx5 = dag.add_node(5);
        let idx6 = dag.add_node(6);
        dag.extend_with_edges(&[
            (idx1, idx2),
            (idx1, idx3),
            (idx2, idx4),
            (idx2, idx5),
            (idx3, idx5),
            (idx3, idx6),
        ]);

        println!("for idx1's children: ");
        for child_idx in dag.neighbors_directed(idx1, Outgoing) {
            println!("{:?}", child_idx);
        }
        println!("for idx2's children: ");
        for child_idx in dag.neighbors_directed(idx2, Outgoing) {
            println!("{:?}", child_idx);
        }
        println!("for idx3's children: ");
        for child_idx in dag.neighbors_directed(idx3, Outgoing) {
            println!("{:?}", child_idx);
        }
        assert_eq!(1, 1);
    }
}