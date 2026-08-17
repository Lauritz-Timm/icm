use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SizeMetrics {
    pub wire_bytes: usize,
    pub result_bytes: usize,
    pub text_bytes: usize,
    pub structured_bytes: usize,
    pub estimated_wire_tokens: usize,
}

pub fn size_metrics(raw_response: &str, parsed: &serde_json::Value) -> SizeMetrics {
    let result_bytes = parsed
        .get("result")
        .and_then(|result| serde_json::to_vec(result).ok())
        .map_or(0, |bytes| bytes.len());
    let text_bytes = parsed
        .pointer("/result/content")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("text").and_then(serde_json::Value::as_str))
                .map(str::len)
                .sum()
        })
        .unwrap_or(0);
    let structured_bytes = parsed
        .pointer("/result/structuredContent")
        .and_then(|value| serde_json::to_vec(value).ok())
        .map_or(0, |bytes| bytes.len());
    let wire_bytes = raw_response.len();
    SizeMetrics {
        wire_bytes,
        result_bytes,
        text_bytes,
        structured_bytes,
        estimated_wire_tokens: wire_bytes.div_ceil(4),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatencySummary {
    pub block_medians_micros: Vec<u128>,
    pub median_micros: u128,
    pub p95_micros: u128,
    pub sample_count: usize,
}

pub fn summarize_blocks(blocks: &[Vec<u128>]) -> LatencySummary {
    let block_medians_micros = blocks.iter().map(|block| percentile(block, 0.5)).collect();
    let all: Vec<_> = blocks.iter().flatten().copied().collect();
    LatencySummary {
        block_medians_micros,
        median_micros: percentile(&all, 0.5),
        p95_micros: percentile(&all, 0.95),
        sample_count: all.len(),
    }
}

fn percentile(samples: &[u128], quantile: f64) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = ((sorted.len() - 1) as f64 * quantile).ceil() as usize;
    sorted[rank]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RetrievalMetrics {
    pub queries: usize,
    pub hit_at_3: f64,
    pub recall_at_3: f64,
    pub ndcg_at_3: f64,
}

pub fn retrieval_metrics(rankings: &[(Vec<String>, Vec<String>)]) -> RetrievalMetrics {
    if rankings.is_empty() {
        return RetrievalMetrics {
            queries: 0,
            hit_at_3: 0.0,
            recall_at_3: 0.0,
            ndcg_at_3: 0.0,
        };
    }
    let mut hit = 0.0;
    let mut recall = 0.0;
    let mut ndcg = 0.0;
    for (actual, relevant) in rankings {
        let top: Vec<_> = actual.iter().take(3).collect();
        let found = top.iter().filter(|id| relevant.contains(id)).count();
        if found > 0 {
            hit += 1.0;
        }
        recall += found as f64 / relevant.len().max(1) as f64;

        let dcg: f64 = top
            .iter()
            .enumerate()
            .filter(|(_, id)| relevant.contains(id))
            .map(|(index, _)| 1.0 / ((index + 2) as f64).log2())
            .sum();
        let ideal_count = relevant.len().min(3);
        let idcg: f64 = (0..ideal_count)
            .map(|index| 1.0 / ((index + 2) as f64).log2())
            .sum();
        if idcg > 0.0 {
            ndcg += dcg / idcg;
        }
    }
    let count = rankings.len() as f64;
    RetrievalMetrics {
        queries: rankings.len(),
        hit_at_3: hit / count,
        recall_at_3: recall / count,
        ndcg_at_3: ndcg / count,
    }
}

pub fn extract_ranked_fixture_ids(text: &str) -> Vec<String> {
    let mut positions = Vec::new();
    for start in 0..text.len() {
        if !text.is_char_boundary(start) {
            continue;
        }
        let suffix = &text[start..];
        let candidate: String = suffix.chars().take(26).collect();
        if candidate.len() == 26
            && candidate.starts_with("01J")
            && candidate.chars().all(|c| c.is_ascii_alphanumeric())
        {
            positions.push((start, candidate));
        }
    }
    positions.sort_by_key(|item| item.0);
    let mut seen = std::collections::BTreeSet::new();
    positions
        .into_iter()
        .filter_map(|(_, id)| seen.insert(id.clone()).then_some(id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_are_exact_for_perfect_ranking() {
        let metrics =
            retrieval_metrics(&[(vec!["a".into(), "b".into()], vec!["a".into(), "b".into()])]);
        assert_eq!(metrics.hit_at_3, 1.0);
        assert_eq!(metrics.recall_at_3, 1.0);
        assert_eq!(metrics.ndcg_at_3, 1.0);
    }

    #[test]
    fn size_counts_newline_frame() {
        let raw = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n";
        let parsed: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(size_metrics(raw, &parsed).wire_bytes, raw.len());
    }
}
