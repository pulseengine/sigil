//! Embedded documentation for the wsc/sigil CLI.
//!
//! Embeds project documentation into the binary so agents and humans
//! can access security guidance, threat models, and integration docs
//! directly via `wsc docs <topic>`.

/// Available documentation topics
pub const TOPICS: &[(&str, &str, &str)] = &[
    ("security", "Security policy and vulnerability reporting", include_str!("../../SECURITY.md")),
    ("threat-model", "STPA-Sec threat model overview", include_str!("../../docs/THREAT_MODEL.md")),
    ("integration", "Integration guidance for embedders", include_str!("../../docs/security/INTEGRATION_GUIDANCE.md")),
    ("slsa", "SLSA compliance documentation", include_str!("../../docs/slsa-compliance.md")),
    ("agents", "Agent context for AI-assisted development", include_str!("../../AGENTS.md")),
    ("risk", "Risk assessment summary", include_str!("../../docs/security/RISK_ASSESSMENT.md")),
];

pub fn list_topics() {
    println!("Available documentation topics:\n");
    for (name, description, _) in TOPICS {
        println!("  {:<16} {}", name, description);
    }
    println!("\nUsage: wsc docs <topic>");
    println!("       wsc docs --search <query>");
}

pub fn show_topic(name: &str) -> bool {
    for (topic_name, _, content) in TOPICS {
        if *topic_name == name {
            println!("{}", content);
            return true;
        }
    }
    false
}

pub fn search_topics(query: &str) {
    let query_lower = query.to_lowercase();
    let mut found = false;

    for (name, description, content) in TOPICS {
        let lines: Vec<(usize, &str)> = content
            .lines()
            .enumerate()
            .filter(|(_, line)| line.to_lowercase().contains(&query_lower))
            .collect();

        if !lines.is_empty() {
            if !found {
                println!("Search results for '{}':\n", query);
            }
            found = true;
            println!("── {} ({}) ──", name, description);
            for (line_num, line) in lines.iter().take(5) {
                println!("  {}:{}: {}", name, line_num + 1, line.trim());
            }
            if lines.len() > 5 {
                println!("  ... and {} more matches", lines.len() - 5);
            }
            println!();
        }
    }

    if !found {
        println!("No results found for '{}'", query);
    }
}
