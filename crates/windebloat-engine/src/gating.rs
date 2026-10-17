use serde::{Deserialize, Serialize};
use windebloat_schema::{AppliesTo, Bundle};

/// EEA (European Economic Area) ISO 3166-1 alpha-2 country codes for DMA gating (§3.2).
pub const EEA_REGION_CODES: &[&str] = &[
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IS", "IE", "IT",
    "LV", "LI", "LT", "LU", "MT", "NL", "NO", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsEnvironment {
    pub build_number: u32,
    pub edition_id: String,
    pub region_code: String,
    pub is_eea: bool,
}

impl Default for OsEnvironment {
    fn default() -> Self {
        Self {
            build_number: 22631,
            edition_id: "Professional".to_string(),
            region_code: "US".to_string(),
            is_eea: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatingResult {
    pub applicable: bool,
    pub skip_reason: Option<String>,
    pub effective_on_note: Option<String>,
}

pub fn evaluate_bundle_gating(bundle: &Bundle, env: &OsEnvironment) -> GatingResult {
    evaluate_applies_to(&bundle.applies_to, env)
}

pub fn evaluate_applies_to(applies: &AppliesTo, env: &OsEnvironment) -> GatingResult {
    if env.build_number < applies.os_min_build {
        return GatingResult {
            applicable: false,
            skip_reason: Some(format!(
                "Requires Windows build >= {} (current build is {})",
                applies.os_min_build, env.build_number
            )),
            effective_on_note: None,
        };
    }

    if let Some(max_build) = applies.os_max_build {
        if env.build_number > max_build {
            return GatingResult {
                applicable: false,
                skip_reason: Some(format!(
                    "Only applicable up to Windows build {} (current build is {})",
                    max_build, env.build_number
                )),
                effective_on_note: None,
            };
        }
    }

    if applies
        .sku_exclude
        .iter()
        .any(|sku| sku.eq_ignore_ascii_case(&env.edition_id))
    {
        return GatingResult {
            applicable: false,
            skip_reason: Some(format!(
                "Excluded on Windows SKU '{}' (e.g. LTSC/IoT)",
                env.edition_id
            )),
            effective_on_note: None,
        };
    }

    for reg in &applies.region_exclude {
        if reg.eq_ignore_ascii_case("EEA") && env.is_eea {
            return GatingResult {
                applicable: false,
                skip_reason: Some(
                    "Excluded in EEA region (Windows provides native DMA controls)".to_string(),
                ),
                effective_on_note: None,
            };
        }
        if reg.eq_ignore_ascii_case(&env.region_code) {
            return GatingResult {
                applicable: false,
                skip_reason: Some(format!("Excluded in region '{}'", env.region_code)),
                effective_on_note: None,
            };
        }
    }

    let effective_on_note = if let Some(eff_list) = &applies.effective_on {
        if !eff_list.is_empty()
            && !eff_list
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&env.edition_id))
        {
            Some(format!(
                "Note: Windows fully honors some policies in this bundle only on {} editions (current SKU: {}).",
                eff_list.join("/"),
                env.edition_id
            ))
        } else {
            None
        }
    } else {
        None
    };

    GatingResult {
        applicable: true,
        skip_reason: None,
        effective_on_note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gates_by_build_sku_and_eea_region() {
        let applies = AppliesTo {
            os_min_build: 22621,
            os_max_build: None,
            sku_exclude: vec!["EnterpriseS".to_string()],
            region_exclude: vec!["EEA".to_string()],
            effective_on: Some(vec!["Enterprise".to_string()]),
        };

        // 1. Old build -> gated out
        let win10 = OsEnvironment {
            build_number: 19045,
            edition_id: "Professional".to_string(),
            region_code: "US".to_string(),
            is_eea: false,
        };
        let r1 = evaluate_applies_to(&applies, &win10);
        assert!(!r1.applicable);

        // 2. LTSC SKU -> gated out
        let ltsc = OsEnvironment {
            build_number: 22631,
            edition_id: "EnterpriseS".to_string(),
            region_code: "US".to_string(),
            is_eea: false,
        };
        let r2 = evaluate_applies_to(&applies, &ltsc);
        assert!(!r2.applicable);

        // 3. EEA region -> gated out
        let eea = OsEnvironment {
            build_number: 22631,
            edition_id: "Professional".to_string(),
            region_code: "DE".to_string(),
            is_eea: true,
        };
        let r3 = evaluate_applies_to(&applies, &eea);
        assert!(!r3.applicable);

        // 4. US Pro -> applicable, with effective_on note
        let pro = OsEnvironment {
            build_number: 22631,
            edition_id: "Professional".to_string(),
            region_code: "US".to_string(),
            is_eea: false,
        };
        let r4 = evaluate_applies_to(&applies, &pro);
        assert!(r4.applicable);
        assert!(r4.effective_on_note.is_some());
    }
}
