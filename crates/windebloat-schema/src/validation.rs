use crate::denylist::{check_bundle_against_denylist, DenylistViolation};
use crate::{Action, Bundle, BundlePolicy, ManifestFile, UndoRoute, UndoTier};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("Unsupported manifest_version {0}; expected 3")]
    UnsupportedVersion(u32),
    #[error("Manifest contains no bundles")]
    EmptyBundles,
    #[error("Duplicate bundle id '{0}'")]
    DuplicateBundleId(String),
    #[error("Bundle '{0}' has an invalid id (must be lowercase alphanumeric + underscores)")]
    InvalidBundleId(String),
    #[error("Bundle '{0}' contains no actions")]
    EmptyActions(String),
    #[error("Bundle '{bundle_id}' action #{action_index}: package_family_name '{pfn}' contains wildcards or is invalid")]
    WildcardOrInvalidPfn {
        bundle_id: String,
        action_index: usize,
        pfn: String,
    },
    #[error("Bundle '{bundle_id}' uses bundle_policy 'abort_on_fail' but action #{action_index} has undo tier '{tier:?}' (must be automatic)")]
    AbortOnFailWithNonAutoUndo {
        bundle_id: String,
        action_index: usize,
        tier: UndoTier,
    },
    #[error("Bundle '{bundle_id}' action #{action_index}: manual_assisted Store undo requires a valid 12-char alphanumeric Store product_id, got '{product_id:?}'")]
    InvalidStoreProductId {
        bundle_id: String,
        action_index: usize,
        product_id: Option<String>,
    },
    #[error(transparent)]
    Denylist(#[from] DenylistViolation),
}

pub fn validate_manifest(manifest: &ManifestFile) -> Result<(), ValidationError> {
    if manifest.manifest_version != 3 {
        return Err(ValidationError::UnsupportedVersion(
            manifest.manifest_version,
        ));
    }
    if manifest.bundles.is_empty() {
        return Err(ValidationError::EmptyBundles);
    }

    let mut seen_ids = HashSet::new();
    for bundle in &manifest.bundles {
        if !seen_ids.insert(bundle.id.clone()) {
            return Err(ValidationError::DuplicateBundleId(bundle.id.clone()));
        }
        validate_bundle(bundle)?;
    }
    Ok(())
}

pub fn validate_bundle(bundle: &Bundle) -> Result<(), ValidationError> {
    if bundle.manifest_version != 3 {
        return Err(ValidationError::UnsupportedVersion(bundle.manifest_version));
    }
    if bundle.id.is_empty()
        || !bundle
            .id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(ValidationError::InvalidBundleId(bundle.id.clone()));
    }
    if bundle.actions.is_empty() {
        return Err(ValidationError::EmptyActions(bundle.id.clone()));
    }

    // Check OS preservation denylist (§2.3)
    check_bundle_against_denylist(bundle)?;

    for (idx, action) in bundle.actions.iter().enumerate() {
        let undo = action.undo();

        // §3.2: A bundle may not combine abort_on_fail with manual_assisted (or none) undo; CI rejects it.
        if bundle.bundle_policy == BundlePolicy::AbortOnFail && undo.tier != UndoTier::Automatic {
            return Err(ValidationError::AbortOnFailWithNonAutoUndo {
                bundle_id: bundle.id.clone(),
                action_index: idx,
                tier: undo.tier,
            });
        }

        // Validate Store product ID resolution format when route is Store (12 chars for UWP 9N..., 13-14 chars for Win32 XP...)
        if undo.tier == UndoTier::ManualAssisted && undo.route == Some(UndoRoute::Store) {
            let valid_id = undo
                .product_id
                .as_ref()
                .map(|id| (12..=14).contains(&id.len()) && id.chars().all(|c| c.is_ascii_alphanumeric()))
                .unwrap_or(false);
            if !valid_id {
                return Err(ValidationError::InvalidStoreProductId {
                    bundle_id: bundle.id.clone(),
                    action_index: idx,
                    product_id: undo.product_id.clone(),
                });
            }
        }

        // §3.3: Exact package_family_name matches only. Wildcards are rejected.
        match action {
            Action::AppxRemove {
                package_family_name,
                ..
            }
            | Action::AppxProvisionedRemove {
                package_family_name,
                ..
            } => {
                if package_family_name.contains('*')
                    || package_family_name.contains('?')
                    || !package_family_name.contains('_')
                {
                    return Err(ValidationError::WildcardOrInvalidPfn {
                        bundle_id: bundle.id.clone(),
                        action_index: idx,
                        pfn: package_family_name.clone(),
                    });
                }
            }
            _ => {}
        }
    }

    Ok(())
}
