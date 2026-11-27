use super::*;
use crate::reconcile::{different_secrets, login_scopes};

pub(super) fn matches(local: &VaultItem, candidate: &VaultItem) -> bool {
    let scopes = login_scopes(local);
    different_secrets(local, candidate) && login_scopes(candidate).iter().any(|scope| scopes.contains(scope))
}

pub(super) fn validate<'a>(
    row: &'a Conflict, visible: &BTreeMap<&str, &VaultItem>, affected: &mut BTreeSet<&'a str>,
) -> Result<(), VaultError> {
    let local = row.ours.as_ref().ok_or_else(batch::invalid)?;
    if local.id != row.id || row.base.is_some() || row.theirs.is_none() || visible.contains_key(row.id.as_str()) {
        return Err(batch::invalid());
    }
    for (item, _) in row.matches() {
        if !affected.insert(&item.id) || !merge::same(visible.get(item.id.as_str()).copied(), Some(item)) ||
            !matches(local, item) {
            return Err(batch::invalid());
        }
    }
    Ok(())
}

fn groups<'a>(state: &'a PackState<'_>) -> BTreeMap<Vec<&'a str>, &'a Conflict> {
    state.staged.rows.iter().filter(|row| row.fields == ["$duplicate"]).map(|row| {
        let mut ids: Vec<_> = row.affected_ids().collect();
        ids.sort_unstable();
        (ids, row)
    }).collect()
}

fn queue_edit(drafts: &mut Vec<Draft>, shown: &VaultItem, base: Option<&VaultItem>, edit: Option<&VaultItem>, source: &str) {
    if merge::same(base, edit) || merge::same(Some(shown), edit) { return; }
    let draft = Draft { base: base.cloned(), ours: edit.cloned(), source: Some(source.into()) };
    if !drafts.iter().any(|other| same_draft(&draft, other)) { drafts.push(draft); }
}

#[derive(Default)]
pub(super) struct Reviews {
    pub(super) held: BTreeSet<String>,
    pub(super) waiting: BTreeSet<String>,
    pub(super) resolved_locally: BTreeMap<String, bool>,
}

pub(super) fn carry(
    base: &PackState<'_>, ours: &PackState<'_>, theirs: &PackState<'_>,
    output: &mut VaultSnapshot, staged: &mut Staged, source: &dyn Fn(&str, bool) -> String,
) -> Reviews {
    let (ancestor, local, remote) = (groups(base), groups(ours), groups(theirs));
    let mut reviews = Reviews::default();
    for (side, other, alternate, alternate_is_local) in [(&remote, &local, ours, true), (&local, &remote, theirs, false)] {
        for (ids, &row) in side {
            if ancestor.contains_key(ids) && !other.contains_key(ids) {
                reviews.resolved_locally.extend(ids.iter().map(|&id| (id.to_owned(), alternate_is_local)));
                continue;
            }
            if ids.iter().any(|&id| reviews.held.contains(id)) {
                reviews.waiting.extend(ids.iter().filter(|&&id| !reviews.held.contains(id)).map(|&id| id.to_owned()));
                continue;
            }
            for shown in row.ours.iter().chain(row.matches().map(|(item, _)| item)) {
                let id = shown.id.as_str();
                reviews.held.insert(id.to_owned());
                if id != row.id { output.items.push(shown.clone()); }
                let baseline = base.row(id);
                let mut drafts = merged_drafts(baseline.drafts, ours.row(id).drafts, theirs.row(id).drafts);
                let entry = alternate.row(id);
                if let Some(pending) = entry.conflict {
                    queue_edit(&mut drafts, shown, pending.base.as_ref(), pending.ours.as_ref(), pending.labels().0);
                    queue_edit(&mut drafts, shown, pending.base.as_ref(), pending.theirs.as_ref(), pending.labels().1);
                } else {
                    let previous = baseline.item.or_else(|| entry.deleted.then_some(shown));
                    queue_edit(&mut drafts, shown, previous, entry.item, &source(id, alternate_is_local));
                }
                if !drafts.is_empty() { staged.drafts.insert(id.to_owned(), drafts); }
            }
            staged.rows.push(row.clone());
        }
    }
    reviews
}

pub(super) fn find_new(
    base: &PackState<'_>, ours: &PackState<'_>, theirs: &PackState<'_>,
    output: &mut VaultSnapshot, staged: &mut Staged, mut waiting: BTreeSet<String>, source: &dyn Fn(&str, bool) -> String,
) -> Result<(), VaultError> {
    waiting.extend(ours.waiting.union(&theirs.waiting).copied()
        .filter(|id| !base.waiting.contains(id) || (ours.waiting.contains(id) && theirs.waiting.contains(id)))
        .map(str::to_owned));
    let exclusive = |side: &PackState<'_>, other: &PackState<'_>| side.items.keys().chain(side.conflicts.keys()).copied()
        .filter(|id| base.row(id).item.is_none() && other.row(id).item.is_none()).map(str::to_owned).collect::<BTreeSet<_>>();
    let local = exclusive(ours, theirs);
    let mut fresh = local.clone();
    fresh.extend(waiting.iter().cloned());
    let candidates = exclusive(theirs, ours);
    let known = reviewed_sources([ours.staged, theirs.staged]);
    let label = |id: &str, local| known.get(id).cloned().unwrap_or_else(|| source(id, local));
    review(output, staged, &fresh, &candidates, &waiting, &label)?;
    if !ours.staged.rows.is_empty() {
        // A remote addition can also overlap a held local candidate.
        review(output, staged, &candidates, &local, &BTreeSet::new(), &|id, local| label(id, !local))?;
    }
    Ok(())
}

pub(super) fn reviewed_sources<'a>(states: impl IntoIterator<Item = &'a Staged>) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    for staged in states {
        for row in staged.rows.iter().filter(|row| row.fields == ["$duplicate"]) {
            names.insert(row.id.clone(), row.labels().0.into());
            names.extend(row.matches().map(|(item, label)| (item.id.clone(), label.into())));
        }
        for (id, queue) in &staged.drafts {
            if let Some(label) = queue.first().filter(|draft| draft.base.is_none()).and_then(|draft| draft.source.as_ref()) {
                names.entry(id.clone()).or_insert_with(|| label.clone());
            }
        }
    }
    names
}

// Queued logins that shared an already-held candidate get a turn as soon as its
// review finishes. Fresh branch additions are compared only across the two branches.
pub(super) fn review(
    output: &mut VaultSnapshot, staged: &mut Staged, fresh: &BTreeSet<String>,
    candidates: &BTreeSet<String>, waiting: &BTreeSet<String>, source: &dyn Fn(&str, bool) -> String,
) -> Result<(), VaultError> {
    if fresh.is_empty() { return Ok(()); }
    let mut held: BTreeSet<_> = staged.rows.iter().flat_map(Conflict::affected_ids).map(str::to_owned).collect();
    let visible = batch::indexed(output)?;
    let mut incoming = BTreeMap::<_, BTreeSet<&str>>::new();
    for (&id, &item) in &visible {
        if fresh.contains(id) || (waiting.is_empty() && !candidates.contains(id)) { continue; }
        for scope in login_scopes(item) { incoming.entry(scope).or_default().insert(id); }
    }
    // A target password that still awaits a decision can match an incoming
    // account even when the displayed target version has the same password.
    let blocked: BTreeSet<_> = {
        let mut alternatives = BTreeMap::<_, Vec<&VaultItem>>::new();
        for item in staged.rows.iter().filter_map(|row| row.ours.as_ref()) {
            if waiting.is_empty() && !candidates.contains(&item.id) { continue; }
            for scope in login_scopes(item) { alternatives.entry(scope).or_default().push(item); }
        }
        fresh.iter().filter(|id| visible.get(id.as_str()).is_some_and(|&local| {
            login_scopes(local).iter().filter_map(|scope| alternatives.get(scope)).flatten().any(|other|
                local.id != other.id && (waiting.contains(*id) || candidates.contains(&other.id)) && different_secrets(local, other))
        })).cloned().collect()
    };
    let mut hidden = BTreeSet::new();
    for id in fresh.iter().map(String::as_str) {
        if held.contains(id) { continue; }
        let Some(&local) = visible.get(id) else { continue; };
        let found: BTreeSet<_> = login_scopes(local).iter().filter_map(|scope| incoming.get(scope)).flatten()
            .filter(|other| waiting.contains(id) || candidates.contains(**other))
            .copied().filter(|other| different_secrets(local, visible[other])).collect();
        if found.is_empty() && !blocked.contains(id) { continue; }
        if blocked.contains(id) || found.iter().any(|&other| held.contains(other)) {
            staged.drafts.entry(id.into()).or_default().insert(0, Draft { base: None, ours: Some(local.clone()), source: Some(source(id, true)) });
            hidden.insert(id.to_owned());
            continue;
        }
        held.extend(found.iter().map(|&id| id.to_owned()));
        held.insert(id.to_owned());
        let mut versions = found.into_iter().map(|id| (visible[id].clone(), source(id, false)));
        let (first, label) = versions.next().ok_or_else(batch::invalid)?;
        staged.rows.push(Conflict { id: id.into(), fields: vec!["$duplicate".into()], base: None, ours: Some(local.clone()),
            theirs: Some(first), receipt: None, sources: Some((source(id, true), label)), additional: versions.collect() });
        hidden.insert(id.to_owned());
    }
    output.items.retain(|item| !hidden.contains(&item.id));
    Ok(())
}
