// Tiny in-memory cache of decrypted (cert, key) pairs for the duration of
// the current TUI session. Lets users navigate Hubs → connect → run several
// admin commands without re-prompting for the key password every screen.
//
// Lives in memory only; never flushed to disk. Cleared on TUI exit by process
// teardown.

import {makeHubClient, type HubClientHandle} from './hubClient.js';
import {resolveIdentity, type ResolvedIdentity} from './clientIdentity.js';
import {findHub, type Hub} from '../storage/hubStore.js';
import type {AdminInfo, CaInfo} from './adminApi.js';

const identityByHub = new Map<string, ResolvedIdentity>();

/**
 * Per-session cache of slow-changing hub data (`/info` + `/ca`). The TUI
 * navigates in and out of `RemoteHubScreen` constantly; without this cache
 * every `Esc` back to it would trigger a fresh round-trip and a "loading…"
 * flicker. Cleared on disconnect (forgetIdentity).
 */
export type HubSnapshot = {info: AdminInfo; ca: CaInfo; cachedAt: number};
const snapshotByHub = new Map<string, HubSnapshot>();

export function rememberIdentity(hubId: string, id: ResolvedIdentity): void {
	identityByHub.set(hubId, id);
}

export function recallIdentity(hubId: string): ResolvedIdentity | null {
	return identityByHub.get(hubId) ?? null;
}

export function forgetIdentity(hubId: string): void {
	identityByHub.delete(hubId);
	snapshotByHub.delete(hubId);
}

export function rememberSnapshot(hubId: string, snap: Omit<HubSnapshot, 'cachedAt'>): void {
	snapshotByHub.set(hubId, {...snap, cachedAt: Date.now()});
}

export function recallSnapshot(hubId: string): HubSnapshot | null {
	return snapshotByHub.get(hubId) ?? null;
}

/**
 * Convenience: return a connected HubClientHandle for the given hub. Uses
 * a cached identity if one exists; otherwise resolves with the supplied
 * password (or throws EncryptedKeyError so the caller can prompt).
 */
export function clientFor(hubId: string, opts?: {keyPassword?: string | null}): HubClientHandle {
	const hub = findHub(hubId);
	if (!hub) throw new Error(`Hub "${hubId}" not found`);
	let identity = recallIdentity(hubId);
	if (!identity) {
		identity = resolveIdentity(hub.clientAuth, {keyPassword: opts?.keyPassword ?? null});
		rememberIdentity(hubId, identity);
	}
	return makeHubClient(hub, identity);
}

export function getHub(hubId: string): Hub | null {
	return findHub(hubId);
}
