import hashlib
import json
import unittest


def stable_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def link_identity(state, *, tenant, principal, provider_subject, generation, action):
    key = (tenant, provider_subject)
    current = state.get(key)
    if action == "link":
        if current is not None:
            if current == (principal, generation):
                return state
            raise ValueError("provider subject already bound")
        state[key] = (principal, generation)
        return state
    if action == "unlink":
        if current != (principal, generation):
            raise ValueError("stale or cross-principal unlink")
        del state[key]
        state[(tenant, provider_subject, "tombstone")] = generation + 1
        return state
    raise ValueError("unknown action")


def rotate_session(*, current_aal, current_generation, refresh_aal, refresh_generation, local_mfa=False):
    if refresh_generation != current_generation:
        raise ValueError("stale assurance generation")
    if refresh_aal < current_aal:
        raise ValueError("assurance downgrade")
    if refresh_aal > current_aal and not local_mfa:
        raise ValueError("unadmitted assurance upgrade")
    return (refresh_aal, current_generation + 1)


def callback_state(*, tenant, session, provider, redirect_id, nonce, generation):
    return stable_digest({
        "tenant": tenant,
        "session": session,
        "provider": provider,
        "redirect_id": redirect_id,
        "nonce": nonce,
        "generation": generation,
    })


class FederatedSessionHardeningTests(unittest.TestCase):
    def test_principal_link_unlink_replay_and_tenant_isolation(self):
        state = {}
        link_identity(state, tenant="t1", principal="p1", provider_subject="github:42", generation=1, action="link")
        before = dict(state)
        link_identity(state, tenant="t1", principal="p1", provider_subject="github:42", generation=1, action="link")
        self.assertEqual(state, before)
        with self.assertRaises(ValueError):
            link_identity(state, tenant="t1", principal="p2", provider_subject="github:42", generation=1, action="link")
        link_identity(state, tenant="t1", principal="p1", provider_subject="github:42", generation=1, action="unlink")
        with self.assertRaises(ValueError):
            link_identity(state, tenant="t1", principal="p1", provider_subject="github:42", generation=1, action="unlink")
        link_identity(state, tenant="t2", principal="p9", provider_subject="github:42", generation=1, action="link")
        self.assertEqual(state[("t2", "github:42")], ("p9", 1))

    def test_session_rotation_preserves_assurance_generation(self):
        self.assertEqual(rotate_session(current_aal=2, current_generation=7, refresh_aal=2, refresh_generation=7), (2, 8))
        with self.assertRaises(ValueError):
            rotate_session(current_aal=2, current_generation=7, refresh_aal=1, refresh_generation=7)
        with self.assertRaises(ValueError):
            rotate_session(current_aal=2, current_generation=7, refresh_aal=2, refresh_generation=6)
        with self.assertRaises(ValueError):
            rotate_session(current_aal=1, current_generation=7, refresh_aal=2, refresh_generation=7)
        self.assertEqual(rotate_session(current_aal=1, current_generation=7, refresh_aal=2, refresh_generation=7, local_mfa=True), (2, 8))

    def test_callback_state_binds_full_authentication_context(self):
        base = dict(tenant="t1", session="s1", provider="github", redirect_id="app-a", nonce="n1", generation=3)
        admitted = callback_state(**base)
        self.assertEqual(admitted, callback_state(**base))
        for key, replacement in {
            "tenant": "t2",
            "session": "s2",
            "provider": "google",
            "redirect_id": "app-b",
            "nonce": "n2",
            "generation": 4,
        }.items():
            changed = dict(base)
            changed[key] = replacement
            self.assertNotEqual(admitted, callback_state(**changed), key)


if __name__ == "__main__":
    unittest.main()
