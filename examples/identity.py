"""the smallest real program against the binding.

generates an identity, prints its node_id, and proves the base58 name round trips
and the key binding holds  -  the discover-by-node_id proof the sandbox apps rest on.

    python examples/identity.py
"""

from __future__ import annotations

import nwep
from nwep import Identity, NodeId


def main() -> None:
    with Identity.generate() as identity:
        node_id = identity.node_id
        print(f"node_id        {node_id}")

        # the node_id is the binding of the public key (sha-256(pubkey + WEB/1)).
        assert node_id.verify(identity.public_key)
        print("key binding    holds (node_id == sha-256(pubkey + WEB/1))")

        # the base58 name round trips exactly.
        text = node_id.base58()
        assert NodeId.from_base58(text) == node_id
        print(f"base58 round   {text} -> NodeId -> equal")

        # a signature over a message verifies against the public key.
        sig = identity.sign(b"hello web/1")
        assert nwep.verify_signature(sig, b"hello web/1", identity.public_key)
        print("signature      verifies against the public key")

    # the private key is wiped (nwep_zeroize) when the with block exits.
    print("private key     wiped on close")


if __name__ == "__main__":
    main()
