"""Deterministic unsigned browser-extension release preparation helpers.

This package prepares and verifies *unsigned* submission ZIPs from the real
`browser-extension/build.js` output. It has no signing, publishing, network,
credential, home-directory, or environment-discovery path. A receipt produced
here is public metadata, never a signature or an accepted store release.
"""
