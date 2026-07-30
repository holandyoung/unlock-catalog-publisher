# Catalog V1 conformance fixture provenance

This file describes public, synthetic, test-only fixtures. It contains no private key or production authorization material.

- Protocol version: `unlock-catalog-v1`
- Generator base commit: `08855a6b339b7213248eba7ec4d1abf151da55fb`
- Generation command: `UPDATE_FIXTURES=1 go test ./internal/assemble -run TestSignedFixturesMatchGenerated -count=1`
- Generated at: `2026-07-30T05:20:00Z`
- Fixed verification time: `2026-07-29T09:00:00Z`
- Earliest manifest expiry: `2026-08-12T08:00:00Z`
- Fixture-set digest: `b114d9f2115b5685b489424d6e65c633496204113b97f2e70bf16763c48a6fee`
- Fixture-set digest algorithm: SHA256 of sorted `path<TAB>length<TAB>sha256<LF>` records below; this provenance file is excluded.

The final Catalog task commit cannot be embedded here without a self-reference. The consuming platform fixture record pins both the Catalog task commit and merge commit after this tree is merged.

## Generator sources

| Path | SHA256 |
| :--- | :--- |
| `internal/assemble/assembler.go` | `d9afd5a5f7b4696f34fb9dd356756fc6dd8b2fb639a027a691e1f87d794d87b5` |
| `internal/assemble/conformance_fixtures_test.go` | `a10de84109c7cbee96a4322d9e08ac29bbe8d1e5b22d95a94f484e92cc67ffc4` |
| `internal/assemble/fixtures_test.go` | `c50920f7636c31d9c9b61f89d263e86138c7ced1f979da1e1371dfebf3fcfc58` |
| `internal/assemble/root.go` | `5875e00722966522e9f2762bae30b2eb36601ee972cb3dbf377d769a3dd86ac3` |
| `internal/catalogv1/types.go` | `89ae53d57bc194e6fce82ad27cf29fa1f066a7983554b6d555816d0cd3fa0a5a` |
| `internal/package/package.go` | `51be70b0d215c20033c801458b367bbbc556cd7951413dd0c695606ffa3ddf5a` |

## Fixture files

| Path | Length | SHA256 |
| :--- | ---: | :--- |
| `signed/README.md` | 765 | `c26f6392c45d45780fa002b650a761e0fa278ef3f93d143bd6388e47364c5367` |
| `signed/negative/bad-digest/artifact.bin` | 46 | `952728fdf9405211334296b5e590a41f565abc72d5903a8a842b630a819db9d0` |
| `signed/negative/bad-digest/current-root.json` | 239 | `f7ffbc020e67e255d8332eff805f445c8166dd7107e9efeb6c53b247da5d6472` |
| `signed/negative/bad-digest/manifest.json` | 2665 | `487b40dc7067149f329e4508f126313d3b37c6467df127322d8f14e363de30e3` |
| `signed/negative/bad-digest/metadata.json` | 230 | `5ba1b8eff7b187684387177dc007a4b19b0e57640840f79d8c87cb34a87a9a9d` |
| `signed/negative/bad-length/artifact.bin` | 45 | `47c54574312024d09679799d3e9e28a94f97ef64805cb1cb8be1e41eafc82628` |
| `signed/negative/bad-length/current-root.json` | 239 | `f7ffbc020e67e255d8332eff805f445c8166dd7107e9efeb6c53b247da5d6472` |
| `signed/negative/bad-length/manifest.json` | 2665 | `487b40dc7067149f329e4508f126313d3b37c6467df127322d8f14e363de30e3` |
| `signed/negative/bad-length/metadata.json` | 230 | `703f640fd49e1fc1414b9ada81ca0d6ea0253174ce8a50fe3489ededb34ad8a3` |
| `signed/negative/bad-package/metadata.json` | 185 | `cfd2965d52856a483bfd5f7ca545e169c774f65b1484bbadff4e8173660e9a78` |
| `signed/negative/bad-package/unlock-catalog-package-v1.tar.zst` | 1920 | `94b69cd643e8dbd8b180a7188a1ef08fd14e445ceaf97e548e9069e756faa848` |
| `signed/negative/bad-path/current-root.json` | 239 | `f7ffbc020e67e255d8332eff805f445c8166dd7107e9efeb6c53b247da5d6472` |
| `signed/negative/bad-path/manifest.json` | 2592 | `ac62386cf223daddf936fd80986e75f553e0b8f767a2caa4a93d4780d6ad07b6` |
| `signed/negative/bad-path/metadata.json` | 182 | `01e2881f3be632f3ac4a4c9160ccecf491c22a4353819b52b3fc7a5427df9962` |
| `signed/negative/bad-permission/current-root.json` | 239 | `698c6d7b243a0a77a26385682b0c090d2214fc111a7c7acfb34d86cebbebb653` |
| `signed/negative/bad-permission/manifest.json` | 3204 | `06e447f0c15176ca9c7118b4dc7abf67d927ce162475575104b772e85acca28a` |
| `signed/negative/bad-permission/metadata.json` | 193 | `12b56bc72e15041c4b78c375c6ad61716549625eca5f5796680dc545d773f83d` |
| `signed/negative/bad-revocation/current-root.json` | 239 | `f7ffbc020e67e255d8332eff805f445c8166dd7107e9efeb6c53b247da5d6472` |
| `signed/negative/bad-revocation/manifest.json` | 2822 | `f3866a72838ebb74c06e86b2e4ef2afafce76765339c6371161ba028ab0ef637` |
| `signed/negative/bad-revocation/metadata.json` | 188 | `cf1e739f0b7ae136354f5d6a26ac96753821a26d747d71f50d87d94783e78c76` |
| `signed/negative/bad-root/current-root.json` | 239 | `393966c47d5e053775b4d875d82aceabbd4fac94c9d50c12b95ea723b7f0082d` |
| `signed/negative/bad-root/manifest.json` | 2665 | `487b40dc7067149f329e4508f126313d3b37c6467df127322d8f14e363de30e3` |
| `signed/negative/bad-root/metadata.json` | 182 | `3a16e825317a687014468f8c9a7c89f25d410627c188acf9b496176135b9c123` |
| `signed/negative/bad-signature/current-root.json` | 239 | `f7ffbc020e67e255d8332eff805f445c8166dd7107e9efeb6c53b247da5d6472` |
| `signed/negative/bad-signature/manifest.json` | 2665 | `d4314ae0a33c845926135650b1006d20e5b8b8e01f20e1bf25e9af334a9f8174` |
| `signed/negative/bad-signature/metadata.json` | 187 | `2c255f908096e7747e290c2bc2def6ed1d18ac386a82bb1feb882dc816b72514` |
| `signed/negative/bad-source-id/current-root.json` | 239 | `f7ffbc020e67e255d8332eff805f445c8166dd7107e9efeb6c53b247da5d6472` |
| `signed/negative/bad-source-id/manifest.json` | 2665 | `487b40dc7067149f329e4508f126313d3b37c6467df127322d8f14e363de30e3` |
| `signed/negative/bad-source-id/metadata.json` | 181 | `e2daad82587729e23ff5d58cbcb2b24d92b84964f7a76476b9cdb785185fe671` |
| `signed/negative/data-manifest-payload-mutated.json` | 2673 | `960e1a598aedfaef119cc5269e6b083ee5b43b6248d0b32dd2e9a55a7a4f8e52` |
| `signed/positive/data/current-root.json` | 239 | `f7ffbc020e67e255d8332eff805f445c8166dd7107e9efeb6c53b247da5d6472` |
| `signed/positive/data/metadata.json` | 157 | `e83cf95592b2abf4fd277e4f14be3860bc798bd2e60a700f82715a45a30b2e56` |
| `signed/positive/data/release/archive/00000000000000000001/manifest.json` | 2665 | `487b40dc7067149f329e4508f126313d3b37c6467df127322d8f14e363de30e3` |
| `signed/positive/data/release/archive/00000000000000000001/root.json` | 501 | `20051f3c22b3f717decbe2610d8930300907411ea8aaeb84f361bacfd4f12366` |
| `signed/positive/data/release/manifest.json` | 2665 | `487b40dc7067149f329e4508f126313d3b37c6467df127322d8f14e363de30e3` |
| `signed/positive/data/release/objects/sha256/9c/9ca556aef9a951d1b323640f2b8916e81765115169c5228a4b91fc74e16dd5de` | 53 | `9ca556aef9a951d1b323640f2b8916e81765115169c5228a4b91fc74e16dd5de` |
| `signed/positive/data/release/objects/sha256/b6/b644c2bba09c02862b8d687d5ffe51689e9e4fe162a160b49962b636444c7659` | 46 | `b644c2bba09c02862b8d687d5ffe51689e9e4fe162a160b49962b636444c7659` |
| `signed/positive/data/release/objects/sha256/f7/f75f077ac6a24379b83ddd51a91d525305e20a291164d05e9d008e238b9524c7` | 44 | `f75f077ac6a24379b83ddd51a91d525305e20a291164d05e9d008e238b9524c7` |
| `signed/positive/data/release/root.json` | 501 | `20051f3c22b3f717decbe2610d8930300907411ea8aaeb84f361bacfd4f12366` |
| `signed/positive/data/release/unlock-catalog-package-v1.tar.zst` | 1919 | `072d55d06821c057b10301ddb3f2771f7779117f915a222ef922592610bea321` |
| `signed/positive/exec/current-root.json` | 239 | `698c6d7b243a0a77a26385682b0c090d2214fc111a7c7acfb34d86cebbebb653` |
| `signed/positive/exec/metadata.json` | 175 | `6952a7563637f410e7330178c9df82446d6962ab9ff6a77552944748114a108a` |
| `signed/positive/exec/release/archive/00000000000000000001/manifest.json` | 3204 | `06e447f0c15176ca9c7118b4dc7abf67d927ce162475575104b772e85acca28a` |
| `signed/positive/exec/release/archive/00000000000000000001/root.json` | 501 | `c92ac2ac22f1fcf894e6b1ea11aba0c870695453e918be99cb001e1dff396dc2` |
| `signed/positive/exec/release/manifest.json` | 3204 | `06e447f0c15176ca9c7118b4dc7abf67d927ce162475575104b772e85acca28a` |
| `signed/positive/exec/release/objects/sha256/3b/3b313d46b5a4ca1be5953808c51f902561e22c6e92441563197ff770e6652ae3` | 49 | `3b313d46b5a4ca1be5953808c51f902561e22c6e92441563197ff770e6652ae3` |
| `signed/positive/exec/release/objects/sha256/66/66f99985a2b62798d47b465bd910793c667527da47b043c385db139b4601113a` | 39 | `66f99985a2b62798d47b465bd910793c667527da47b043c385db139b4601113a` |
| `signed/positive/exec/release/objects/sha256/a5/a5b3aece0430b3ae2b7c4046f061759140d255a147e1389a5baaa0e4180d1a68` | 58 | `a5b3aece0430b3ae2b7c4046f061759140d255a147e1389a5baaa0e4180d1a68` |
| `signed/positive/exec/release/objects/sha256/db/db7d8b15bedcdbac8577d01d13f0d89451bf55f3f79a70b1606613d3463fa154` | 51 | `db7d8b15bedcdbac8577d01d13f0d89451bf55f3f79a70b1606613d3463fa154` |
| `signed/positive/exec/release/root.json` | 501 | `c92ac2ac22f1fcf894e6b1ea11aba0c870695453e918be99cb001e1dff396dc2` |
| `signed/positive/exec/release/unlock-catalog-package-v1.tar.zst` | 2138 | `e59ca88357f56a9b4432a47a93562f6ec6a60e9ce267ca176df4d26cd9ee2c54` |
