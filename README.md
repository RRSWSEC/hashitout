<p align="center">
  <img src="https://raw.githubusercontent.com/RRSWSEC/hashitout/main/.github/avenatwork.png" width="300">
</p>
# Hash It Out (HIO)

yes, this started as:

> “lemme just decode this one thing real quick”

and turned into this.

this was not vibe coded or whatever. claude was used, chat gpt was used, human brains were used, people and machines were orchestrated and directed to make a vision come to life completely and properly.

-spex-thementor-aven

if you've ever seen:

```
4WZr9mci1CdzVnc01Saml2dtQ3clV3Z
```

and immediately knew:

- this is layered
- this is cursed
- i am not opening cyberchef again

this is for you.

---

## what it is

**Hash It Out** is a single-file, self-installing CLI that:

- decodes obvious stuff instantly
- brute-forces the annoying stuff automatically
- recursively peels layered encodings
- carves files from raw blobs
- ranks results so you can focus
- explains why a candidate looks strong

built for:

- CTF players
- OSINT analysts
- DFIR teams
- anyone tired of manual transforms

---

## quick start

```bash
hashitout "SGVsbG8gd29ybGQ="
hashitout "uryyb"
hashitout -f weird.bin
hashitout --shell
```

---

## recommended modes

### `--fast`
quick sanity pass, no expensive stuff.

### `--standard`
default and balanced.

### `--ctf`
aggressive layered decoding: xor, classical, reverse, chaining.

### `--deep-mode`
slower, deeper, more brute.

### `--forensics`
file carving, embedded data detection, binary artifact analysis.

---

## why this stands out

### 1) scoring that actually helps

results are ranked by:

- readability
- entropy
- known patterns
- flag format matches
- structural sanity

### 2) chain tracking

you get the decoding path, not just output.

```
base64 -> xor(0x23) -> reverse -> rot13
```

### 3) explain mode

```bash
--explain
```

tells you why a result scored high.

### 4) RRSW signal system

- **RRSW-SIGMA** → likely solve
- **RRSW-TRACK** → strong lead
- **RRSW-TRACE** → maybe
- **RRSW-NOISE** → ignore

your brain doesn’t have to triage everything.

### 5) interactive shell

```bash
hashitout --shell
```

commands:

```
top 10
show 1
chain 1
use 1
save 1
```

walk the problem interactively instead of re-running guesses.

---

## examples

```bash
hashitout "68656c6c6f"
hashitout "uryyb" --decode-basic
hashitout -f suspect.png --forensics
hashitout "..." --ctf --explain
```

---

## install

```bash
python hashitout.py --install
```

installs to `/usr/local/bin/hashitout` so you can run:

```bash
hashitout "input"
```

---

## important

only run this on:

- data you own
- challenges you're allowed to solve
- systems you're authorized to analyze

don’t be weird.

---

## final note

this exists because:

- repeating transforms sucks
- losing the chain sucks
- second guessing results sucks

this fixes that.

if it helps, good.
if you break it, even better.

tell me.

future improvements incoming. collaboration welcome.

---

**spex / RRSW**
