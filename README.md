# Hash It Out (HIO)

yeah… this started as  
“lemme just decode this one thing real quick”

and turned into this

if you’ve ever stared at something like:

```
4WZr9mci1CdzVnc01Saml2dtQ3clV3Z
```

and immediately knew:

> this is layered  
> this is cursed  
> and i am not opening cyberchef again  

this is for you

---

## what it is

**Hash It Out** is a single-file, self-installing CLI tool that:

- decodes the obvious stuff instantly  
- brute forces the stuff you don’t want to  
- recursively peels layered encodings  
- carves files out of raw blobs  
- ranks results so you’re not drowning in noise  
- tells you *why* something looks correct  

built for:

- CTF players  
- OSINT  
- DFIR  
- people who are tired of guessing transforms manually  

---

## quick start

```bash
hashitout "SGVsbG8gd29ybGQ="
hashitout "uryyb"
hashitout -f weird.bin
hashitout --shell
```

---

## modes (use these, seriously)

### `--fast`
quick sanity pass, no expensive operations  

### `--standard`
default behavior, balanced  

### `--ctf`
aggressive layered decoding  
xor, classical, reverse, chaining  

### `--deep-mode`
go deeper than you probably need  
slower, but thorough  

### `--forensics`
file carving  
embedded data detection  
binary artifact analysis  

---

## what makes this different

### 1. scoring system

not everything is dumped equally

results are ranked based on:

- readability  
- entropy  
- known patterns  
- flag formats  
- structural sanity  

---

### 2. chain tracking

you don’t just get output, you get the path:

```
base64 -> xor(0x23) -> reverse -> rot13
```

no more “wait what did i just try?”

---

### 3. explain mode

```bash
--explain
```

tells you *why* something ranked high  

useful when you’re not sure if something is legit or coincidence  

---

### 4. RRSW signal system

every result is classified:

- **RRSW-SIGMA** → this is probably it  
- **RRSW-TRACK** → strong lead  
- **RRSW-TRACE** → maybe  
- **RRSW-NOISE** → ignore  

this keeps your brain from melting mid-CTF  

---

### 5. interactive shell

this is where it actually becomes a workflow tool

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

you can **walk the problem** instead of rerunning commands over and over  

---

## examples

```bash
hashitout "68656c6c6f"
hashitout "uryyb" --decode-basic
hashitout -f suspect.png --forensics
hashitout "..." --ctf --explain
```

---

## install (optional)

```bash
python hashitout.py --install
```

installs to:

```
/usr/local/bin/hashitout
```

so you can just run:

```bash
hashitout "input"
```

---

## important

only run this on:

- data you own  
- challenges you’re allowed to solve  
- environments you’re authorized to analyze  

don’t be weird with it  

---

## final note

this tool exists because:

- repeating the same transforms sucks  
- losing track of what you tried sucks  
- second guessing results sucks  

this fixes that

if it helps you, good  
if you break it, even better  

tell me

---

**spex / RRSW**
