# Layers of Truth

**Author:** Incendio

---

### Challenge Description
>
> Vice City is a city built on money, power, and secrets. Beneath its neon lights, every image can hold another story.
>
> A photograph of the city has surfaced. It looks ordinary, but there is more than one layer to the truth. Search the image for hidden data.
>

The challenge provides one file:

- **layers_of_truth.png** — a Vice City skyline image with a hidden payload in its pixel data

![Layers of Truth challenge image](../../challenges/easy_challenges/Layers%20of%20truth/layers_of_truth.png)

---

### Step 1: Find the Hidden Data with zsteg

Scan the PNG's bit planes:

```bash
zsteg layers_of_truth.png
```

The RGB least-significant-bit plane contains the hidden text. Extract that plane's 71-byte payload:

Output:

```text
SECRET:0554001031581A1C55256E0516374A3D1742335F070C2C6E2C2652225E0C0A3E
```

The value after `SECRET:` is hexadecimal ciphertext. It is not the flag yet; it must be XORed with a key.

---

### Step 2: Find the Key in the Metadata

Inspect the image metadata with ExifTool:

```bash
exiftool layers_of_truth.png
```

The output includes a field named `Key`:

```text
Key                             :  Unknown (V1ceC1ty!)
```

The Key field is originally a musical key field, the attacker used it to hide the XOR key, Since Exiftool can't recongnize the word V1ceC1ty! it as a musical key it will wrap the text in "Unknown()", so in reality the key is only V1ceC1ty!.

Or in the first place just use this command to show the raw value:

```bash
exiftool -n layers_of_truth.png
```

---

### Step 3: Decrypt the Payload

Convert the hexadecimal ciphertext to bytes and XOR each byte with the repeating key:

This can easily be done by cyber chef recipe: From hex + XOR with UTF-8 key, or any other tool.

Output:

```text
Securinets_fst{Incendio_X_stooo}
```
