# Deep Cover

**Author:** Incendio

---

### Challenge Description
>
> Vice City has a way of burying its secrets beneath layers of evidence. Two images have surfaced: one seems to carry a hidden clue, while the other may conceal something deeper.
>
> Follow the trail from one image to the next, uncover what is hidden inside, and recover the secret.
>

---

## Solution

The challenge provides one file:

- **image.png** — an image with a clue and a hidden archive

---

## Step 1: Find the ZIP Password

Run zsteg on `image.png` to inspect its image data:

`zsteg -a image.png`

Among the results, the `b1,rgb,msb,xy` entry reveals the ZIP password:

`ViceCity!`

---

## Step 2: Extract the Hidden ZIP

Run binwalk to locate and extract the ZIP archive from `image.png`:

`binwalk -e image.png`

Binwalk reports the ZIP archive at offset `166244` (`0x28964`) and saves it under `_image.png.extracted/28964.zip`.

The archive is password-protected, so unzip it using the password found in Step 1:

`unzip -P 'ViceCity!' _image.png.extracted/28964.zip`

This extracts `inner.jpg`.

---

## Step 3: Extract the Embedded File

The image contains data embedded with Steghide. Extract it using an empty passphrase:

`steghide extract -sf inner.jpg -p ''`

Steghide writes the embedded data to `flag.txt`. Read it to get the flag:

`cat flag.txt`

`Securinets_fst{0n3_l4y3r_d33p3r}`
