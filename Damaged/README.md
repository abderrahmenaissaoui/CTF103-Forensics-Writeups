# Damaged

**Author:** Incendio

---

### Challenge Description
>
> Vice City is a city built on money, power, and secrets. But even the most carefully hidden truths can survive the chaos.
>
> A mysterious file has surfaced. At first glance, it might seem useless, just another piece of evidence lost somewhere in the city. But in Vice City, appearances can be deceiving, and sometimes all it takes is a small step to reveal the bigger picture.
>

---

### Step 1: Identify the File Type

The challenge file has no extension. Inspect its first bytes:

`xxd -l 12 file`

or just

`hexeditor file`

The header reads `GXF89a`. This is nearly the GIF signature `GIF89a`; only the second byte is corrupted.

---

### Step 2: Repair the Signature

Change the byte at offset 1 from `X` (`0x58`) to `I` (`0x49`) and save the repaired copy.

The repaired file is now recognized as an animated GIF. Open `fixed.gif` in an image viewer.

---

### Step 3: Read the Flag in the Image

The flag is visibly overlaid at the bottom of the animation:

`Securinets_fst{Mag1cally_f1l3s_h4s_s1gn4tures!!}`
